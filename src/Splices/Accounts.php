<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth\Splices;

use Kelunik\TwoFactor\Oath;
use ParagonIE\ConstantTime\{
    Base32,
    Base64UrlSafe,
    Binary
};
use ParagonIE\HiddenString\HiddenString;
use Slim\Container;
use Soatok\AnthroKit\Auth\{Exceptions\AccountBannedException, Fursona, Shortcuts};
use Soatok\AnthroKit\Auth\Exceptions\InviteRequiredException;
use Soatok\AnthroKit\Splice;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Password;
use SodiumException;
use Twig\Environment;
use Zend\Mail\Message;
use Zend\Mail\Transport\TransportInterface;

/**
 * Class Accounts
 * @package Soatok\AnthroKit\Auth\Splices
 */
class Accounts extends Splice
{
    use Shortcuts;

    /** @var array<string, string|array> $config */
    private $config;

    /** @var TransportInterface $mailer */
    private $mailer;

    /** @var SymmetricKey $passwordKey */
    private $passwordKey;

    /** @var Environment $twig */
    private $twig;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->mailer = $container['mailer'];
        $this->passwordKey = $container->get('settings')['password-key'];
        $this->twig = $container->get('twig');
    }

    /**
     * @param HiddenString $code
     * @param int|null $accountId
     * @return bool
     */
    public function checkTwoFactor(HiddenString $code, ?int $accountId = null): bool
    {
        if ($this->config['two-factor']['level'] === Fursona::TWOFACTOR_DISABLED) {
            return false;
        }
        if ($this->config['two-factor']['type'] === Fursona::TWOFACTOR_TOTP) {
            return $this->checkTwoFactorTotp($code, $accountId);
        }

        // FIDO U2F method call goes here

        throw new \RangeException('Configured value for two-factor type is invalid');
    }

    /**
     * @param HiddenString $code
     * @param int|null $accountId
     * @param int $graceWindows
     * @return bool
     */
    public function checkTwoFactorTotp(
        HiddenString $code,
        ?int $accountId = null,
        int $graceWindows = 2
    ): bool {
        if (!$accountId) {
            return false;
        }
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldTwoFactor = $this->field('accounts', 'twofactor');

        $secretKey = $this->db->cell(
            "SELECT {$fieldTwoFactor} FROM {$tableName} WHERE {$fieldPrimaryKey} = ?",
            $accountId
        );
        if (empty($secretKey)) {
            // Fail closed...
            return false;
        }

        return (new Oath())->verifyTotp(
            Base64UrlSafe::decode($secretKey),
            $code->getString(),
            $graceWindows
        );
    }

    /**
     * @param string|null $inviteCode
     * @param int $accountId
     * @return bool
     */
    public function consumeInviteCode(?string $inviteCode, int $accountId): bool
    {
        if (!$inviteCode) {
            return false;
        }
        $tableName = $this->table('invites');
        $fInviteCode = $this->field('invites', 'invite_code');
        $fInviteTo = $this->field('invites', 'newaccountid');
        $fClaimed = $this->field('invites', 'claimed');

        $this->db->beginTransaction();
        $this->db->update(
            $tableName,
            [
                $fClaimed => true,
                $fInviteTo => $accountId
            ],
            [
                $fInviteCode => $inviteCode
            ]
        );
        return $this->db->commit();
    }

    /**
     * @param string $login
     * @param HiddenString $password
     * @param string $email
     * @param string|null $inviteCode
     *
     * @return int
     * @throws \Exception
     * @throws \SodiumException
     */
    public function createAccount(
        string $login,
        HiddenString $password,
        string $email,
        ?string $inviteCode = null
    ): int {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldLogin = $this->field('accounts', 'login');
        $fieldEmail = $this->field('accounts', 'email');
        $fieldPasswordHash = $this->field('accounts', 'pwhash');
        $fieldActive = $this->field('accounts', 'active');

        $exists = $this->db->exists(
            'SELECT count(*) FROM ' . $tableName . ' WHERE ' . $fieldLogin . ' = ?',
            $login
        );
        if ($exists) {
            return 0;
        }

        $accountId = $this->db->insertGet(
            $tableName,
            [
                $fieldActive => true,
                $fieldLogin => $login
            ],
            $fieldPrimaryKey
        );
        if ($inviteCode) {
            $this->consumeInviteCode($inviteCode, $accountId);
        }
        $this->db->update(
            $tableName,
            [
                $fieldEmail => $email,
                $fieldPasswordHash => (new Password($this->passwordKey))
                    ->hash($password, (string) $accountId)
            ],
            [
                $fieldPrimaryKey => $accountId
            ]
        );
        return $accountId;
    }

    /**
     * @param string $login
     * @param HiddenString $password
     * @return int|null
     * @throws CryptoException
     * @throws SodiumException
     */
    public function loginWithPassword(string $login, HiddenString $password): ?int
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldLogin = $this->field('accounts', 'login');
        $fieldPasswordHash = $this->field('accounts', 'pwhash');

        $row = $this->db->row(
            'SELECT * FROM ' . $tableName . ' WHERE ' . $fieldLogin . ' = ?',
            $login
        );
        if (empty($row)) {
            return null;
        }
        if (empty($row[$fieldPasswordHash])) {
            return null;
        }
        $valid = (new Password($this->passwordKey))->verify(
            $password,
            $row[$fieldPasswordHash],
            (string) $row[$fieldPrimaryKey]
        );
        if (!$valid) {
            return null;
        }
        return $this->throwIfBanned((int) $row[$fieldPrimaryKey]);
    }

    /**
     * @param int $fromAccountId
     * @return string
     * @throws \Exception
     */
    public function createInviteCode(int $fromAccountId): string
    {
        $tableName = $this->table('invites');
        $fInviteCode = $this->field('invites', 'invite_code');
        $fInviteFrom = $this->field('invites', 'invitefrom');
        $fClaimed = $this->field('invites', 'claimed');

        $randomCode = Base32::encodeUnpadded(random_bytes(
            $this->config['random']['invite-token'] ?? 25
        ));

        $this->db->insert(
            $tableName,
            [
                $fInviteFrom => $fromAccountId,
                $fInviteCode => $randomCode,
                $fClaimed => false
            ]
        );
        return $randomCode;
    }

    /**
     * @param int $accountId
     * @param string $username
     * @return void
     * @throws \Twig\Error\LoaderError
     * @throws \Twig\Error\RuntimeError
     * @throws \Twig\Error\SyntaxError
     */
    public function sendActivationEmail(int $accountId, string $username = ''): void
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldEmailActivation = $this->field('accounts', 'email_activation');

        // Create/store token in database
        // Create email body from template file
        // Send email to user
        $this->db->beginTransaction();
        $token = Base32::encodeUnpadded(random_bytes(
            $this->config['random']['email-token'] ?? 40
        ));
        $this->db->update(
            $tableName,
            [
                $fieldEmailActivation => $token
            ],
            [
                $fieldPrimaryKey => $accountId
            ]
        );
        if (!$this->db->commit()) {
            $this->db->rollBack();
            throw new \Exception('Could not write to database');
        }

        $url = Fursona::isHTTPS() ? 'https' : 'http';
        $url .= '://';
        $url .= $_SERVER['HTTP_HOST'];

        $this->sendEmail(
            $accountId,
            'Complete Your Registration',
            $this->twig->render(
                $this->config['templates']['email-activate'] ?? 'email/activate.twig',
                [
                    'base_url' => $url,
                    'token' => $token,
                    'username' => $username
                ]
            )
        );
    }

    /**
     * @param int $accountId
     * @param string $subject
     * @param string $body
     */
    public function sendEmail(int $accountId, string $subject, string $body): void
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldEmail = $this->field('accounts', 'email');

        $email = $this->db->cell(
            'SELECT ' .
                    $fieldEmail .
                ' FROM ' .
                    $tableName .
                ' WHERE ' .
                    $fieldPrimaryKey . ' = ?',
            $accountId
        );
        if ($email) {
            $message = new Message();
            $message->setFrom($this->config['email']['from'] ?? 'noreply@localhost');
            $message->setTo($email);
            $message->setSubject($subject);
            $message->setBody($body);
            $this->mailer->send($message);
        }
    }

    /**
     * Create and return a device token which allows two-factor authentication
     * to be bypassed for up to [policy-determined, default 30] days.
     *
     * @param int $accountId
     * @return string
     * @throws SodiumException
     */
    public function createDeviceToken(int $accountId): string
    {
        $tableName = $this->table('account_known_device');
        // FK = Foreign Key
        $fieldAccountFK = $this->field('account_known_device', 'account');
        $fieldSelector = $this->field('account_known_device', 'selector');
        $fieldValidator = $this->field('account_known_device', 'validator');

        $selector = random_bytes(
            $this->config['random']['device-prefix'] ?? 20
        );
        $returnSecret = random_bytes(
            $this->config['random']['device-suffix'] ?? 35
        );
        $hashed = \sodium_crypto_generichash(
            \ParagonIE_Sodium_Core_Util::store64_le($accountId) .
            $selector,
            $returnSecret
        );

        $this->db->insert($tableName, [
            $fieldAccountFK => $accountId,
            $fieldSelector => Base32::encodeUnpadded($selector),
            $fieldValidator => Base32::encodeUnpadded($hashed)
        ]);
        return Base32::encodeUnpadded($selector . $returnSecret);
    }

    /**
     * @param string $token
     * @param int $accountId
     * @return bool
     * @throws SodiumException
     */
    public function checkDeviceToken(string $token, int $accountId): bool
    {
        $tableName = $this->table('account_known_device');
        // FK = Foreign Key
        $fieldAccountFK = $this->field('account_known_device', 'account');
        $fieldCreated = $this->field('account_known_device', 'created');
        $fieldSelector = $this->field('account_known_device', 'selector');
        $fieldValidator = $this->field('account_known_device', 'validator');

        // 20 / 5 === 4
        // 4 <<< 3 === (4 * 8) == 32
        $len = intdiv(($this->config['random']['device-prefix'] ?? 20), 5) << 3;

        $selector = Binary::safeSubstr($token, 0, $len);
        $validator = Binary::safeSubstr($token, $len);
        $hashed = \sodium_crypto_generichash(
            \ParagonIE_Sodium_Core_Util::store64_le($accountId) .
            Base32::decode($selector),
            Base32::decode($validator)
        );
        $diff = $this->config['device-token-lifetime'] ?? null;
        if (!($diff instanceof \DateInterval)) {
            $diff = new \DateInterval('P30D');
        }

        $expires = (new \DateTime())
            ->sub($diff)
            ->format(\DateTime::ATOM);

        $stored = $this->db->cell(
            "SELECT {$fieldValidator} 
            FROM {$tableName}
            WHERE {$fieldSelector} = ?
              AND {$fieldAccountFK} = ?
              AND {$fieldCreated} >= ?",
            $selector,
            $accountId,
            $expires
        );

        return hash_equals(Base32::decode($stored), $hashed);
    }

    /**
     * @param HiddenString $string
     * @param int $accountId
     * @return bool
     */
    public function setTwoFactorSecret(HiddenString $string, int $accountId): bool
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldTwoFactor = $this->field('accounts', 'twofactor');

        $encoded = Base64UrlSafe::encode($string->getString());
        $this->db->beginTransaction();
        $this->db->update(
            $tableName,
            [
                $fieldTwoFactor => $encoded
            ],
            [
                $fieldPrimaryKey => $accountId
            ]
        );
        return $this->db->commit();
    }

    /**
     * Check that the account has not been banned.
     *
     * @param int $accountId
     * @return int
     * @throws AccountBannedException
     */
    public function throwIfBanned(int $accountId): int
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldActive = $this->field('accounts', 'active');
        if (!$this->db->exists(
            "SELECT {$fieldActive} FROM {$tableName} WHERE {$fieldPrimaryKey} = ?",
            $accountId
        )) {
            throw new AccountBannedException('Your account has been deactivated');
        }
        return $accountId;
    }

    /**
     * Register or Login with Twitter
     *
     * @param array $accessToken
     * @return int|null
     *
     * @throws AccountBannedException
     * @throws InviteRequiredException
     */
    public function twitterAccess(array $accessToken): ?int
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldActive = $this->field('accounts', 'active');
        $fieldLogin = $this->field('accounts', 'login');
        $fieldExternalAuth = $this->field('accounts', 'external_auth');

        $username = preg_replace(
            '/[^A-Za-z0-9_]+/',
            '',
            $accessToken['screen_name']
        );
        $user_id = (int) $accessToken['user_id'];

        // JSONB Query
        $exists = $this->db->cell(
            'SELECT ' .
                $fieldPrimaryKey .
            ' FROM ' .
                $tableName .
            ' WHERE ' .
                $fieldExternalAuth . '->>\'service\' = \'twitter\' AND ' .
                $fieldExternalAuth . '->>\'user_id\' = ? ',
            $user_id
        );
        if ($exists) {
            // Account exists. Login as this user.
            return $this->throwIfBanned($exists);
        }

        // Only allow registration if invited:
        $a = $this->config['session']['invite_key'] ?? 'invite_key';
        if ($this->config['require-invite-register']) {
            if (empty($_SESSION[$a])) {
                throw new InviteRequiredException();
            } elseif (!$this->validateInviteCode($_SESSION[$a])) {
                throw new InviteRequiredException();
            }
        }
        $inviteCode = $_SESSION[$a] ?? null;

        // Find an unused username
        $base = $username;
        $iterations = 1;
        do {
            $exists = $this->db->cell(
                'SELECT ' .
                    $fieldPrimaryKey .
                ' FROM ' .
                    $tableName .
                ' WHERE login = ?',
                    $username
            );
            if ($exists) {
                // Dedeuplicate
                ++$iterations;
                $username = $base . $iterations;
            }
        } while ($exists);
        try {
            $accountId = (int) $this->db->insertGet(
                $tableName,
                [
                    $fieldActive => true,
                    $fieldLogin => $username,
                    $fieldExternalAuth => json_encode([
                        'service' => 'twitter',
                        'user_id' => $accessToken['user_id'],
                        'username' => $accessToken['screen_name']
                    ])
                ],
                $fieldPrimaryKey
            );
            if ($inviteCode) {
                $this->consumeInviteCode($inviteCode, $accountId);
            }
            return $accountId;
        } catch (\Exception $ex) {
            return null;
        }
    }

    /**
     * @param string $token
     * @return bool
     */
    public function validateEmail(string $token): bool
    {
        $tableName = $this->table('accounts');
        $fieldPrimaryKey = $this->field('accounts', 'id');
        $fieldEmailActivation = $this->field('accounts', 'email_activation');

        $accountId = $this->db->cell(
            "SELECT 
                {$fieldPrimaryKey}
            FROM
                {$tableName}
            WHERE 
                {$fieldEmailActivation} IS NOT NULL AND {$fieldEmailActivation} = ?",
            $token
        );
        if (!$accountId) {
            $this->db->beginTransaction();
            $this->db->update(
                $tableName,
                [
                    $fieldEmailActivation => null
                ],
                [
                    $fieldPrimaryKey => $accountId
                ]
            );
            return $this->db->commit();
        }
        return false;
    }

    /**
     * Return true if...
     *
     * 1. The invite code exists
     * 2. The account that invited it is still active
     * 3. The invite code has not been claimed
     *
     * @param string $inviteCode
     * @return bool
     */
    public function validateInviteCode(string $inviteCode): bool
    {
        $tableName = $this->table('invites');
        $fInviteCode = $this->field('invites', 'invite_code');
        $fInviteFrom = $this->field('invites', 'invitefrom');
        $fClaimed = $this->field('invites', 'claimed');

        $accTable = $this->table('accounts');
        $accPrimaryKey = $this->field('accounts', 'id');
        $accActive = $this->field('accounts', 'active');

        return $this->db->exists(
            "SELECT count(c.*)
                FROM {$tableName} c
                JOIN {$accTable} a ON c.{$fInviteFrom} = a.{$accPrimaryKey}
                WHERE {$fInviteCode} = ? AND a.{$accActive} AND NOT c.{$fClaimed}",
            $inviteCode
        );
    }

    /**
     * @param array $config
     * @return self
     */
    public function setConfig(array $config): self
    {
        $this->config = $config;
        return $this;
    }
}
