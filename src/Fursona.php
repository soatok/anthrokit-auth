<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Class Fursona
 * @package Soatok\AnthroKit\Auth
 */
class Fursona
{
    const CONTAINER_KEY = 'anthrokit_auth';

    const TWOFACTOR_DISABLED = 0;
    const TWOFACTOR_ENABLED = 1;
    const TWOFACTOR_REQUIRED = 2;
    const TWOFACTOR_TOTP = 'TOTP';

    public static function getDefaults(): array
    {
        return [
            'allow-password-auth' => true,
            'allow-twitter-auth' => false,
            'auto-configured' => true,
            'cookie-config' => [
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ],
            'cookie' => [
                'device-token' => 'device_token',
            ],
            'device-token-lifetime' =>
                new \DateInterval('P30D'),
            'email' => [
                'from' => 'noreply@localhost'
            ],
            'form-keys' => [
                'activate' => [
                    'token' => 'token'
                ],
                'login' => [
                    'login' => 'login',
                    'password' => 'password'
                ],
                'register' => [
                    'email' => 'email',
                    'login' => 'login',
                    'password' => 'password',
                    'two-factor-challenge' => 'two-factor-challenge'
                ],
                'two-factor' => [
                    'code' => 'code',
                    'remember-device' => 'remember-device'
                ]
            ],
            'random' => [
                'email-token' => 40,
                'invite-token' => 25
            ],
            'require-invite-register' => false,
            'require-two-factor-auth' => true,
            'redirect' => [
                'account-banned' => '/',
                'auth-success' => '/',
                'auth-failure' => '/',
                'activate-success' => '/',
                'empty-params' => '/',
                'invalid-action' => '/',
                'invite-required' => '/',
                'login' => '/login',
                'logout-fail' => '/',
                'logout-success' => '/',
                'register' => '/register',
                'twitter' => '/twitter',
                'twitter-error' => '/',
                'two-factor' => '/verify',
            ],
            'session' => [
                'account_key' => 'account_id',
                'auth_redirect_key' => 'auth_redirect',
                'halfauth_key' => 'halfauth_id',
                'invite_key' => 'invite_code',
                'register_2fa_key' => 'register_2fa_key',
                'logout_key' => 'logout_token'
            ],
            'sql' => [
                'accounts' => [
                    'table' => 'anthrokit_accounts',
                    'field' => [
                        'id' => 'accountid',
                        'login' => 'login',
                        'pwhash' => 'pwhash',
                        'twofactor' => 'twofactor',
                        'email' => 'email',
                        'email_activation' => 'email_activation',
                        'external_auth' => 'external_auth'
                    ]
                ],
                'account_known_device' => [
                    'table' => 'anthrokit_account_known_device',
                    'field' => [
                        'id' => 'deviceid',
                        'account' => 'accountid',
                        'created' => 'created',
                        'selector' => 'selector',
                        'validator' => 'validator'
                    ]
                ],
                'invites' => [
                    'table' => 'anthrokit_invites',
                    'field' => [
                        'id' => 'inviteid',
                        'from' => 'invitefrom',
                        'twitter' => 'twitter',
                        'email' => 'email',
                        'invite_code' => 'invite_code',
                        'claimed' => 'claimed',
                        'created' => 'created',
                        'newaccountid' => 'newaccountid'
                    ]
                ]
            ],
            'templates' => [
                'email-activate' => 'email/activate.twig',
                'login' => 'login.twig',
                'register' => 'register.twig',
                'two-factor' => 'two-factor.twig'
            ],
            'two-factor' => [
                'type' => self::TWOFACTOR_TOTP,
                'level' => self::TWOFACTOR_ENABLED
            ]
        ];
    }

    /**
     * @param ServerRequestInterface|null $request
     * @return bool
     */
    public static function isHTTPS(?ServerRequestInterface $request = null): bool
    {
        if ($request) {
            $server = $request->getServerParams();
        } else {
            $server = $_SERVER;
        }
        if (empty($server['HTTPS'])) {
            return false;
        }
        return $server['HTTPS'] !== 'off';
    }

    /**
     * @param array $userDefined
     * @return array
     */
    public static function autoConfig(array $userDefined): array
    {
        return $userDefined + self::getDefaults();
    }
}
