<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth;

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
                    'password' => 'password'
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
                'twitter-error' => '/'
            ],
            'session' => [
                'account_key' => 'account_id',
                'halfauth_key' => 'halfauth_id',
                'invite_key' => 'invite_code',
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
     * @param array $userDefined
     * @return array
     */
    public static function autoConfig(array $userDefined): array
    {
        return $userDefined + self::getDefaults();
    }
}
