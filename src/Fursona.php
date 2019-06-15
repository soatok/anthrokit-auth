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

    public static function getDefaults(): array
    {
        return [
            'allow-twitter-auth' => false,
            'device-token-lifetime' =>
                new \DateInterval('P30D'),
            'random' => [
                'email-token' => 40
            ],
            'redirect' => [
                'auth-success' => '/',
                'empty-params' => '/',
                'invalid-action' => '/',
                'login' => '/login',
                'register' => '/register',
            ],
            'session' => [
                'account_key' => 'account_id'
            ],
            'sql' => [
                'accounts' => [
                    'table' => 'anthrokit_accounts',
                    'field' => [
                        'id' => 'accountid',
                        'login' => 'login',
                        'pwhash' => 'pwhash',
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
                ]
            ],
            'templates' => [
                'email-activate' => 'email/activate.twig',
                'register' => 'register.twig'
            ]
        ];
    }

    /**
     * @param array $userDefined
     * @return array
     */
    public static function autoConfig(array $userDefined): array
    {
        return array_merge_recursive($userDefined, self::getDefaults());
    }
}
