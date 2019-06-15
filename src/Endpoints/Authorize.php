<?php
declare(strict_types=1);
namespace Soatok\Anthrokit\Auth\Endpoints;

use Abraham\TwitterOAuth\{
    TwitterOAuth,
    TwitterOAuthException
};
use Interop\Container\Exception\ContainerException;
use ParagonIE\HiddenString\HiddenString;
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface
};
use Slim\Container;
use Soatok\AnthroKit\Auth\{
    Fursona,
    Splices\Accounts
};
use Soatok\AnthroKit\Endpoint;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Twig\Error\{
    LoaderError,
    RuntimeError,
    SyntaxError
};

/**
 * Class Authorize
 * @package Soatok\Anthrokit\Auth\Endpoints
 *
 * Workflow:
 *
 * /auth/register -> create account
 * /auth/activate -> verify email address / etc.
 * /auth/login    -> login
 * /auth/verify   -> two-factor authentication prompt
 * /auth/logout   -> logout
 *
 *
 * /auth/twitter          -> register/login
 * /auth/twitter/callback -> validate (create account)
 */
class Authorize extends Endpoint
{
    /** @var Accounts $accounts */
    protected $accounts;

    /** @var array<string, string|array> $config */
    protected $config;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $config = $container->get(Fursona::CONTAINER_KEY) ?? [];
        $this->config = Fursona::autoConfig($config);
        $this->accounts = $this->splice('Accounts');
        $this->accounts->setConfig($this->config);
    }

    /**
     * @param RequestInterface $request
     * @param ResponseInterface|null $response
     * @param array $routerParams
     * @return ResponseInterface
     *
     * @throws ContainerException
     * @throws CryptoException
     * @throws LoaderError
     * @throws RuntimeError
     * @throws SyntaxError
     * @throws TwitterOAuthException
     * @throws \SodiumException
     */
    public function __invoke(
        RequestInterface $request,
        ?ResponseInterface $response = null,
        array $routerParams = []
    ): ResponseInterface {
        if (empty($routerParams)) {
            // No params? No dice.
            return $this->redirect(
                $this->config['redirect']['empty-params'] ?? '/'
            );
        }
        $routerKey = $this->config['router']['action-key'] ?? 'action';
        switch ($routerParams[$routerKey]) {
            case 'activate':
                return $this->activate($request, $routerParams);
            case 'login':
                return $this->login($request);
            case 'logout':
                return $this->logout($request, $routerParams);
            case 'register':
                return $this->register($request);
            case 'twitter':
                return $this->twitter($request, $routerParams);
            case 'verify':
                return $this->verify($request, $routerParams);
            default:
                return $this->redirect(
                    $this->config['redirect']['invalid-action'] ?? '/'
                );
        }
    }

    /**
     * @param RequestInterface $request
     * @param array $routerParams
     * @return ResponseInterface
     */
    protected function activate(
        RequestInterface $request,
        array $routerParams = []
    ): ResponseInterface {
        return $this->json($routerParams);
    }

    /**
     * @param RequestInterface $request
     * @return ResponseInterface
     *
     * @throws ContainerException
     * @throws CryptoException
     * @throws LoaderError
     * @throws RuntimeError
     * @throws SyntaxError
     * @throws \SodiumException
     */
    protected function login(RequestInterface $request): ResponseInterface
    {
        // Do we have valid data?
        $post = $this->post($request);
        $errors = [];
        $keys = $this->config['login']['form-keys'];
        if (!empty($post)) {
            $l = $keys['login'] ?? 'login';
            $p = $keys['password'] ?? 'password';
            $accountId = $this->accounts->loginWithPassword(
                $post[$l],
                new HiddenString($post[$p])
            );
            if ($accountId) {
                $a = $this->config['session']['account_key'] ?? 'account_id';
                $_SESSION[$a] = $accountId;
                $this->redirect(
                    $this->config['redirect']['auth-success']
                );
            }

        }
        return $this->view(
            $this->config['templates']['login'] ?? 'login.twig',
            ['post' => $post]
        );
    }

    /**
     * @param RequestInterface $request
     * @param array $routerParams
     * @return ResponseInterface
     */
    protected function logout(
        RequestInterface $request,
        array $routerParams = []
    ): ResponseInterface {
        return $this->json($routerParams);

    }

    /**
     * @param RequestInterface $request
     * @return ResponseInterface
     *
     * @throws ContainerException
     * @throws LoaderError
     * @throws RuntimeError
     * @throws SyntaxError
     * @throws \SodiumException
     */
    protected function register(RequestInterface $request): ResponseInterface
    {
        // Do we have valid data?
        $post = $this->post($request);
        $errors = [];
        $keys = $this->config['register']['form-keys'];
        if (!empty($post)) {
            $l = $keys['login'] ?? 'login';
            $p = $keys['password'] ?? 'password';
            $e = $keys['email'] ?? 'email';

            if (empty($post[$l])) {
                $errors []= 'Username must be provided';
            }

            if (empty($post[$p])) {
                $errors []= 'Passphrase must be provided';
            }

            if (empty($post[$e])) {
                $errors []= 'Email address must be provided';
            } elseif (strpos($post[$e], '@') === false) {
                $errors []= 'Not a valid email address';
            }

            if (empty($errors)) {
                // Create the account:
                $accountId = $this->accounts->createAccount(
                    $post[$l],
                    new HiddenString($post[$p])
                );
                if ($accountId) {
                    $a = $this->config['session']['account_key'] ?? 'account_id';
                    $_SESSION[$a] = $accountId;
                    $this->accounts->sendActivationEmail($accountId);
                    $this->view(
                        $this->config['templates']['register-success'] ?? 'register.twig',
                        ['success' => true]
                    );
                } else {
                    $this->setTwigVar('errors', ['Registration unsuccessful']);
                }
            } else {
                $this->setTwigVar('errors', $errors);
            }
        }
        return $this->view(
            $this->config['templates']['register'] ?? 'register.twig',
            ['post' => $post]
        );
    }

    /**
     * @param RequestInterface $request
     * @param array $routerParams
     * @return ResponseInterface
     * @throws ContainerException
     * @throws TwitterOAuthException
     */
    protected function twitter(
        RequestInterface $request,
        array $routerParams = []
    ): ResponseInterface {
        // Ensure it's enabled
        if (!$this->config['allow-twitter-auth']) {
            return $this->redirect(
                $this->config['redirect']['register']
            );
        }
        $settings = $this->container->get('settings')['twitter'];
        $callback = $settings['callback_url'] ?? null;
        if (empty($callback)) {
            throw new TwitterOAuthException('Callback not configured');
        }

        /** @var TwitterOAuth $twitter */
        $twitter = new TwitterOAuth(
            $settings['consumer_key'],
            $settings['consumer_secret']
        );

        // Is this a callback request?
        if (!empty($routerParams)) {
            $arg = array_shift($routerParams);
            if ($arg === 'callback') {
                try {
                    return $this->twitterCallback($request, $twitter);
                } catch (\Exception $ex) {
                }
            }
        }

        /** @var array<string, string> $request_token */
        $request_token = $twitter->oauth(
            'oauth/request_token',
            [
                'oauth_callback' => $callback
            ]
        );

        if (!empty($request_token['oauth_callback_confirmed'])) {
            $_SESSION['twitter_oauth_token'] = $request_token['oauth_token'];
            $_SESSION['twitter_oauth_token_secret'] = $request_token['oauth_token_secret'];
        }

        $url = $twitter->url(
            'oauth/authorize',
            [
                'oauth_token' => $request_token['oauth_token']
            ]
        );
        return $this->redirect($url);
    }

    /**
     * @param RequestInterface $request
     * @param TwitterOAuth $twitter
     * @return ResponseInterface
     * @throws TwitterOAuthException
     */
    protected function twitterCallback(
        RequestInterface $request,
        TwitterOAuth $twitter
    ): ResponseInterface {
        $request_token = [
            'oauth_token' => $_SESSION['twitter_oauth_token'],
            'oauth_token_secret' => $_SESSION['twitter_oauth_token_secret']
        ];
        if (!hash_equals($request['oauth_token'], $_GET['oauth_token'])) {
            return $this->redirect('/');
        }
        $twitter->setOauthToken(
            $request_token['oauth_token'],
            $request_token['oauth_token_secret']
        );

        $access_token = $twitter->oauth(
            'oauth/access_token',
            [
                'oauth_verifier' => $_GET['oauth_verifier']
            ]
        );

        $accountId = $this->accounts->twitterAccess($access_token);
        if ($accountId) {
            $a = $this->config['session']['account_key'] ?? 'account_id';
            $_SESSION[$a] = $accountId;
            $_SESSION['twitter_access_token'] = $access_token;
        }
        return $this->redirect(
            $this->config['redirect']['auth-success']
        );
    }

    /**
     * @param RequestInterface $request
     * @param array $routerParams
     * @return ResponseInterface
     */
    protected function verify(
        RequestInterface $request,
        array $routerParams = []
    ): ResponseInterface {
        return $this->json($routerParams);
    }
}
