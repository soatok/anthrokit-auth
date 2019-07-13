<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth\Middleware;

use ParagonIE\ConstantTime\Base32;
use Psr\Http\Message\{
    MessageInterface,
    RequestInterface,
    ResponseInterface
};
use Slim\Http\{
    Headers,
    Response,
    StatusCode
};
use Soatok\AnthroKit\Auth\Fursona;
use Soatok\AnthroKit\Middleware;

/**
 * Class AuthorizedUsersOnly
 * @package Soatok\AnthroKit\Auth\Middleware
 */
class AuthorizedUsersOnly extends Middleware
{
    public function __invoke(
        RequestInterface $request,
        ResponseInterface $response,
        callable $next
    ): MessageInterface {
        $config = Fursona::autoConfig(
            $this->container->get(Fursona::CONTAINER_KEY) ?? []
        );
        $key = $config['session']['account_key'] ?? 'account_id';
        if (empty($_SESSION[$key])) {
            // Store URI for post-auth return
            $k2 = $config['session']['auth_redirect_key'] ?? 'auth_redirect';
            $_SESSION[$k2] = $request->getUri()->getPath();
            return new Response(
                StatusCode::HTTP_FOUND,
                new Headers([
                    'Location' => $config['redirect']['login']
                ])
            );
        } else {
            // Ensure logout CSRF token is defined.
            $k2 = $config['session']['logout_key'] ?? 'logout_key';
            if (empty($_SESSION[$k2])) {
                try {
                    $_SESSION[$k2] = Base32::encodeUnpadded(random_bytes(32));
                } catch (\Exception $ex) {
                }
            }
        }
        return $next($request, $response);
    }
}
