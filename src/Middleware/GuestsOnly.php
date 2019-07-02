<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth\Middleware;

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
 * Class GuestsOnly
 * @package Soatok\AnthroKit\Auth\Middleware
 */
class GuestsOnly extends Middleware
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
        if (!empty($_SESSION[$key])) {
            return new Response(
                StatusCode::HTTP_FOUND,
                new Headers([
                    'Location' => $config['redirect']['auth-success']
                ])
            );
        }
        return $next($request, $response);
    }
}
