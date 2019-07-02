<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth\Middleware;

use Psr\Http\Message\{
    MessageInterface,
    RequestInterface,
    ResponseInterface
};
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
        if (empty($_SESSION['account_id'])) {
            @header('Location: /auth/login');
            exit;
        }
        return $next($request, $response);
    }
}
