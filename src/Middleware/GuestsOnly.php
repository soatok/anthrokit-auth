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
        if (!empty($_SESSION['account_id'])) {
            header('Location: /');
            exit;
        }
        return $next($request, $response);
    }
}
