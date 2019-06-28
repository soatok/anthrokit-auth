<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth\Filters;

use ParagonIE\Ionizer\Filter\StringFilter;
use ParagonIE\Ionizer\InputFilterContainer;

/**
 * Class LoginFilter
 * @package Soatok\AnthroKit\Auth\Filters
 */
class LoginFilter extends InputFilterContainer
{
    /**
     * LoginFilter constructor.
     * @param array $config
     * @throws \Exception
     */
    public function __construct(array $config = [])
    {
        if (!$config) {
            throw new \Exception('Container not passed to constructor');
        }
        $keys = $config['form-keys']['login'];
        $this->addFilter($keys['login'], new StringFilter());
        $this->addFilter($keys['password'], new StringFilter());
    }
}
