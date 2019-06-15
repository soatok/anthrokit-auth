<?php
declare(strict_types=1);
namespace Soatok\AnthroKit\Auth;

/**
 * Trait Shortcuts
 * @package Soatok\AnthroKit\Auth
 *
 * @property array<string, string|array> $config
 */
trait Shortcuts
{
    /**
     * @param string $name
     * @return string
     */
    protected function table(string $name): string
    {
        return $this->config['sql'][$name]['table'] ?? $name;
    }

    /**
     * @param string $table
     * @param string $column
     * @return string
     */
    protected function field(string $table, string $column): string
    {
        return $this->config['sql'][$table]['field'][$column] ?? $column;
    }
}