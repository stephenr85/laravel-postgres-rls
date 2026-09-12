<?php

namespace Rushing\PostgresRls\Audits;

use Rushing\PostgresRls\SessionSettingsPostgresConnector;

/**
 * Reads what the audits need out of a `database.connections` array without opening anything:
 * which entries are pgsql, which carry `session_settings`, and which schemas an entry's
 * `search_path` names.
 */
final class ConnectionConfig
{
    /**
     * @param  array<string, array<string, mixed>>  $connections  the `database.connections` array
     */
    public function __construct(private readonly array $connections) {}

    /**
     * @return array<string, array<string, mixed>>
     */
    public function pgsql(): array
    {
        return array_filter($this->connections, fn ($config) => is_array($config) && ($config['driver'] ?? null) === 'pgsql');
    }

    /**
     * Names of pgsql connections carrying a non-empty `session_settings` map.
     *
     * @return list<string>
     */
    public function scoped(): array
    {
        return array_keys(array_filter($this->pgsql(), fn ($config) => ($config[SessionSettingsPostgresConnector::CONFIG_KEY] ?? []) !== []));
    }

    /**
     * Names of pgsql connections whose `search_path` names any of the schemas.
     *
     * @param  list<string>  $schemas
     * @return list<string>
     */
    public function reaching(array $schemas): array
    {
        $names = [];

        foreach ($this->pgsql() as $name => $config) {
            if (array_intersect(self::searchPath($config), $schemas) !== []) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * @return array<string, mixed>
     */
    public function get(string $name): array
    {
        return is_array($this->connections[$name] ?? null) ? $this->connections[$name] : [];
    }

    public function has(string $name): bool
    {
        return isset($this->connections[$name]);
    }

    /**
     * The schemas a connection config's `search_path` (or legacy `schema`) names, unquoted.
     * Mirrors Laravel's own `ParsesSearchPath` shape: a string like `"a", b` or an array.
     *
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    public static function searchPath(array $config): array
    {
        $raw = $config['search_path'] ?? $config['schema'] ?? null;

        if ($raw === null || $raw === '' || $raw === []) {
            return [];
        }

        $parts = is_array($raw) ? $raw : preg_split('/[\s,]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY);

        return array_values(array_filter(array_map(
            fn ($part) => trim((string) $part, " \t\n\r\0\x0B\"'"),
            (array) $parts,
        ), fn ($part) => $part !== ''));
    }
}
