<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Grammars\PostgresGrammar as QueryGrammar;
use Illuminate\Database\Schema\Grammars\PostgresGrammar as SchemaGrammar;
use Rushing\PostgresRls\SessionSettingsPostgresConnector;

/**
 * On every scoped connection — a pgsql connection whose `session_settings` carry a custom setting (a
 * dotted name such as `app.tenant_id`; built-ins like `statement_timeout` have none) — swaps in the
 * query grammar that scopes upsert conflict targets ({@see ScopesConflictTargets}) and the schema grammar
 * that scopes new foreign keys into prepared tables ({@see ScopesForeignKeys}). Laravel dispatches
 * `ConnectionEstablished` each time it builds a connection object, so a purged-and-rebuilt tenant
 * connection is covered again.
 *
 * Only the grammars this package knows are swapped (Laravel's and tpetry's). A connection whose grammar
 * is some other class keeps it, and fails loudly on a rewritten key as it would have.
 */
final class ScopedGrammars
{
    public static function apply(Connection $connection, string $column): void
    {
        if ($connection->getDriverName() !== 'pgsql' || ! self::scoped($connection)) {
            return;
        }

        $query = match (get_class($connection->getQueryGrammar())) {
            QueryGrammar::class => new ScopedPostgresGrammar($connection),
            'Tpetry\PostgresqlEnhanced\Query\Grammar' => new ScopedEnhancedGrammar($connection),
            default => null,
        };

        if ($query !== null) {
            self::bind($query, $connection);
            $connection->setQueryGrammar($query->scopeBy($column));
        }

        if ($connection->getSchemaGrammar() === null) {
            $connection->useDefaultSchemaGrammar();
        }

        $schema = match (get_class($connection->getSchemaGrammar())) {
            SchemaGrammar::class => new ScopedPostgresSchemaGrammar($connection),
            'Tpetry\PostgresqlEnhanced\Schema\Grammars\Grammar' => new ScopedEnhancedSchemaGrammar($connection),
            default => null,
        };

        if ($schema !== null) {
            self::bind($schema, $connection);
            $connection->setSchemaGrammar($schema->scopeBy($column));
        }
    }

    /** Laravel 11 grammars take their connection by setter, not constructor. */
    private static function bind(object $grammar, Connection $connection): void
    {
        if (method_exists($grammar, 'setConnection')) {
            $grammar->setConnection($connection);
        }
    }

    private static function scoped(Connection $connection): bool
    {
        $settings = $connection->getConfig(SessionSettingsPostgresConnector::CONFIG_KEY);

        if (! is_array($settings)) {
            return false;
        }

        foreach (array_keys($settings) as $name) {
            if (str_contains((string) $name, '.')) {
                return true;
            }
        }

        return false;
    }
}
