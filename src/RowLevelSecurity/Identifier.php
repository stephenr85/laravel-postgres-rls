<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use InvalidArgumentException;

/**
 * Validation and quoting for the names this package interpolates into DDL.
 *
 * Schema and table names come from the catalog or the operator and are double-quoted. The
 * column and the setting are also written INTO a policy body and a column default, where their
 * exact spelling is hashed, so they are restricted to plain lower-case identifiers rather than
 * quoted: a quoted spelling would change the hash for the same column.
 */
final class Identifier
{
    private const PLAIN = '/^[a-z_][a-z0-9_]*$/';

    private const MAX_IDENTIFIER = 63;

    public static function quote(string $identifier): string
    {
        return '"'.str_replace('"', '""', $identifier).'"';
    }

    public static function qualified(string $schema, string $relation): string
    {
        return self::quote($schema).'.'.self::quote($relation);
    }

    public static function literal(string $value): string
    {
        return "'".str_replace("'", "''", $value)."'";
    }

    public static function assertColumn(string $column): string
    {
        if (! preg_match(self::PLAIN, $column)) {
            throw new InvalidArgumentException(sprintf(
                'The discriminator column must be a plain lower-case identifier (letters, digits, underscore); "%s" given.',
                $column
            ));
        }

        // Postgres truncates a longer identifier silently; the catalog would then never report
        // the name the preparer asked for, and prepare() would stop being idempotent.
        if (strlen($column) > self::MAX_IDENTIFIER) {
            throw new InvalidArgumentException(sprintf(
                'The discriminator column must be at most %d bytes; "%s" is %d.',
                self::MAX_IDENTIFIER,
                $column,
                strlen($column)
            ));
        }

        return $column;
    }

    /**
     * Postgres accepts SET for any name containing a dot (a "customized option") and refuses
     * an unrecognised name without one, so a setting for this package must be namespaced.
     */
    public static function assertSetting(string $setting): string
    {
        if (! preg_match('/^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$/', $setting)) {
            throw new InvalidArgumentException(sprintf(
                'The session setting must be namespaced (`app.key`): Postgres refuses to set an unrecognised name without a dot; "%s" given.',
                $setting
            ));
        }

        return $setting;
    }

    public static function assertSchema(string $schema): string
    {
        if ($schema === '' || strlen($schema) > self::MAX_IDENTIFIER) {
            throw new InvalidArgumentException('A schema name must be between 1 and 63 characters.');
        }

        return $schema;
    }

    /**
     * A role name that is safe to interpolate into `CREATE ROLE`/`ALTER ROLE` DDL — the same plain
     * identifier restriction as {@see assertColumn()}, since role DDL (unlike a table/schema name)
     * takes no bind parameters at all: `CREATE ROLE $1` is not valid SQL.
     */
    public static function assertRole(string $role): string
    {
        if (! preg_match(self::PLAIN, $role)) {
            throw new InvalidArgumentException(sprintf(
                'A role name must be a plain lower-case identifier (letters, digits, underscore); "%s" given.',
                $role
            ));
        }

        if (strlen($role) > self::MAX_IDENTIFIER) {
            throw new InvalidArgumentException(sprintf(
                'A role name must be at most %d bytes; "%s" is %d.',
                self::MAX_IDENTIFIER,
                $role,
                strlen($role)
            ));
        }

        return $role;
    }
}
