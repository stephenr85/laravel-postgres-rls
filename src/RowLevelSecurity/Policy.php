<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

/**
 * The one policy shape this package installs, and the naming rule that lets the preparer tell
 * a current policy from an outdated one without parsing it back out of `pg_policies`.
 *
 * Body (measured in the pooled-storage ticket 01 spike, 23/23 on Postgres 17):
 *
 *     USING (col = current_setting('setting', true)) WITH CHECK (col = current_setting('setting', true))
 *
 * `current_setting(name, true)` returns NULL rather than throwing when the setting is unset, and
 * `col = NULL` is never true, so a connection with no setting bound reads zero rows and cannot
 * insert: fail-closed. The column's own DEFAULT uses the strict one-argument form on purpose,
 * so an unscoped insert that names no value throws instead of storing an empty key.
 *
 * Name: `{table}_rls_policy_{hash}` where hash is the first six hex chars of sha1(body). A
 * changed column or setting changes the body, the hash, and therefore the name, so the
 * preparer sees "a policy with my prefix but not my name" and replaces it. Prior art:
 * stancl/tenancy v4's `CreateUserWithRLSPolicies` (`src/Commands/CreateUserWithRLSPolicies.php`,
 * policy-name hashing and zombie-policy drops); reimplemented here without the framework.
 *
 * Postgres truncates identifiers to 63 bytes, so the table portion is shortened first when the
 * full name would overflow; otherwise the stored name would never equal the computed one and
 * every run would drop and re-create.
 */
final class Policy
{
    public const SUFFIX = '_rls_policy_';

    public const HASH_LENGTH = 6;

    private const MAX_IDENTIFIER = 63;

    public static function body(string $column, string $setting): string
    {
        $predicate = sprintf("%s = current_setting('%s', true)", $column, $setting);

        return sprintf('USING (%s) WITH CHECK (%s)', $predicate, $predicate);
    }

    public static function hash(string $column, string $setting): string
    {
        return substr(sha1(self::body($column, $setting)), 0, self::HASH_LENGTH);
    }

    public static function prefix(string $table): string
    {
        $room = self::MAX_IDENTIFIER - strlen(self::SUFFIX) - self::HASH_LENGTH;

        return substr($table, 0, $room).self::SUFFIX;
    }

    public static function name(string $table, string $column, string $setting): string
    {
        return self::prefix($table).self::hash($column, $setting);
    }

    /** Whether a policy name was minted by this package (for any table). */
    public static function isOurs(string $policyName): bool
    {
        return (bool) preg_match('/'.preg_quote(self::SUFFIX, '/').'[0-9a-f]{'.self::HASH_LENGTH.'}$/', $policyName);
    }
}
