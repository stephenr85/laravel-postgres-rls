<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;

/**
 * A per-key login role whose session setting is bound in the role itself, via `ALTER ROLE ... SET`
 * — so a DIRECT connection as that role (a BI tool, `psql`, a report scheduler) sees exactly one
 * key's rows under the same policy, with no application code, no `session_settings` connection
 * config, and no `SET` statement in the path at all. `ALTER ROLE` writes the setting into
 * `pg_db_role_setting`, which Postgres applies automatically at the start of every session that
 * role opens — before the first statement runs.
 *
 * ## Why this is a distinct primitive from the connector
 *
 * {@see \Rushing\PostgresRls\SessionSettingsPostgresConnector} applies `session_settings` from
 * connection CONFIG — the right shape for the application's own pooled connections, which share one
 * or a few roles across many keys and vary the setting per Laravel `database.connections` entry.
 * `RoleBinder` is the opposite shape: one role PER key, so the binding travels with the role itself
 * and survives a connection made by a tool this package has never heard of.
 *
 * ## What this does not do
 *
 * Never stores or echoes the password — every statement list returned redacts it as `[redacted]`;
 * the caller hands the credential out once and this class keeps nothing. Never grants `BYPASSRLS`
 * or `SUPERUSER` — the role owns nothing, so it is subject to every policy in the schema exactly
 * like the connector-based scoped connections are. Never runs migrations or touches the schema's
 * own contents.
 */
final class RoleBinder
{
    private readonly Catalog $catalog;

    public function __construct(
        private readonly Connection $connection,
        private readonly string $schema,
    ) {
        Identifier::assertSchema($schema);

        $this->catalog = new Catalog($connection);
    }

    /**
     * Create the role if absent, or (when it already exists and a password is given) rotate its
     * password — then bind `$setting` to `$key` on the role and grant it what {@see RoleGrants}
     * grants any scoped role on this schema. Idempotent: a second `bind()` re-asserts the key and
     * the grants rather than accumulating anything.
     *
     * @return list<string> the statements executed, in order, with any password REDACTED
     */
    public function bind(string $role, string $setting, string $key, ?string $password = null): array
    {
        $role = Identifier::assertRole($role);
        Identifier::assertSetting($setting);

        $quotedRole = Identifier::quote($role);
        $statements = [];

        if ($this->catalog->roleExists($role)) {
            if ($password !== null) {
                $statements[] = $this->run(
                    sprintf('ALTER ROLE %s WITH PASSWORD %s', $quotedRole, Identifier::literal($password)),
                    sprintf('ALTER ROLE %s WITH PASSWORD %s', $quotedRole, '\'[redacted]\'')
                );
            }
        } else {
            $passwordClause = $password !== null ? ' PASSWORD '.Identifier::literal($password) : '';
            $redactedClause = $password !== null ? ' PASSWORD \'[redacted]\'' : '';
            $statements[] = $this->run(
                sprintf('CREATE ROLE %s LOGIN%s', $quotedRole, $passwordClause),
                sprintf('CREATE ROLE %s LOGIN%s', $quotedRole, $redactedClause)
            );
        }

        $statements[] = $this->run(sprintf('ALTER ROLE %s SET %s = %s', $quotedRole, $setting, Identifier::literal($key)));

        return array_merge($statements, (new RoleGrants($this->connection, $this->schema))->grant($role));
    }

    /**
     * Revoke everything {@see RoleGrants::grant()} granted on this schema, then drop the role.
     * Idempotent: unbinding an absent role is a no-op (returns an empty list) rather than an error
     * — a caller retrying a partially-applied unbind should not be punished for it.
     *
     * @return list<string> the statements executed, in order
     */
    public function unbind(string $role): array
    {
        $role = Identifier::assertRole($role);

        if (! $this->catalog->roleExists($role)) {
            return [];
        }

        $owner = $this->catalog->schemaOwner($this->schema);
        $quotedRole = Identifier::quote($role);
        $schema = Identifier::quote($this->schema);
        $statements = [];

        if ($owner !== null) {
            $forOwner = Identifier::quote($owner);

            $statements[] = sprintf('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s REVOKE ALL ON TABLES FROM %s', $forOwner, $schema, $quotedRole);
            $statements[] = sprintf('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s REVOKE ALL ON SEQUENCES FROM %s', $forOwner, $schema, $quotedRole);
        }

        $statements[] = sprintf('REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM %s', $schema, $quotedRole);
        $statements[] = sprintf('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %s FROM %s', $schema, $quotedRole);
        $statements[] = sprintf('REVOKE USAGE ON SCHEMA %s FROM %s', $schema, $quotedRole);
        $statements[] = sprintf('DROP ROLE %s', $quotedRole);

        $this->connection->transaction(function () use ($statements) {
            foreach ($statements as $statement) {
                $this->connection->statement($statement);
            }
        });

        return $statements;
    }

    /** Execute $real; return $redacted (or $real, when there is nothing to redact) for the log. */
    private function run(string $real, ?string $redacted = null): string
    {
        $this->connection->statement($real);

        return $redacted ?? $real;
    }
}
