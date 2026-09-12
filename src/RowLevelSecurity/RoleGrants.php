<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;
use InvalidArgumentException;

/**
 * Grants a named NON-OWNER role what a scoped connection needs on a prepared schema: usage on
 * the schema, DML on every table, read/next on every sequence, and the same on tables and
 * sequences the schema owner creates later (`ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`).
 *
 * Why a separate role at all: a table's OWNER is not subject to its policies unless
 * `FORCE ROW LEVEL SECURITY` is on, and a SUPERUSER is never subject to them. Row-level
 * security therefore only bites on a connection that is neither — so the scoped connection
 * must authenticate as a role that owns nothing. Prior art: stancl/tenancy v4's dedicated RLS
 * user (`CreateUserWithRLSPolicies`).
 *
 * This class never creates the role and never sets a password. Provisioning a login role and
 * its credential is the host's job (and on managed Postgres often the operator's).
 *
 * Run it as the schema owner or a superuser: `ALTER DEFAULT PRIVILEGES FOR ROLE x` is only
 * allowed to members of `x`.
 */
final class RoleGrants
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
     * @return list<string> the statements executed, in order
     */
    public function grant(string $role): array
    {
        $owner = $this->catalog->schemaOwner($this->schema);

        if ($owner === null) {
            throw new InvalidArgumentException(sprintf('Schema "%s" does not exist.', $this->schema));
        }

        $schema = Identifier::quote($this->schema);
        $grantee = Identifier::quote($role);
        $forOwner = Identifier::quote($owner);

        $statements = [
            sprintf('GRANT USAGE ON SCHEMA %s TO %s', $schema, $grantee),
            sprintf('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %s TO %s', $schema, $grantee),
            sprintf('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %s TO %s', $schema, $grantee),
            sprintf('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s', $forOwner, $schema, $grantee),
            sprintf('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT USAGE, SELECT ON SEQUENCES TO %s', $forOwner, $schema, $grantee),
        ];

        $this->connection->transaction(function () use ($statements) {
            foreach ($statements as $statement) {
                $this->connection->statement($statement);
            }
        });

        return $statements;
    }
}
