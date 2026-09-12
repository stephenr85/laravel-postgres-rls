# Agent orientation — rushing/laravel-postgres-rls

Start with the repository `AGENTS.md` (self-ID, the three measured facts the code depends on, and the
Postgres-only test posture) and the `README.md` (guarantees, non-guarantees, privilege model). The
machinery is documented on the classes themselves: `RowLevelSecurity\SchemaPreparer` for the order
of operations and the migration window, `RowLevelSecurity\Policy` for the body and the hashed name,
`RowLevelSecurity\RoleGrants` for why a scoped connection needs a role that owns nothing, and
`RowLevelSecurity\Coverage` for what the read-only probe reads. Audit conventions (how a host's
doctor consumes `Coverage`, the role audit that catches a superuser app connection) are written
against this package by its consumers and will be pointed to from here when they land.
