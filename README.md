# rushing/laravel-postgres-rls

**Postgres row-level security keyed by a session setting.** Many keys share one schema; every row
carries a discriminator the database fills and enforces; the connection carries the key. Models
never learn the column exists.

```php
use Rushing\PostgresRls\RowLevelSecurity\SchemaPreparer;

$report = (new SchemaPreparer(DB::connection('owner'), schema: 'pool'))->prepare();
echo $report;
// schema pool: 2 table(s) inspected, 12 statement(s) applied, 0 item(s) skipped
//   comments:
//     applied  ALTER TABLE "pool"."comments" ADD COLUMN tenant_id text DEFAULT current_setting('app.tenant_id', true)
//     ...
```

```php
// config/database.php — a connection that carries the key
'scoped' => [
    'driver' => 'pgsql',
    'username' => env('DB_SCOPED_USERNAME'),   // a NON-owner role, see "Privilege model"
    'search_path' => 'pool',
    'session_settings' => ['app.tenant_id' => $key],
    // ...
],
```

After that, `DB::connection('scoped')->table('posts')->insert(['slug' => 'hello'])` lands a row
under `$key`, `->count()` sees only that key's rows, and a connection with no setting bound sees
zero rows and cannot insert.

## What it does

Four pieces, each usable alone:

| piece | role |
| --- | --- |
| `SessionSettingsPostgresConnector` | a pgsql connector that runs `select set_config(name, value, false)` for every `session_settings` pair after connect — and therefore after every reconnect, because Laravel's `reconnect()` goes back through the connector. Bound at `db.connector.pgsql` by the provider only when nothing else has claimed the key. Works for built-in settings too (`statement_timeout`). |
| `RowLevelSecurity\SchemaPreparer` | for every base table in a schema: adds the discriminator column (`text NOT NULL DEFAULT current_setting('app.tenant_id')`), a btree index on it, `ENABLE ROW LEVEL SECURITY` (and `FORCE` when configured), the policy `USING (col = current_setting('setting', true)) WITH CHECK (same)`, and rewrites unique indexes to lead with the column. Idempotent; a second run reports zero applied statements. Everything runs in one transaction. |
| `RowLevelSecurity\Coverage` | read-only: per table, is RLS enabled, forced as expected, the current policy present, the column present with its default, every unique index covered. `complete(): bool` for a doctor or a post-migrate gate. |
| `RowLevelSecurity\RoleGrants` | grants a named non-owner role `USAGE` on the schema, DML on all tables, `USAGE, SELECT` on all sequences, and the same as default privileges for tables and sequences the owner creates later. Never creates the role or sets a password. |

Plus `postgres-rls:prepare {schema}` (options `--connection`, `--column`, `--setting`,
`--exclude=*`, `--force`) and a publishable `config/postgres-rls.php` holding the defaults:
column `tenant_id`, setting `app.tenant_id`, exclude `['migrations']`, force `false`.

### Policy names carry a hash

A policy is named `{table}_rls_policy_{sha1(body)[:6]}`. Change the column or the setting and the
body changes, so the name changes, so the preparer sees a policy with its prefix but not its name and
replaces it. Policies with the package suffix on tables outside scope are dropped as zombies. Both
ideas, and the dedicated non-owner role for scoped connections, come from
[stancl/tenancy v4's `CreateUserWithRLSPolicies`](https://github.com/archtechx/tenancy/blob/master/src/Commands/CreateUserWithRLSPolicies.php);
this package reimplements them without the framework and without a foreign-key path to a tenants
table — the column is defaulted by the database, so shared migrations need not name it.

## Guarantees

- **Fail-closed.** The policy compares against `current_setting(name, true)`, which is NULL when
  unbound; `col = NULL` is never true. A connection that lost its setting reads nothing and cannot
  insert. The column DEFAULT uses the strict one-argument form, so an unscoped insert throws rather
  than storing an empty key.
- **Writes are scoped too.** `USING` filters UPDATE and DELETE; `WITH CHECK` refuses an INSERT or
  UPDATE that would produce a row bearing another key, even when the column is named explicitly.
- **Reconnect-safe.** The setting rides connection config through the connector; a re-established
  PDO gets it again. A plain `SET` issued once does not survive that.
- **Migration window is closed, not open.** `SchemaPreparer::dropPolicies()` removes the policies
  so a migration can alter the column freely; RLS stays *enabled*, so a non-owner connection reads
  zero rows until `prepare()` runs again.
- **Unique means unique per key.** Every unique index whose key columns lack the discriminator is
  re-created under the same name with the column prepended (through `DROP/ADD CONSTRAINT` when a
  `UNIQUE` constraint owns it), so two keys may share a slug.

## Non-guarantees

- **Foreign-key checks bypass RLS.** A row in key B may reference key A's row by id if B knows the id;
  Postgres validates FKs as the table owner, outside the policy. Measured in the pooled-storage
  ticket 01 spike. Do not rely on RLS to stop a guessed-id reference.
- **Sequences are schema-global.** A serial id is unique across keys but not contiguous per key, and
  gaps reveal that other keys exist. UUID keys are unaffected.
- **Backups are schema-granular.** A dump of the schema contains every key's rows; per-key restore
  is a filtered copy, not a restore.
- **A unique index a foreign key references is not rewritten.** Postgres will not drop it, and the
  referencing table would need the key in its own FK columns. The preparer skips it and reports
  it; `Coverage` lists it separately and does not count it against completeness.
- **Populated tables need the setting bound on the preparing connection.** Postgres evaluates an
  `ADD COLUMN` default once at ALTER time and stamps every existing row with it; unbound, the run
  fails at `SET NOT NULL` with "contains null values" and rolls back. Bind the key the existing rows
  belong to (`select set_config('app.tenant_id', 'that-key', false)`) and run again.

## Privilege model

Row-level security only bites on a role that is neither the table owner nor a superuser:

| role | subject to the policy? | use it for |
| --- | --- | --- |
| superuser (`postgres`; Herd's `root`) | never | nothing in an application |
| table owner | only under `FORCE ROW LEVEL SECURITY` | migrations, `prepare()`, maintenance across keys |
| non-owner role | always | every scoped connection |

`force` defaults **off**: the owner then bypasses the policy and can run migrations without holding
`BYPASSRLS`, which managed Postgres (Cloud SQL, RDS) cannot grant because it hands out no superuser.
Turn it on only where the owner can hold `BYPASSRLS` or never needs to read across keys; with it on,
an owner connection with no setting bound reads zero rows.

On a developer machine every app connection is typically a superuser, so RLS is not exercised at
all unless a non-superuser role is used. That is why the test suite creates its own roles.

## Running the suite

Postgres only; there is no sqlite fallback and `composer test` refuses to start without
`PG_TEST_DATABASE`:

```
psql -U postgres -h 127.0.0.1 -c 'create database test_pgrls'
PG_TEST_DATABASE=test_pgrls composer test
```

Optional: `PG_TEST_HOST` (127.0.0.1), `PG_TEST_PORT` (5432), `PG_TEST_USERNAME` (postgres),
`PG_TEST_PASSWORD` (empty). The user must be able to `CREATE ROLE` and `CREATE SCHEMA`: every test
builds a fresh schema owned by a non-superuser role (`pgrls_test_owner`) and connects as a non-owner
role (`pgrls_test_scoped`) under two keys and under none, then drops both roles. Point it at a
throwaway, session-scoped database (the isolated-test-db pattern: one database per session, created
before the run and dropped after) rather than a shared one — two concurrent runs would reset each
other's schema, and `phpunit.xml` sets `failOnEmptyTestSuite` so a run that reaches no test is red.

## Install

```
composer require rushing/laravel-postgres-rls
php artisan vendor:publish --tag=postgres-rls-config   # optional
```

Requires PHP ^8.2 and `illuminate/database` ^11|^12|^13. No tenancy framework, no product
package. The provider is auto-discovered; it binds the connector only when `db.connector.pgsql`
is unbound. `tpetry/laravel-postgresql-enhanced` overrides the *Connection* class
(`Connection::resolverFor('pgsql')`), not the connector, so both coexist — measured 2026-09-12.

That guard is **fail-open by design**: if another package already holds `db.connector.pgsql`, this
connector is not installed and `session_settings` are silently not applied — every scoped connection
then reads zero rows (the policy is fail-closed) rather than the wrong rows, but nothing says why.
`Coverage` cannot detect it; it reads the schema, not the container. Check the binding instead:
`app('db.connector.pgsql') instanceof Rushing\PostgresRls\SessionSettingsPostgresConnector`, or
`select current_setting('app.tenant_id', true)` on a scoped connection. A host that ships its own
connector should extend this one or call its `applySessionSettings()` from theirs.

## Documentation

- Class docblocks carry the machinery: `SchemaPreparer` (order of operations, the three-step
  column add, the migration window), `Policy` (body, naming, hashing), `RoleGrants` (why a
  separate role), `Coverage` (what is read).
- `docs/agents/` — orientation for agents working in or through this package.

## License

MIT.
