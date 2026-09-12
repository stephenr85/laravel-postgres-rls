# Postgres row-level security keyed by a session setting — convention

**Status:** canon for any host that pools several keys in one Postgres schema through this package.
**Decided:** 2026-09-12 (pooled-storage tickets 01–03), on a spike measured 23/23 against Postgres 17
and a suite that runs on Postgres only.
**Mechanism:** `Rushing\PostgresRls` — `SessionSettingsPostgresConnector`, `RowLevelSecurity\SchemaPreparer`,
`RowLevelSecurity\Coverage`, `RowLevelSecurity\RoleGrants`, and the four audits under `Audits\`. This
page states what the mechanism guarantees, what it does not, who may connect as what, and how a host
proves all of it on its own database. The classes document their machinery.

## The shape

One schema, many keys. Every table carries a `text NOT NULL` discriminator column whose DEFAULT is
`current_setting('app.tenant_id')` and a policy
`USING (col = current_setting('app.tenant_id', true)) WITH CHECK (same)`. A scoped connection carries
`session_settings => ['app.tenant_id' => $key]` in its config; the connector applies it with
`set_config(name, value, false)` on every connect. Application code never names the column.

## Guarantees

1. **Own rows only, both directions.** A scoped connection reads, updates and deletes only rows
   bearing its key (`USING`), and cannot produce a row bearing another key, even by naming the column
   (`WITH CHECK`). Measured: two keys, two tables, same slug under both.
2. **Fail-closed on a missing setting.** `current_setting(name, true)` is NULL when unbound and
   `col = NULL` is never true: an unscoped connection reads zero rows. The column DEFAULT uses the
   strict form, so an unscoped insert throws rather than storing an empty key.
3. **Reconnect-safe.** The setting is connection config, applied by the connector; a re-established
   PDO (server restart, pooler recycle, explicit `reconnect()`, `DB::purge()`) gets it again.
4. **The migration window is closed.** `dropPolicies()` removes the policies so a migration can alter
   the column; RLS stays enabled, so scoped connections read zero rows until `prepare()` re-runs.
5. **Idempotent preparation, hashed policies.** A second `prepare()` applies nothing. A policy is named
   `{table}_rls_policy_{sha1(body)[:6]}`, so a changed column or setting is replaced rather than
   duplicated, and a policy with the suffix on an excluded table is dropped as a zombie.
6. **Unique means unique per key.** Every rewritable unique index leads with the column after
   `prepare()`.

## The three non-guarantees

1. **Foreign-key checks bypass RLS.** Postgres validates a FOREIGN KEY as the referenced table's
   owner, outside the policy. Key B can reference key A's row by id if B knows the id, and the
   referenced row need not be visible to B. Measured (spike check 21). There is no gate; a host that
   needs cross-key reference to be impossible puts the key into the FK columns itself.
2. **Sequences are schema-global.** A `serial`/`identity` id is unique across keys but not contiguous
   per key, and a gap reveals that other keys inserted. UUID keys are unaffected. Accepted for the
   base tier; the flagship's census counted 81 serial columns in its shared migration set.
3. **Backups are schema-granular.** A dump of the schema holds every key's rows; restoring one key is
   a filtered copy under that key's frame, not a restore. Promotion to a schema of its own is the
   upgrade path, not backup.

A fourth limit is operational, not a leak: **a unique index a foreign key references is not
rewritten** (Postgres will not drop it), so it stays unique across keys. The preparer reports it,
`Coverage` lists it apart, and the `CoverageAudit` names it in a Pass rather than failing.

## Privilege model

| role | subject to the policy? | belongs on |
| --- | --- | --- |
| superuser | never | nothing in an application; on a developer machine every connection is one, which is why the suite creates roles |
| table owner | only under `FORCE ROW LEVEL SECURITY` | the migration path: `migrate`, `prepare()`, `dropPolicies()`, cross-key maintenance |
| non-owner role (`RoleGrants::grant()`) | always | every scoped connection |

`force` defaults **off**. With it off the owner bypasses the policy and needs no `BYPASSRLS`, which
managed Postgres (Cloud SQL, RDS) cannot grant. With it on the owner is subject too, and reads zero
rows when it carries no setting. Turn it on only where the owner can hold `BYPASSRLS` or never needs
to read across keys. The audits treat an owner on a request path as a Fail while any table is
unforced, and as a Pass that says so when every table is forced.

The connector binding is **fail-open by design**: if another package already holds
`db.connector.pgsql`, this connector is not installed and the settings are silently not applied —
scoped connections then read zero rows, which the `FrameAudit` is the only instrument that sees.

## How a host runs the audits

Four `Rushing\Doctor\DoctorAudit` implementations, bound in the container by the provider from
`config/postgres-rls.php` `audits`, so a host manifest registers them by class and the doctor resolves
them with no arguments:

| audit | question | shape | a Pass does not prove |
| --- | --- | --- | --- |
| `Audits\CoverageAudit` | is every table in each prepared schema in the state `prepare()` leaves it? | **gate** — a Fail is a table that leaks; unreadable connection = Fail; a table FORCEd while `force` is off is safer and is noted, not failed | which role reads it; whether the setting is bound; schemas not in scope |
| `Audits\RoleAudit` | does every scoped connection authenticate as a role the policy binds (not superuser, not `BYPASSRLS`, owns nothing in the schema)? The Pass names the role. | **gate**; unopenable connection = Fail; clean attributes with no schemas configured = inconclusive (ownership unmeasured) | that the setting is bound; that tables carry a policy; runtime-built connections not listed |
| `Audits\OwnerExposureAudit` | does any configured connection whose `search_path` reaches a prepared schema authenticate as its owner, outside the declared maintenance connections? | **gate** while any table is unforced; superuser reaching the schema = Warn; no connection reaching the schema = inconclusive | runtime-built connections; a `url`-style config's user or a member of the owner role — it compares the config `username` only, so it can Pass a connection `RoleAudit` would Fail |
| `Audits\FrameAudit` | on the live session, is the setting bound where it should be and NULL where it should not? The runtime half of the pooler probe. | **advisory** — Warn, never Fail; unopenable = inconclusive | that the value stays bound under a pooler; runtime-built connections |

Every audit reports `Finding::inconclusive()` (a Pass with `conclusive: false`) when its population is
empty — no schemas configured, no scoped connection, a schema with no tables — and says so in the
detail. **Rule 4: a zero from these audits means "nothing here", never "measured clean"**; read the
flag with `DoctorReport::inconclusive()` before trusting a green run.

```php
// config/postgres-rls.php in the host
'audits' => [
    'schemas' => ['pool'],
    'connection' => 'pool_owner',              // reads the catalog; the owner
    'scoped_connections' => null,              // every pgsql connection carrying session_settings
    'maintenance_connections' => ['pool_owner'], // the only place the owner may authenticate
],
```

```php
// the host's doctor manifest
new DoctorRegistration('rushing/laravel-postgres-rls', CoverageAudit::class, gate: true);
new DoctorRegistration('rushing/laravel-postgres-rls', RoleAudit::class, gate: true);
new DoctorRegistration('rushing/laravel-postgres-rls', OwnerExposureAudit::class, gate: true);
new DoctorRegistration('rushing/laravel-postgres-rls', FrameAudit::class);          // advisory
```

**Which audits open a connection.** `OwnerExposureAudit` reads config only — the exposure is the
configured `username`, so config is the honest instrument, and it compares that string with the
schema owner from `pg_namespace` (a connection with no `search_path` key counts as reaching
`public`, Laravel's default). `RoleAudit` and `FrameAudit` **do open** each scoped or probe
connection and run read-only selects (`pg_roles`, `pg_tables`, `current_setting`), because the role
a connection really authenticates as and the setting on its live session are not config facts: a
`url` DSN or a membership of the owner role is invisible to a string comparison. `CoverageAudit`
opens the catalog connection. None of them writes.

A host whose scoped connections exist only at runtime (assembled per request from a key) rebinds
`Audits\AuditScope` with the connection names it wants measured, or constructs an audit directly with
its own scope and `Audits\ConnectionConfig`. The catalog connection named in `connection` is **not**
exempt from `OwnerExposureAudit` unless it is also listed in `maintenance_connections` — a misdeclared
catalog connection must not exempt itself.

## Direct access: a role per key

`RowLevelSecurity\RoleBinder` issues a login role whose **default session setting is one key**
(`ALTER ROLE ... SET app.tenant_id = '<key>'`), grants it the schema through `RoleGrants`, and later
revokes and drops it:

```php
$binder = new RoleBinder(DB::connection('pool_owner'), schema: 'pool');
$binder->bind('pool_acme', 'app.tenant_id', 'acme', password: $oneTimeSecret);
$binder->unbind('pool_acme');
```

**What it is for.** A BI tool, a psql session, a reporting job — anything that connects to Postgres
with no application in the path. Postgres applies a role's `SET` defaults at session start, before
the first statement, so a connection as `pool_acme` carries the setting with no `session_settings`,
no connector and no code, and the same policy scopes it: it reads only `acme`'s rows and every
insert is stamped `acme`. Both `bind()` and `unbind()` are idempotent; a second bind re-asserts the
key and grants (and rotates the password when one is given), a second unbind returns an empty list.

**What it does not do.** It never stores the password and never echoes it — the returned statement
list is redacted. The host hands the credential out once and keeps, at most, the role name. It
never creates a role that bypasses the policy: the role owns nothing, so it is subject to every
policy in the schema, and the `RoleAudit` would fail it if it were not. And it does not protect
against a role holding privileges in another database or owning objects; `DROP ROLE` then fails
with Postgres's own error, which is correct — this package did not create that state.

Run it as a role with `CREATEROLE` that owns the schema or is a member of the owner. Managed
Postgres grants its default user `CREATEROLE` without `SUPERUSER`, which is enough; `BYPASSRLS` is
never needed.

## What the suite proves, and where

Every guarantee above is a test on real Postgres (`tests/`), every non-guarantee is either measured in
the ticket 01 spike or stated as a limit in `README.md`, and every audit has a test that breaks its
invariant and observes the Fail (or the Warn, for the advisory one). `composer test` refuses to run
without `PG_TEST_DATABASE` and fails on an empty suite, so a green run means the policy was exercised.
