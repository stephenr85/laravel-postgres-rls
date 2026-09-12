> You are in **rushing/laravel-postgres-rls** — Postgres row-level security keyed by a session setting: a pgsql connector that applies `session_settings` on every connect and reconnect, a schema preparer that adds a defaulted discriminator column, enables RLS and installs a hashed policy on every table in a schema, a read-only coverage probe, and role grants for the non-owner connection.

Foundation-vendor: requires `illuminate/*` and `rushing/laravel-doctor` only. No tenancy framework,
no `splicewire/*`, no `schemastud/*` (declared in `composer.json` `extra.package-topology` and
enforced by `tests/TopologySeamGuardTest.php`). Host vocabulary stays out of
`src/`: this package says *key*, *discriminator*, *setting*, *schema*, *owner role*, *scoped role*.
The default column name `tenant_id` and setting `app.tenant_id` are config values, not vocabulary.

## Before you change SQL

Every DDL shape here was measured on a real Postgres before it was written (pooled-storage ticket 01
spike, 23/23 on Postgres 17). The suite runs on Postgres only and refuses to start without
`PG_TEST_DATABASE`; a change to any statement in `SchemaPreparer`, `RoleGrants` or `Catalog` is not
done until `PG_TEST_DATABASE=<throwaway> composer test` is green. Create a throwaway database per
session; never point the suite at a shared one.

Three facts the code depends on, each with a test:

- A superuser is never subject to a policy and a table owner is not unless `FORCE` is on, so the
  suite creates a non-superuser owner and a non-owner scoped role. An assertion made on a superuser
  connection proves nothing.
- `ADD COLUMN ... DEFAULT <expr>` evaluates the expression once at ALTER time, even on an empty
  table. That is why the column lands in three statements (lenient default, then strict `SET DEFAULT`,
  then `SET NOT NULL`) rather than one.
- Policy names carry `sha1(body)[:6]`, so the body text in `Policy::body()` is load-bearing: change
  its spelling and every deployed policy becomes "outdated" on the next `prepare()`.

## Where things go

- Mechanism and its reasons: class docblocks (`SchemaPreparer`, `Policy`, `RoleGrants`, `Coverage`,
  `SessionSettingsPostgresConnector`, and each `Audits\*Audit` — every audit's docblock states the
  question it answers and what a Pass does NOT prove). Guarantees, non-guarantees, the privilege
  model and how a host runs the audits: `docs/agents/postgres-rls.convention.md`; `README.md` summarises.
- Audits are gate-shaped (Coverage, Role, OwnerExposure: an unreadable population is a Fail) except
  `FrameAudit`, which is advisory and never Fails. Do not change a shape without changing the
  convention page in the same commit.
- Formatting: `composer pint` before every commit.
