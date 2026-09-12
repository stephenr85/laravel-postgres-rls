<?php

/*
 * Defaults for `postgres-rls:prepare` and for hosts constructing SchemaPreparer / Coverage
 * from config. Every key can be overridden per call.
 */
return [

    /*
     * The discriminator column the preparer adds to every table in scope. Its value is filled
     * by a database default from the session setting below, so application code never names it.
     */
    'column' => 'tenant_id',

    /*
     * The session setting the column defaults from and the policy compares against. Postgres
     * custom settings MUST be namespaced (`app.key`); an unnamespaced name is rejected.
     */
    'setting' => 'app.tenant_id',

    /*
     * Tables in the schema the preparer leaves untouched. Policies carrying the package's
     * `_rls_policy_` suffix on an excluded table are dropped as zombies.
     */
    'exclude' => ['migrations'],

    /*
     * `FORCE ROW LEVEL SECURITY` makes the table OWNER subject to the policy too. Off by default:
     * the owner then bypasses the policy and can run migrations and maintenance without holding
     * BYPASSRLS, which managed Postgres (Cloud SQL, RDS) cannot grant. Turn it on only where the
     * owner role can hold BYPASSRLS or never needs to read across keys.
     */
    'force' => false,

];
