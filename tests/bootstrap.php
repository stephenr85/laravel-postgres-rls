<?php

/*
 * This suite runs on Postgres ONLY, and refuses to run without one. Row-level security does not
 * exist on sqlite; a green run that never reached Postgres would be an instrument that cannot
 * fail. So the gate is here, before PHPUnit discovers a single test.
 *
 * Point it at a throwaway database (create one per session; see README "Running the suite"):
 *
 *   PG_TEST_DATABASE=test_pgrls composer test
 *
 * Optional: PG_TEST_HOST (127.0.0.1), PG_TEST_PORT (5432), PG_TEST_USERNAME (postgres),
 * PG_TEST_PASSWORD (empty). The user must be able to CREATE ROLE and CREATE SCHEMA — the
 * suite creates a non-superuser owner role and a non-owner scoped role, because a superuser
 * is never subject to a policy and the assertions would prove nothing.
 *
 * The second half of the gate is `failOnEmptyTestSuite="true"` in phpunit.xml: a run that
 * discovers no tests (a `--filter` that matches nothing, a broken autoload) exits non-zero instead
 * of reporting "No tests executed" with a green exit code.
 */

require __DIR__.'/../vendor/autoload.php';

$database = getenv('PG_TEST_DATABASE');

if ($database === false || trim($database) === '') {
    fwrite(STDERR, <<<'MSG'

    rushing/laravel-postgres-rls: refusing to run — PG_TEST_DATABASE is not set.

    This suite only runs against a real PostgreSQL database; there is no sqlite fallback,
    because row-level security cannot be exercised without Postgres and a suite that passed
    without it would prove nothing. Create a throwaway database and name it:

        psql -U postgres -h 127.0.0.1 -c 'create database test_pgrls'
        PG_TEST_DATABASE=test_pgrls composer test

    Optional: PG_TEST_HOST, PG_TEST_PORT, PG_TEST_USERNAME, PG_TEST_PASSWORD.


    MSG);

    exit(1);
}
