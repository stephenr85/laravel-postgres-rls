<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase as Orchestra;
use Rushing\PostgresRls\PostgresRlsServiceProvider;
use Rushing\PostgresRls\RowLevelSecurity\Coverage;
use Rushing\PostgresRls\RowLevelSecurity\RoleGrants;
use Rushing\PostgresRls\RowLevelSecurity\SchemaPreparer;

/**
 * Every test gets a fresh schema owned by a NON-superuser role, and five connections:
 *
 *   admin   — the PG_TEST_* user (a superuser locally); creates roles and the schema, and
 *             is used for nothing an assertion depends on, because a superuser bypasses RLS
 *   owner   — the schema owner; creates tables, runs the preparer; not subject to a policy
 *             unless FORCE is on
 *   key_a   — the scoped role with `app.tenant_id = a`
 *   key_b   — the scoped role with `app.tenant_id = b`
 *   unset   — the scoped role with no setting bound
 *
 * Roles are cluster-global, so they are created if absent and dropped in tearDown after
 * `DROP OWNED BY` clears the default privileges RoleGrants leaves behind.
 */
abstract class TestCase extends Orchestra
{
    public const SCHEMA = 'rls_test';

    public const OWNER_ROLE = 'pgrls_test_owner';

    public const SCOPED_ROLE = 'pgrls_test_scoped';

    /** Issued by RoleBinder in its tests; dropped in tearDown if a test left it behind. */
    public const DIRECT_ROLE = 'pgrls_test_direct';

    public const SETTING = 'app.tenant_id';

    protected function getPackageProviders($app): array
    {
        return [PostgresRlsServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $base = [
            'driver' => 'pgsql',
            'host' => getenv('PG_TEST_HOST') ?: '127.0.0.1',
            'port' => (int) (getenv('PG_TEST_PORT') ?: 5432),
            'database' => getenv('PG_TEST_DATABASE'),
            'username' => getenv('PG_TEST_USERNAME') ?: 'postgres',
            'password' => getenv('PG_TEST_PASSWORD') ?: '',
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => self::SCHEMA,
            'sslmode' => 'prefer',
        ];

        $app['config']->set('database.default', 'owner');
        $app['config']->set('database.connections.admin', ['search_path' => 'public'] + $base);
        $app['config']->set('database.connections.owner', ['username' => self::OWNER_ROLE, 'password' => ''] + $base);
        $app['config']->set('database.connections.key_a', $this->scopedConnection($base, ['app.tenant_id' => 'a']));
        $app['config']->set('database.connections.key_b', $this->scopedConnection($base, ['app.tenant_id' => 'b']));
        $app['config']->set('database.connections.unset', $this->scopedConnection($base, []));
    }

    /**
     * @param  array<string, mixed>  $base
     * @param  array<string, string>  $settings
     * @return array<string, mixed>
     */
    protected function scopedConnection(array $base, array $settings): array
    {
        $config = ['username' => self::SCOPED_ROLE, 'password' => ''] + $base;

        if ($settings !== []) {
            $config['session_settings'] = $settings;
        }

        return $config;
    }

    protected function setUp(): void
    {
        parent::setUp();

        $admin = $this->admin();

        foreach ([self::OWNER_ROLE, self::SCOPED_ROLE] as $role) {
            $admin->unprepared(sprintf(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE \"%s\" LOGIN; END IF; END $$",
                $role,
                $role,
            ));
        }

        $admin->unprepared(sprintf('DROP SCHEMA IF EXISTS "%s" CASCADE', self::SCHEMA));
        $admin->unprepared(sprintf('CREATE SCHEMA "%s" AUTHORIZATION "%s"', self::SCHEMA, self::OWNER_ROLE));
        $admin->unprepared(sprintf('GRANT USAGE ON SCHEMA "%s" TO "%s"', self::SCHEMA, self::SCOPED_ROLE));
    }

    protected function tearDown(): void
    {
        foreach (['owner', 'key_a', 'key_b', 'unset', 'direct'] as $name) {
            DB::purge($name);
        }

        $admin = $this->admin();
        $admin->unprepared(sprintf(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN EXECUTE 'DROP OWNED BY \"%s\"'; EXECUTE 'DROP ROLE \"%s\"'; END IF; END $$",
            self::DIRECT_ROLE,
            self::DIRECT_ROLE,
            self::DIRECT_ROLE,
        ));
        $admin->unprepared(sprintf('DROP SCHEMA IF EXISTS "%s" CASCADE', self::SCHEMA));
        $admin->unprepared(sprintf('DROP OWNED BY "%s", "%s"', self::OWNER_ROLE, self::SCOPED_ROLE));
        $admin->unprepared(sprintf('DROP ROLE IF EXISTS "%s", "%s"', self::OWNER_ROLE, self::SCOPED_ROLE));
        DB::purge('admin');

        parent::tearDown();
    }

    protected function admin(): Connection
    {
        return DB::connection('admin');
    }

    protected function owner(): Connection
    {
        return DB::connection('owner');
    }

    protected function scoped(string $key): Connection
    {
        return DB::connection('key_'.$key);
    }

    protected function unset(): Connection
    {
        return DB::connection('unset');
    }

    /**
     * The spike's two tables, created as the owner with NO discriminator, NO RLS: the preparer
     * has to add everything. `posts.slug` is unique on its own — the preparer must widen it.
     */
    protected function createSpikeTables(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE posts (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                slug text NOT NULL
            );
            CREATE TABLE comments (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                post_id uuid NOT NULL REFERENCES posts(id),
                body text NOT NULL
            );
            CREATE UNIQUE INDEX posts_slug_unique ON posts (slug);
            CREATE TABLE migrations (
                id serial PRIMARY KEY,
                migration text NOT NULL
            );
            SQL);
    }

    /**
     * @param  list<string>  $exclude
     */
    protected function preparer(bool $force = false, array $exclude = ['migrations'], string $column = 'tenant_id', string $setting = self::SETTING): SchemaPreparer
    {
        return new SchemaPreparer($this->owner(), self::SCHEMA, $column, $setting, $exclude, $force);
    }

    protected function coverage(bool $force = false): Coverage
    {
        return new Coverage($this->owner(), self::SCHEMA, 'tenant_id', self::SETTING, ['migrations'], $force);
    }

    protected function grantScopedRole(): void
    {
        (new RoleGrants($this->owner(), self::SCHEMA))->grant(self::SCOPED_ROLE);
    }

    protected function currentSetting(Connection $connection, string $setting = self::SETTING): ?string
    {
        return $connection->selectOne('select current_setting(?, true) as v', [$setting])->v;
    }
}
