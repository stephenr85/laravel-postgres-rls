<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Rushing\PostgresRls\RowLevelSecurity\Catalog;
use Rushing\PostgresRls\RowLevelSecurity\RoleBinder;

class RoleBinderTest extends TestCase
{
    private function binder(): RoleBinder
    {
        // a superuser here; on managed Postgres a CREATEROLE user that owns the schema
        return new RoleBinder($this->admin(), self::SCHEMA);
    }

    private function direct(): \Illuminate\Database\Connection
    {
        $this->app['config']->set('database.connections.direct', [
            'username' => self::DIRECT_ROLE,
            'password' => 'once',
        ] + (array) $this->app['config']->get('database.connections.unset'));

        return DB::connection('direct');
    }

    public function test_a_direct_connection_as_the_bound_role_sees_one_key_with_no_session_settings(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $this->grantScopedRole();
        $this->scoped('a')->table('posts')->insert(['slug' => 'mine']);
        $this->scoped('b')->table('posts')->insert(['slug' => 'theirs']);

        $statements = $this->binder()->bind(self::DIRECT_ROLE, self::SETTING, 'a', 'once');

        $this->assertSame('CREATE ROLE "pgrls_test_direct" LOGIN PASSWORD \'[redacted]\'', $statements[0]);
        $this->assertSame('ALTER ROLE "pgrls_test_direct" SET app.tenant_id = \'a\'', $statements[1]);
        $this->assertContains('GRANT USAGE ON SCHEMA "rls_test" TO "pgrls_test_direct"', $statements);
        $this->assertStringNotContainsString('once', implode("\n", $statements), 'the password is never echoed');

        $direct = $this->direct();
        $this->assertArrayNotHasKey('session_settings', $this->app['config']->get('database.connections.direct'));

        $this->assertSame('a', $this->currentSetting($direct), 'the role default binds the setting before any statement');
        $this->assertSame(['mine'], $direct->table('posts')->pluck('slug')->all());

        $direct->table('posts')->insert(['slug' => 'direct']);
        $this->assertSame('a', $direct->table('posts')->where('slug', 'direct')->value('tenant_id'), 'the default stamps the role\'s key');
        $this->assertSame(2, $this->scoped('a')->table('posts')->count());
        $this->assertSame(1, $this->scoped('b')->table('posts')->count());
    }

    public function test_bind_is_idempotent_and_re_asserts_the_key(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $this->binder()->bind(self::DIRECT_ROLE, self::SETTING, 'a');
        $again = $this->binder()->bind(self::DIRECT_ROLE, self::SETTING, 'b', 'rotated');

        $this->assertSame('ALTER ROLE "pgrls_test_direct" WITH PASSWORD \'[redacted]\'', $again[0]);
        $this->assertSame('ALTER ROLE "pgrls_test_direct" SET app.tenant_id = \'b\'', $again[1]);
        $this->assertStringNotContainsString('CREATE ROLE', implode("\n", $again));
        $this->assertSame('b', $this->currentSetting($this->direct()));
    }

    public function test_unbind_revokes_drops_and_is_a_noop_the_second_time(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $this->binder()->bind(self::DIRECT_ROLE, self::SETTING, 'a');
        $this->owner()->unprepared('CREATE TABLE later (id serial PRIMARY KEY)');

        $statements = $this->binder()->unbind(self::DIRECT_ROLE);

        $this->assertSame('DROP ROLE "pgrls_test_direct"', end($statements));
        $this->assertContains('ALTER DEFAULT PRIVILEGES FOR ROLE "pgrls_test_owner" IN SCHEMA "rls_test" REVOKE ALL ON TABLES FROM "pgrls_test_direct"', $statements);
        $this->assertFalse((new Catalog($this->admin()))->roleExists(self::DIRECT_ROLE));

        $this->assertSame([], $this->binder()->unbind(self::DIRECT_ROLE), 'a second unbind says nothing to do');
    }

    public function test_the_setting_must_be_namespaced(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->binder()->bind(self::DIRECT_ROLE, 'tenant_id', 'a');
    }
}
