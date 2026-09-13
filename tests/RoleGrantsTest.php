<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Rushing\PostgresRls\RowLevelSecurity\RoleGrants;

class RoleGrantsTest extends TestCase
{
    public function test_the_scoped_role_can_read_and_write_after_the_grant(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        try {
            $this->scoped('a')->table('posts')->count();
            $this->fail('without a grant the scoped role must be refused');
        } catch (QueryException $e) {
            $this->assertStringContainsString('permission denied', $e->getMessage());
        }

        $statements = (new RoleGrants($this->owner(), self::SCHEMA))->grant(self::SCOPED_ROLE);

        $this->assertCount(5, $statements);
        $this->assertSame('GRANT USAGE ON SCHEMA "rls_test" TO "pgrls_test_scoped"', $statements[0]);
        $this->assertStringContainsString('ALTER DEFAULT PRIVILEGES FOR ROLE "pgrls_test_owner" IN SCHEMA "rls_test"', $statements[3]);

        $this->scoped('a')->table('posts')->insert(['slug' => 'hello']);
        $this->assertSame(1, $this->scoped('a')->table('posts')->count());
        $this->assertSame(1, $this->scoped('a')->table('posts')->where('slug', 'hello')->update(['slug' => 'hi']));
        $this->assertSame(1, $this->scoped('a')->table('posts')->delete());
    }

    public function test_tables_and_sequences_created_later_by_the_owner_are_covered(): void
    {
        $this->createSpikeTables();
        (new RoleGrants($this->owner(), self::SCHEMA))->grant(self::SCOPED_ROLE);

        $this->owner()->unprepared('CREATE TABLE later (id serial PRIMARY KEY, name text NOT NULL)');
        $this->preparer()->prepare();

        // a serial column needs USAGE on its sequence; a plain insert proves the default privilege landed
        $this->scoped('a')->table('later')->insert(['name' => 'x']);
        $this->assertSame(1, $this->scoped('a')->table('later')->count());
        $this->assertSame(0, $this->scoped('b')->table('later')->count());
    }

    public function test_defaults_can_follow_the_role_that_creates_tables_rather_than_the_schema_owner(): void
    {
        // Postgres 15+ `public` shape: the schema belongs to someone else, a login role runs the migrations.
        $admin = $this->admin();
        $admin->unprepared('DROP SCHEMA IF EXISTS rls_shared CASCADE; CREATE SCHEMA rls_shared; GRANT USAGE, CREATE ON SCHEMA rls_shared TO '.self::OWNER_ROLE);

        try {
            (new RoleGrants($admin, 'rls_shared', defaultsFor: self::OWNER_ROLE))->grant(self::SCOPED_ROLE);
            $this->owner()->unprepared('CREATE TABLE rls_shared.created_later (id serial PRIMARY KEY, name text)');

            $this->scoped('a')->table('rls_shared.created_later')->insert(['name' => 'x']);
            $this->assertSame(1, $this->scoped('a')->table('rls_shared.created_later')->count());
        } finally {
            DB::purge('key_a');
            $admin->unprepared('DROP SCHEMA IF EXISTS rls_shared CASCADE');
        }
    }

    public function test_an_unknown_schema_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new RoleGrants($this->owner(), 'no_such_schema'))->grant(self::SCOPED_ROLE);
    }
}
