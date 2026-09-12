<?php

namespace Rushing\PostgresRls\Tests;

use Rushing\PostgresRls\RowLevelSecurity\Catalog;

class PrepareCommandTest extends TestCase
{
    public function test_the_command_prepares_the_schema_and_prints_the_report(): void
    {
        $this->createSpikeTables();

        $this->artisan('postgres-rls:prepare', ['schema' => self::SCHEMA, '--connection' => 'owner'])
            ->expectsOutputToContain('schema rls_test: 2 table(s) inspected')
            ->expectsOutputToContain('applied  ALTER TABLE "rls_test"."posts" ENABLE ROW LEVEL SECURITY')
            ->assertExitCode(0);

        $this->assertTrue($this->coverage()->probe()->complete());

        $this->artisan('postgres-rls:prepare', ['schema' => self::SCHEMA])
            ->expectsOutputToContain('posts: up to date')
            ->assertExitCode(0);
    }

    public function test_options_override_the_config_defaults(): void
    {
        $this->createSpikeTables();
        $this->app['config']->set('postgres-rls.exclude', ['migrations', 'comments']);

        $this->artisan('postgres-rls:prepare', ['schema' => self::SCHEMA, '--force' => true])
            ->expectsOutputToContain('applied  ALTER TABLE "rls_test"."posts" FORCE ROW LEVEL SECURITY')
            ->assertExitCode(0);

        $catalog = new Catalog($this->owner());
        $this->assertTrue($catalog->rowSecurity(self::SCHEMA, 'posts')['forced']);
        $this->assertFalse($catalog->rowSecurity(self::SCHEMA, 'comments')['enabled'], 'config exclude is honoured');

        $this->artisan('postgres-rls:prepare', ['schema' => self::SCHEMA, '--exclude' => ['migrations'], '--setting' => 'app.other'])
            ->expectsOutputToContain('comments:')
            ->assertExitCode(0);

        $this->assertTrue($catalog->rowSecurity(self::SCHEMA, 'comments')['enabled']);
        $this->assertTrue($catalog->isSettingDefault($catalog->column(self::SCHEMA, 'comments', 'tenant_id')['default'], 'app.other'));
    }

    public function test_the_config_file_ships_the_documented_defaults(): void
    {
        $this->assertSame('tenant_id', $this->app['config']->get('postgres-rls.column'));
        $this->assertSame('app.tenant_id', $this->app['config']->get('postgres-rls.setting'));
        $this->assertSame(['migrations'], $this->app['config']->get('postgres-rls.exclude'));
        $this->assertFalse($this->app['config']->get('postgres-rls.force'));
    }
}
