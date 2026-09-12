<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Support\Facades\DB;
use Rushing\PostgresRls\PostgresRlsServiceProvider;
use Rushing\PostgresRls\SessionSettingsPostgresConnector;

class SessionSettingsConnectorTest extends TestCase
{
    public function test_the_provider_binds_the_connector_at_the_container_key(): void
    {
        $this->assertInstanceOf(
            SessionSettingsPostgresConnector::class,
            $this->app->make(PostgresRlsServiceProvider::CONNECTOR_KEY),
        );
    }

    public function test_the_provider_leaves_an_existing_binding_alone(): void
    {
        $this->app->bind(PostgresRlsServiceProvider::CONNECTOR_KEY, fn () => 'sentinel');

        (new PostgresRlsServiceProvider($this->app))->register();

        $this->assertSame('sentinel', $this->app->make(PostgresRlsServiceProvider::CONNECTOR_KEY));
    }

    public function test_the_setting_is_applied_on_connect(): void
    {
        $this->assertSame('a', $this->currentSetting($this->scoped('a')));
        $this->assertSame('b', $this->currentSetting($this->scoped('b')));
        $this->assertNull($this->currentSetting($this->unset()));
    }

    public function test_the_setting_is_reapplied_after_reconnect(): void
    {
        $connection = $this->scoped('a');
        $before = spl_object_id($connection->getPdo());

        $connection->reconnect();

        $this->assertNotSame($before, spl_object_id($connection->getPdo()), 'reconnect() must hand out a new PDO for this to prove anything');
        $this->assertSame('a', $this->currentSetting($connection));
    }

    public function test_the_setting_is_reapplied_on_a_fresh_connection_after_purge(): void
    {
        $before = spl_object_id($this->scoped('a'));

        DB::purge('key_a');
        $connection = $this->scoped('a');

        $this->assertNotSame($before, spl_object_id($connection), 'purge() must resolve a new Connection for this to prove anything');
        $this->assertSame('a', $this->currentSetting($connection));
    }

    public function test_the_setting_is_session_scoped_and_survives_transactions(): void
    {
        $connection = $this->scoped('a');

        $connection->transaction(fn ($c) => $c->selectOne('select 1'));
        $this->assertSame('a', $this->currentSetting($connection));

        $connection->transaction(fn ($c) => $c->selectOne('select 1'));
        $this->assertSame('a', $this->currentSetting($connection));
    }

    public function test_every_pair_is_applied_and_values_are_cast_to_string(): void
    {
        $config = $this->app['config']->get('database.connections.key_a');
        $config['session_settings'] = ['app.tenant_id' => 'multi', 'app.shard' => 42];
        $this->app['config']->set('database.connections.multi', $config);

        $connection = DB::connection('multi');

        $this->assertSame('multi', $this->currentSetting($connection));
        $this->assertSame('42', $this->currentSetting($connection, 'app.shard'));

        DB::purge('multi');
    }
}
