<?php

namespace Rushing\PostgresRls;

use Illuminate\Support\ServiceProvider;
use Rushing\PostgresRls\Console\PrepareCommand;

/**
 * Binds {@see SessionSettingsPostgresConnector} at the container key Laravel's
 * `ConnectionFactory` consults before falling back to its own connector
 * (`db.connector.pgsql`), merges the package config, and registers the prepare command.
 *
 * The connector is bound ONLY when nothing else has claimed the key, so a host that already
 * ships its own pgsql connector keeps it; wrap or extend this class there instead.
 *
 * Coexistence with `tpetry/laravel-postgresql-enhanced`: that package overrides the
 * CONNECTION class via `Connection::resolverFor('pgsql', ...)`, not the connector, so the two
 * are independent seams and both stay active. Measured 2026-09-12 (pooled-storage ticket 01
 * spike, `evidence/01-spike.md` check 2): with this connector bound, the resolved connection
 * class was `Tpetry\PostgresqlEnhanced\PostgresEnhancedConnection` and the session setting was
 * applied on connect and re-applied after `reconnect()`.
 */
class PostgresRlsServiceProvider extends ServiceProvider
{
    public const CONNECTOR_KEY = 'db.connector.pgsql';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/postgres-rls.php', 'postgres-rls');

        if (! $this->app->bound(self::CONNECTOR_KEY)) {
            $this->app->bind(self::CONNECTOR_KEY, SessionSettingsPostgresConnector::class);
        }
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/postgres-rls.php' => $this->app->configPath('postgres-rls.php'),
            ], 'postgres-rls-config');

            $this->commands([PrepareCommand::class]);
        }
    }
}
