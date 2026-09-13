<?php

namespace Rushing\PostgresRls;

use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Support\ServiceProvider;
use Rushing\PostgresRls\Audits\AuditScope;
use Rushing\PostgresRls\Audits\ConnectionConfig;
use Rushing\PostgresRls\Audits\CoverageAudit;
use Rushing\PostgresRls\Audits\FrameAudit;
use Rushing\PostgresRls\Audits\OwnerExposureAudit;
use Rushing\PostgresRls\Audits\RoleAudit;
use Rushing\PostgresRls\Console\PrepareCommand;
use Rushing\PostgresRls\Query\ScopedGrammars;

/**
 * Binds {@see SessionSettingsPostgresConnector} at the container key Laravel's
 * `ConnectionFactory` consults before falling back to its own connector
 * (`db.connector.pgsql`), merges the package config, registers the prepare command, binds
 * the four doctor audits with their config-derived scope, and scopes upsert conflict targets and new foreign keys on
 * every connection carrying a custom `session_settings` entry ({@see ScopedGrammars}).
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

        $this->bindAudits();

        // The preparer widened keys under code that names only its own columns: upsert conflict targets and
        // foreign keys added by later migrations. The scoped grammars put the discriminator back (ticket 11).
        $this->app['events']->listen(ConnectionEstablished::class, function (ConnectionEstablished $event) {
            if ($this->app['config']->get('postgres-rls.scope_grammars', true)) {
                ScopedGrammars::apply($event->connection, (string) $this->app['config']->get('postgres-rls.column', 'tenant_id'));
            }
        });
    }

    /**
     * The audits resolve from the container with no arguments (that is the {@see \Rushing\Doctor\DoctorAudit}
     * contract a host's doctor manifest relies on), so their scope comes from config here. A host
     * whose scoped connections exist only at runtime rebinds AuditScope, or the audit, with its own.
     */
    protected function bindAudits(): void
    {
        $this->app->bind(AuditScope::class, fn ($app) => AuditScope::fromConfig((array) $app['config']->get('postgres-rls', [])));
        $this->app->bind(ConnectionConfig::class, fn ($app) => new ConnectionConfig((array) $app['config']->get('database.connections', [])));

        $this->app->bind(CoverageAudit::class, fn ($app) => new CoverageAudit($app['db'], $app->make(AuditScope::class)));

        foreach ([RoleAudit::class, OwnerExposureAudit::class, FrameAudit::class] as $audit) {
            $this->app->bind($audit, fn ($app) => new $audit($app['db'], $app->make(AuditScope::class), $app->make(ConnectionConfig::class)));
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
