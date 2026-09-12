<?php

namespace Rushing\PostgresRls\Tests\Audits;

use Rushing\Doctor\DoctorStatus;
use Rushing\Doctor\Finding;
use Rushing\PostgresRls\Audits\AuditScope;
use Rushing\PostgresRls\Audits\ConnectionConfig;
use Rushing\PostgresRls\Tests\TestCase;

abstract class AuditTestCase extends TestCase
{
    /**
     * @param  ?list<string>  $scoped
     * @param  list<string>  $maintenance
     */
    protected function scope(?array $scoped = null, array $maintenance = ['owner'], bool $force = false, array $schemas = [self::SCHEMA], ?string $connection = 'owner'): AuditScope
    {
        return new AuditScope(
            schemas: $schemas,
            connection: $connection,
            scopedConnections: $scoped,
            maintenanceConnections: $maintenance,
            column: 'tenant_id',
            setting: self::SETTING,
            exclude: ['migrations'],
            force: $force,
        );
    }

    protected function connections(): ConnectionConfig
    {
        return new ConnectionConfig((array) $this->app['config']->get('database.connections'));
    }

    /**
     * Add a connection derived from an existing one, for breaking an invariant.
     *
     * @param  array<string, mixed>  $overrides
     */
    protected function addConnection(string $name, string $from, array $overrides): void
    {
        $this->app['config']->set(
            'database.connections.'.$name,
            $overrides + (array) $this->app['config']->get('database.connections.'.$from),
        );
    }

    /**
     * @param  list<Finding>  $findings
     */
    protected function assertStatuses(array $expected, array $findings): void
    {
        $this->assertSame(
            $expected,
            array_map(fn (Finding $f) => $f->status->value, $findings),
            implode("\n", array_map(fn (Finding $f) => $f->status->value.': '.$f->detail, $findings)),
        );
    }

    protected function assertFinding(DoctorStatus $status, string $needle, Finding $finding, bool $conclusive = true): void
    {
        $this->assertSame($status, $finding->status, $finding->detail);
        $this->assertSame($conclusive, $finding->conclusive, $finding->detail);
        $this->assertStringContainsString($needle, $finding->detail);
    }
}
