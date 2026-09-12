<?php

namespace Rushing\PostgresRls\Tests\Audits;

use Illuminate\Database\Connectors\PostgresConnector;
use Illuminate\Support\Facades\DB;
use Rushing\Doctor\DoctorStatus;
use Rushing\PostgresRls\Audits\FrameAudit;
use Rushing\PostgresRls\PostgresRlsServiceProvider;

class FrameAuditTest extends AuditTestCase
{
    private function audit(?array $scoped = null): FrameAudit
    {
        return new FrameAudit($this->app['db'], $this->scope(scoped: $scoped), $this->connections());
    }

    public function test_scoped_connections_carry_the_setting_and_unscoped_ones_do_not(): void
    {
        $findings = $this->audit()->run();

        // key_a, key_b scoped; owner and unset reach the schema without settings
        $this->assertStatuses(['pass', 'pass', 'pass', 'pass'], $findings);
        $this->assertFinding(DoctorStatus::Pass, 'Connection "key_a": app.tenant_id = "a" on the live session', $findings[0]);
        $this->assertFinding(DoctorStatus::Pass, 'Connection "owner": app.tenant_id is NULL', $findings[2]);
        $this->assertFinding(DoctorStatus::Pass, 'Connection "unset": app.tenant_id is NULL', $findings[3]);
    }

    public function test_a_scoped_connection_without_the_connector_warns(): void
    {
        // the fail-open shape: another package holds db.connector.pgsql
        $this->app->bind(PostgresRlsServiceProvider::CONNECTOR_KEY, fn () => new PostgresConnector);
        DB::purge('key_a');

        $finding = $this->audit(['key_a'])->run()[0];

        $this->assertFinding(DoctorStatus::Warn, 'carries session_settings but app.tenant_id is NOT bound on the live session', $finding);
        $this->assertStringContainsString('db.connector.pgsql', $finding->detail);
    }

    public function test_a_stale_frame_on_a_scoped_connection_warns(): void
    {
        $this->scoped('a')->statement("select set_config('app.tenant_id', 'zzz', false)");

        $this->assertFinding(DoctorStatus::Warn, 'on the live session but config says "a": a stale frame', $this->audit(['key_a'])->run()[0]);
    }

    public function test_a_leaked_frame_on_an_unscoped_connection_warns(): void
    {
        $this->unset()->statement("select set_config('app.tenant_id', 'leak', false)");

        $findings = $this->audit([])->run();

        $this->assertStatuses(['pass', 'warn'], $findings);
        $this->assertFinding(DoctorStatus::Warn, 'Connection "unset" carries no session_settings yet app.tenant_id = "leak"', $findings[1]);
    }

    public function test_an_unopenable_connection_is_inconclusive_never_fail(): void
    {
        $this->addConnection('key_ghost', 'key_a', ['username' => 'no_such_role']);

        $this->assertFinding(DoctorStatus::Pass, 'Could not open connection "key_ghost"', $this->audit(['key_ghost'])->run()[0], conclusive: false);
    }

    public function test_nothing_to_read_is_inconclusive(): void
    {
        $audit = new FrameAudit($this->app['db'], $this->scope(scoped: [], schemas: []), $this->connections());

        $this->assertFinding(DoctorStatus::Pass, 'no frame was read', $audit->run()[0], conclusive: false);
    }

    public function test_it_resolves_from_the_container(): void
    {
        $this->app['config']->set('postgres-rls.audits.schemas', [self::SCHEMA]);

        $this->assertStatuses(['pass', 'pass', 'pass', 'pass'], $this->app->make(FrameAudit::class)->run());
    }
}
