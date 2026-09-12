<?php

namespace Rushing\PostgresRls\Tests\Audits;

use Rushing\Doctor\DoctorStatus;
use Rushing\PostgresRls\Audits\ConnectionConfig;
use Rushing\PostgresRls\Audits\OwnerExposureAudit;

class OwnerExposureAuditTest extends AuditTestCase
{
    private function audit(array $maintenance = ['owner'], array $schemas = [self::SCHEMA]): OwnerExposureAudit
    {
        return new OwnerExposureAudit($this->app['db'], $this->scope(maintenance: $maintenance, schemas: $schemas), $this->connections());
    }

    public function test_the_owner_on_a_request_path_fails_while_any_table_is_unforced(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $finding = $this->audit(maintenance: [])->run()[0];

        $this->assertFinding(DoctorStatus::Fail, 'Connection(s) owner reach schema "rls_test" as its owner "pgrls_test_owner"', $finding);
        $this->assertStringContainsString('2 table(s) are not FORCEd (comments, posts)', $finding->detail);
    }

    public function test_the_declared_maintenance_connection_is_exempt(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $finding = $this->audit(maintenance: ['owner'])->run()[0];

        $this->assertFinding(DoctorStatus::Pass, 'No connection reaches schema "rls_test" as its owner', $finding);
        $this->assertStringContainsString('outside the maintenance path (key_a, key_b, unset)', $finding->detail);
    }

    public function test_the_owner_is_tolerated_when_every_table_is_forced(): void
    {
        $this->createSpikeTables();
        $this->preparer(force: true)->prepare();

        $this->assertFinding(DoctorStatus::Pass, 'every table there is FORCEd', $this->audit(maintenance: [])->run()[0]);

        $this->owner()->unprepared('ALTER TABLE posts NO FORCE ROW LEVEL SECURITY');
        $this->assertFinding(DoctorStatus::Fail, '1 table(s) are not FORCEd (posts)', $this->audit(maintenance: [])->run()[0]);
    }

    public function test_a_superuser_reaching_the_schema_warns(): void
    {
        $this->createSpikeTables();
        $this->addConnection('su_pool', 'admin', ['search_path' => '"rls_test", public']);

        $this->assertFinding(DoctorStatus::Warn, 'Connection(s) su_pool reach schema "rls_test" as a SUPERUSER', $this->audit()->run()[0]);
    }

    public function test_a_missing_schema_fails_and_an_empty_scope_is_inconclusive(): void
    {
        $this->assertFinding(DoctorStatus::Fail, 'Schema "nope" does not exist', $this->audit(schemas: ['nope'])->run()[0]);
        $this->assertFinding(DoctorStatus::Pass, 'No prepared schemas are configured', $this->audit(schemas: [])->run()[0], conclusive: false);
    }

    public function test_search_path_is_parsed_in_every_shape_laravel_accepts(): void
    {
        $this->assertSame(['rls_test'], ConnectionConfig::searchPath(['search_path' => 'rls_test']));
        $this->assertSame(['rls_test', 'public'], ConnectionConfig::searchPath(['search_path' => '"rls_test", public']));
        $this->assertSame(['rls_test', 'public'], ConnectionConfig::searchPath(['search_path' => ['rls_test', 'public']]));
        $this->assertSame(['legacy'], ConnectionConfig::searchPath(['schema' => 'legacy']));
        $this->assertSame([], ConnectionConfig::searchPath([]));
    }

    public function test_it_resolves_from_the_container(): void
    {
        $this->createSpikeTables();
        $this->app['config']->set('postgres-rls.audits', ['schemas' => [self::SCHEMA], 'connection' => 'owner', 'maintenance_connections' => ['owner']]);

        $this->assertStatuses(['pass'], $this->app->make(OwnerExposureAudit::class)->run());
    }
}
