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

    public function test_a_schema_no_connection_reaches_is_inconclusive_not_clean(): void
    {
        $this->admin()->unprepared(sprintf('CREATE SCHEMA rls_lonely AUTHORIZATION "%s"', self::OWNER_ROLE));

        $finding = $this->audit(maintenance: [], schemas: ['rls_lonely'])->run()[0];

        $this->assertFinding(DoctorStatus::Pass, 'No configured connection reaches schema "rls_lonely"', $finding, conclusive: false);
        $this->assertStringContainsString('owner exposure was not measured', $finding->detail);

        // every configured connection exempted is the same empty population
        $all = array_keys($this->connections()->pgsql());
        $this->assertFinding(DoctorStatus::Pass, 'declared: '.implode(', ', $all), $this->audit(maintenance: $all)->run()[0], conclusive: false);
    }

    public function test_a_connection_without_a_search_path_reaches_public(): void
    {
        $this->addConnection('bare_owner', 'owner', ['search_path' => null]);
        // an unforced table in public, so the owner has something to read across keys
        $this->admin()->unprepared(sprintf('CREATE TABLE public.rls_probe (id int); ALTER SCHEMA public OWNER TO "%s"', self::OWNER_ROLE));

        try {
            $finding = $this->audit(maintenance: ['owner'], schemas: ['public'])->run()[0];
        } finally {
            $this->admin()->unprepared(sprintf('ALTER SCHEMA public OWNER TO "%s"; DROP TABLE public.rls_probe', getenv('PG_TEST_USERNAME') ?: 'postgres'));
        }

        $this->assertFinding(DoctorStatus::Fail, 'Connection(s) bare_owner reach schema "public" as its owner', $finding);
        $this->assertStringContainsString('1 table(s) are not FORCEd (rls_probe)', $finding->detail);
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
        $this->assertSame(['public'], ConnectionConfig::searchPath([]), 'Laravel leaves an absent search_path at the server default, which reaches public');
        $this->assertSame(['public'], ConnectionConfig::searchPath(['search_path' => '']));
    }

    public function test_it_resolves_from_the_container(): void
    {
        $this->createSpikeTables();
        $this->app['config']->set('postgres-rls.audits', ['schemas' => [self::SCHEMA], 'connection' => 'owner', 'maintenance_connections' => ['owner']]);

        $this->assertStatuses(['pass'], $this->app->make(OwnerExposureAudit::class)->run());
    }
}
