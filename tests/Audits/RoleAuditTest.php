<?php

namespace Rushing\PostgresRls\Tests\Audits;

use Rushing\Doctor\DoctorStatus;
use Rushing\PostgresRls\Audits\RoleAudit;

class RoleAuditTest extends AuditTestCase
{
    private function audit(?array $scoped = null): RoleAudit
    {
        return new RoleAudit($this->app['db'], $this->scope(scoped: $scoped), $this->connections());
    }

    public function test_scoped_connections_on_a_non_owner_role_pass_and_name_the_role(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $findings = $this->audit()->run();

        $this->assertStatuses(['pass', 'pass'], $findings);
        $this->assertFinding(DoctorStatus::Pass, 'Scoped connection "key_a" authenticates as role "pgrls_test_scoped"', $findings[0]);
        $this->assertStringContainsString('no table in rls_test', $findings[0]->detail);
        $this->assertStringContainsString('"key_b"', $findings[1]->detail);
    }

    public function test_a_superuser_scoped_connection_fails(): void
    {
        $this->addConnection('key_su', 'admin', ['search_path' => self::SCHEMA, 'session_settings' => ['app.tenant_id' => 'su']]);

        $finding = $this->audit(['key_su'])->run()[0];

        $this->assertFinding(DoctorStatus::Fail, 'is a SUPERUSER', $finding);
        $this->assertStringContainsString('"key_su"', $finding->detail);
    }

    public function test_a_bypassrls_role_fails(): void
    {
        $this->admin()->unprepared(sprintf('ALTER ROLE "%s" BYPASSRLS', self::SCOPED_ROLE));

        $this->assertFinding(DoctorStatus::Fail, 'holds BYPASSRLS', $this->audit(['key_a'])->run()[0]);
    }

    public function test_a_role_owning_a_table_in_the_schema_fails(): void
    {
        $this->createSpikeTables();
        $this->admin()->unprepared(sprintf('ALTER TABLE "%s".posts OWNER TO "%s"', self::SCHEMA, self::SCOPED_ROLE));

        $this->assertFinding(DoctorStatus::Fail, 'owns table(s) rls_test.posts', $this->audit(['key_a'])->run()[0]);
    }

    public function test_a_scoped_connection_authenticating_as_the_schema_owner_fails(): void
    {
        $this->createSpikeTables();
        $this->addConnection('key_owner', 'owner', ['session_settings' => ['app.tenant_id' => 'o']]);

        $finding = $this->audit(['key_owner'])->run()[0];

        $this->assertFinding(DoctorStatus::Fail, 'owns schema(s) rls_test', $finding);
        $this->assertStringContainsString('role "pgrls_test_owner"', $finding->detail);
    }

    public function test_an_unopenable_scoped_connection_fails(): void
    {
        $this->addConnection('key_ghost', 'key_a', ['username' => 'no_such_role']);

        $this->assertFinding(DoctorStatus::Fail, 'Could not open scoped connection "key_ghost"', $this->audit(['key_ghost'])->run()[0]);
    }

    public function test_no_scoped_connection_is_inconclusive(): void
    {
        $this->assertFinding(DoctorStatus::Pass, 'No connection carries session_settings', $this->audit([])->run()[0], conclusive: false);
    }

    public function test_it_resolves_from_the_container(): void
    {
        $this->app['config']->set('postgres-rls.audits.schemas', [self::SCHEMA]);

        $this->assertStatuses(['pass', 'pass'], $this->app->make(RoleAudit::class)->run());
    }
}
