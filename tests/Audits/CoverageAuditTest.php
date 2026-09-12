<?php

namespace Rushing\PostgresRls\Tests\Audits;

use Rushing\Doctor\DoctorStatus;
use Rushing\PostgresRls\Audits\CoverageAudit;

class CoverageAuditTest extends AuditTestCase
{
    private function audit(bool $force = false, array $schemas = [self::SCHEMA], ?string $connection = 'owner'): CoverageAudit
    {
        return new CoverageAudit($this->app['db'], $this->scope(force: $force, schemas: $schemas, connection: $connection));
    }

    public function test_a_prepared_schema_passes_and_names_its_tables(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $findings = $this->audit()->run();

        $this->assertCount(1, $findings);
        $this->assertFinding(DoctorStatus::Pass, 'all 2 table(s) carry the column', $findings[0]);
        $this->assertSame(CoverageAudit::CHECK, $findings[0]->check);
    }

    public function test_an_unprepared_schema_fails_naming_every_table(): void
    {
        $this->createSpikeTables();

        $finding = $this->audit()->run()[0];

        $this->assertFinding(DoctorStatus::Fail, '2 of 2 table(s) are not covered', $finding);
        $this->assertStringContainsString('posts: column absent', $finding->detail);
        $this->assertStringContainsString('postgres-rls:prepare rls_test', $finding->detail);
    }

    public function test_each_broken_invariant_fails(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $owner = $this->owner();

        $owner->unprepared('ALTER TABLE posts DISABLE ROW LEVEL SECURITY');
        $this->assertFinding(DoctorStatus::Fail, 'posts: row level security not enabled', $this->audit()->run()[0]);
        $owner->unprepared('ALTER TABLE posts ENABLE ROW LEVEL SECURITY');

        $this->preparer()->dropPolicies();
        $this->assertFinding(DoctorStatus::Fail, 'policy absent', $this->audit()->run()[0]);
        $this->preparer()->prepare();

        $owner->unprepared('ALTER TABLE comments ALTER COLUMN tenant_id DROP DEFAULT');
        $this->assertFinding(DoctorStatus::Fail, 'comments: column absent, nullable, or not defaulted', $this->audit()->run()[0]);
        $owner->unprepared("ALTER TABLE comments ALTER COLUMN tenant_id SET DEFAULT current_setting('app.tenant_id')");

        $owner->unprepared('CREATE UNIQUE INDEX comments_body_unique ON comments (body)');
        $this->assertFinding(DoctorStatus::Fail, 'unique index(es) lacking the column: comments_body_unique', $this->audit()->run()[0]);
        $owner->unprepared('DROP INDEX comments_body_unique');

        $this->assertFinding(DoctorStatus::Pass, 'all 2 table(s)', $this->audit()->run()[0]);
    }

    public function test_forced_is_required_only_when_force_is_on(): void
    {
        $this->createSpikeTables();
        $this->preparer(force: true)->prepare();

        $this->assertFinding(DoctorStatus::Pass, 'enabled and forced', $this->audit(force: true)->run()[0]);

        $safer = $this->audit(force: false)->run()[0];
        $this->assertFinding(DoctorStatus::Pass, '2 table(s) are FORCEd although force is off (strictly safer', $safer);
        $this->assertStringContainsString('comments, posts', $safer->detail);

        $this->owner()->unprepared('ALTER TABLE posts NO FORCE ROW LEVEL SECURITY');
        $this->assertFinding(DoctorStatus::Fail, 'posts: row level security not forced', $this->audit(force: true)->run()[0]);
    }

    public function test_a_foreign_key_backed_unique_index_is_noted_not_failed(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE authors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL UNIQUE);
            CREATE TABLE books (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), author_email text NOT NULL REFERENCES authors(email));
            SQL);
        $this->preparer()->prepare();

        $finding = $this->audit()->run()[0];

        $this->assertFinding(DoctorStatus::Pass, 'Unique indexes the preparer cannot rewrite: authors.authors_email_key', $finding);
    }

    public function test_nothing_to_measure_is_inconclusive_not_clean(): void
    {
        $this->assertFinding(DoctorStatus::Pass, 'No prepared schemas are configured', $this->audit(schemas: [])->run()[0], conclusive: false);
        $this->assertFinding(DoctorStatus::Pass, 'has no tables in scope', $this->audit()->run()[0], conclusive: false);
    }

    public function test_an_unreadable_connection_is_a_fail_not_a_pass(): void
    {
        $this->createSpikeTables();
        $this->addConnection('ghost', 'owner', ['username' => 'no_such_role']);

        $this->assertFinding(DoctorStatus::Fail, 'coverage is unverified', $this->audit(connection: 'ghost')->run()[0]);
    }

    public function test_it_resolves_from_the_container_with_the_config_scope(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $this->app['config']->set('postgres-rls.audits.schemas', [self::SCHEMA]);
        $this->app['config']->set('postgres-rls.audits.connection', 'owner');

        $findings = $this->app->make(CoverageAudit::class)->run();

        $this->assertFinding(DoctorStatus::Pass, 'Schema "rls_test"', $findings[0]);
    }
}
