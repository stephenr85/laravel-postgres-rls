<?php

namespace Rushing\PostgresRls\Tests;

use Rushing\PostgresRls\RowLevelSecurity\Policy;

class CoverageTest extends TestCase
{
    public function test_an_unprepared_schema_is_incomplete_on_every_axis(): void
    {
        $this->createSpikeTables();

        $report = $this->coverage()->probe();

        $this->assertFalse($report->complete());
        $this->assertCount(2, $report->incomplete());
        $this->assertNull($report->table('migrations'), 'excluded tables are not probed');

        $posts = $report->table('posts');
        $this->assertFalse($posts->rlsEnabled);
        $this->assertFalse($posts->rlsForced);
        $this->assertFalse($posts->policyPresent);
        $this->assertFalse($posts->policyCurrent);
        $this->assertFalse($posts->columnPresentWithDefault);
        $this->assertSame(['posts_slug_unique'], $posts->uncoveredUniqueIndexes);
        $this->assertFalse($posts->uniqueIndexesCovered());
    }

    public function test_a_prepared_schema_is_complete(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $report = $this->coverage()->probe();

        $this->assertTrue($report->complete(), (string) $report);
        $this->assertSame([], $report->incomplete());
        $this->assertStringContainsString('posts: covered', (string) $report);
        $this->assertStringStartsWith('schema rls_test: 2 table(s), 0 incomplete', (string) $report);
    }

    public function test_each_break_is_reported_by_name(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $owner = $this->owner();

        $owner->unprepared('ALTER TABLE posts DISABLE ROW LEVEL SECURITY');
        $this->assertSame(['row level security not enabled'], $this->coverage()->probe()->table('posts')->problems(false));
        $owner->unprepared('ALTER TABLE posts ENABLE ROW LEVEL SECURITY');

        $owner->unprepared('ALTER TABLE posts FORCE ROW LEVEL SECURITY');
        $forced = $this->coverage()->probe();
        $this->assertSame([], $forced->table('posts')->problems(false), 'forced beyond config is safer, not a problem');
        $this->assertTrue($forced->table('posts')->forcedBeyondConfig(false));
        $this->assertStringContainsString('FORCEd although force is off', (string) $forced);
        $this->assertSame([], $this->coverage(force: true)->probe()->table('posts')->problems(true));
        $owner->unprepared('ALTER TABLE posts NO FORCE ROW LEVEL SECURITY');
        $this->assertSame(['row level security not forced'], $this->coverage(force: true)->probe()->table('posts')->problems(true));

        $current = Policy::name('posts', 'tenant_id', 'app.tenant_id');
        $owner->unprepared(sprintf('DROP POLICY "%s" ON posts', $current));
        $this->assertSame(['policy absent'], $this->coverage()->probe()->table('posts')->problems(false));
        $owner->unprepared('CREATE POLICY posts_rls_policy_000000 ON posts USING (true)');
        $this->assertSame(['policy present but outdated (hash differs)'], $this->coverage()->probe()->table('posts')->problems(false));
        $owner->unprepared('DROP POLICY posts_rls_policy_000000 ON posts');
        $owner->unprepared(sprintf('CREATE POLICY "%s" ON posts %s', $current, Policy::body('tenant_id', 'app.tenant_id')));

        $owner->unprepared('ALTER TABLE posts ALTER COLUMN tenant_id DROP DEFAULT');
        $this->assertSame(['column absent, nullable, or not defaulted from the setting'], $this->coverage()->probe()->table('posts')->problems(false));
        $owner->unprepared("ALTER TABLE posts ALTER COLUMN tenant_id SET DEFAULT current_setting('app.tenant_id')");

        $owner->unprepared('CREATE UNIQUE INDEX comments_body_unique ON comments (body)');
        $comments = $this->coverage()->probe()->table('comments');
        $this->assertSame(['comments_body_unique'], $comments->uncoveredUniqueIndexes);
        $this->assertSame(['unique index(es) lacking the column: comments_body_unique'], $comments->problems(false));

        $this->assertFalse($this->coverage()->probe()->complete());
    }

    public function test_a_foreign_key_backed_unique_index_is_noted_but_does_not_block_completeness(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE authors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL UNIQUE);
            CREATE TABLE books (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), author_email text NOT NULL REFERENCES authors(email));
            SQL);
        $this->preparer()->prepare();

        $report = $this->coverage()->probe();

        $this->assertTrue($report->complete(), (string) $report);
        $this->assertSame(['authors_email_key'], $report->table('authors')->foreignKeyBackedUniqueIndexes);
        $this->assertSame([], $report->table('authors')->uncoveredUniqueIndexes);
        $this->assertStringContainsString('note: unique index authors_email_key lacks the column but backs a foreign key', (string) $report);
    }
}
