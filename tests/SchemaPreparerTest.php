<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Database\QueryException;
use InvalidArgumentException;
use Rushing\PostgresRls\RowLevelSecurity\Catalog;
use Rushing\PostgresRls\RowLevelSecurity\Policy;
use Rushing\PostgresRls\RowLevelSecurity\SchemaPreparer;

class SchemaPreparerTest extends TestCase
{
    public function test_two_keys_on_two_tables_see_only_their_own_rows(): void
    {
        $this->createSpikeTables();
        $report = $this->preparer()->prepare();
        $this->grantScopedRole();

        $this->assertGreaterThan(0, $report->appliedCount());

        $a = $this->scoped('a');
        $b = $this->scoped('b');

        $a->table('posts')->insert(['slug' => 'hello']);
        $b->table('posts')->insert(['slug' => 'hello']);
        $a->table('posts')->insert(['slug' => 'second']);

        // the defaulted insert lands with the key, and application code never named the column
        $this->assertSame('a', $a->table('posts')->where('slug', 'hello')->value('tenant_id'));

        $this->assertSame(2, $a->table('posts')->count());
        $this->assertSame(1, $b->table('posts')->count());
        $this->assertTrue($b->table('posts')->where('slug', 'hello')->exists(), 'the same slug is allowed under two keys');

        // second table, referencing the first inside the same key
        $postId = $a->table('posts')->where('slug', 'hello')->value('id');
        $a->table('comments')->insert(['post_id' => $postId, 'body' => 'x']);
        $this->assertSame(1, $a->table('comments')->count());
        $this->assertSame(0, $b->table('comments')->count());

        // an unbound frame is fail-closed: reads zero, cannot insert
        $this->assertSame(0, $this->unset()->table('posts')->count());
        try {
            $this->unset()->table('posts')->insert(['slug' => 'leak']);
            $this->fail('an insert with no setting bound must throw');
        } catch (QueryException $e) {
            $this->assertStringContainsString('unrecognized configuration parameter', $e->getMessage());
        }

        // WITH CHECK refuses a row bearing another key
        try {
            $b->table('posts')->insert(['slug' => 'evil', 'tenant_id' => 'a']);
            $this->fail('WITH CHECK must refuse a cross-key insert');
        } catch (QueryException $e) {
            $this->assertStringContainsString('row-level security policy', $e->getMessage());
        }

        // USING scopes writes: B's update and delete touch only B's row
        $this->assertSame(1, $b->table('posts')->where('slug', 'hello')->update(['slug' => 'changed']));
        $this->assertTrue($a->table('posts')->where('slug', 'hello')->exists());
        $this->assertSame(1, $b->table('posts')->whereIn('slug', ['hello', 'second', 'changed'])->delete());
        $this->assertSame(2, $a->table('posts')->count());

        // the owner, with force off, is not subject to the policy
        $this->assertSame(2, $this->owner()->table('posts')->count());
        $this->assertSame(1, $this->owner()->table('comments')->count());
    }

    public function test_a_second_run_applies_nothing(): void
    {
        $this->createSpikeTables();

        $first = $this->preparer()->prepare();
        $second = $this->preparer()->prepare();

        $this->assertFalse($first->isNoop());
        $this->assertTrue($second->isNoop(), (string) $second);
        $this->assertSame(0, $second->appliedCount());
        $this->assertSame(['comments', 'posts'], $second->tables());
        $this->assertStringContainsString('posts: up to date', (string) $second);
        $this->assertTrue($this->coverage()->probe()->complete());
    }

    public function test_the_report_lists_the_statements_it_applied(): void
    {
        $this->createSpikeTables();

        $report = $this->preparer()->prepare();
        $statements = $report->appliedStatements()['posts'];

        $this->assertContains('ALTER TABLE "rls_test"."posts" ADD COLUMN tenant_id text DEFAULT current_setting(\'app.tenant_id\', true)', $statements);
        $this->assertContains('ALTER TABLE "rls_test"."posts" ALTER COLUMN tenant_id SET DEFAULT current_setting(\'app.tenant_id\')', $statements);
        $this->assertContains('ALTER TABLE "rls_test"."posts" ALTER COLUMN tenant_id SET NOT NULL', $statements);
        $this->assertContains('CREATE INDEX "posts_tenant_id_idx" ON "rls_test"."posts" (tenant_id)', $statements);
        $this->assertContains('ALTER TABLE "rls_test"."posts" ENABLE ROW LEVEL SECURITY', $statements);
        $this->assertContains(
            sprintf('CREATE POLICY "%s" ON "rls_test"."posts" USING (tenant_id = current_setting(\'app.tenant_id\', true)) WITH CHECK (tenant_id = current_setting(\'app.tenant_id\', true))', Policy::name('posts', 'tenant_id', 'app.tenant_id')),
            $statements,
        );
        $this->assertNotContains('ALTER TABLE "rls_test"."posts" FORCE ROW LEVEL SECURITY', $statements);
        $this->assertArrayNotHasKey('migrations', $report->appliedStatements());
        $this->assertStringStartsWith('schema rls_test: 2 table(s) inspected', (string) $report);
    }

    public function test_unique_indexes_gain_the_column_under_the_same_name(): void
    {
        $this->createSpikeTables();
        $this->owner()->unprepared('CREATE TABLE tags (id serial PRIMARY KEY, name text NOT NULL, CONSTRAINT tags_name_key UNIQUE (name))');

        $this->preparer()->prepare();

        $catalog = new Catalog($this->owner());

        $posts = $catalog->uniqueIndexes(self::SCHEMA, 'posts');
        $this->assertCount(1, $posts);
        $this->assertSame('posts_slug_unique', $posts[0]->name);
        $this->assertSame(['tenant_id', 'slug'], $posts[0]->keyColumns);
        $this->assertFalse($posts[0]->backsConstraint());

        $tags = $catalog->uniqueIndexes(self::SCHEMA, 'tags');
        $this->assertCount(1, $tags);
        $this->assertSame('tags_name_key', $tags[0]->name);
        $this->assertSame(['tenant_id', 'name'], $tags[0]->keyColumns);
        $this->assertTrue($tags[0]->backsConstraint(), 'a UNIQUE constraint is rewritten as a constraint, not demoted to a bare index');
        $this->assertSame('UNIQUE (tenant_id, name)', $tags[0]->constraintDefinition);

        // and it behaves: the same name is allowed under two keys, refused within one
        $this->grantScopedRole();
        $this->scoped('a')->table('tags')->insert(['name' => 'x']);
        $this->scoped('b')->table('tags')->insert(['name' => 'x']);
        $this->expectException(QueryException::class);
        $this->scoped('a')->table('tags')->insert(['name' => 'x']);
    }

    public function test_primary_keys_and_the_foreign_keys_between_prepared_tables_lead_with_the_column(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE authors (id uuid PRIMARY KEY, email text NOT NULL UNIQUE);
            CREATE TABLE books (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                author_id uuid NOT NULL REFERENCES authors(id) ON DELETE CASCADE,
                author_email text REFERENCES authors(email) ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TABLE reviews (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                book_id uuid REFERENCES books(id) ON DELETE SET NULL
            );
            SQL);

        $this->preparer()->prepare();
        $catalog = new Catalog($this->owner());

        $this->assertSame(['tenant_id', 'id'], $catalog->primaryKey(self::SCHEMA, 'authors')['columns']);
        $this->assertSame(['tenant_id', 'email'], $catalog->uniqueIndexes(self::SCHEMA, 'authors')[0]->keyColumns, 'a unique index a foreign key references follows the key too');

        $definitions = collect($this->owner()->select("select conname, pg_get_constraintdef(oid) as def from pg_constraint where contype = 'f' and connamespace = 'rls_test'::regnamespace"))->pluck('def', 'conname');
        $this->assertSame('FOREIGN KEY (tenant_id, author_id) REFERENCES authors(tenant_id, id) ON DELETE CASCADE', $definitions['books_author_id_fkey']);
        $this->assertSame('FOREIGN KEY (tenant_id, author_email) REFERENCES authors(tenant_id, email) ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED', $definitions['books_author_email_fkey']);
        $this->assertSame('FOREIGN KEY (tenant_id, book_id) REFERENCES books(tenant_id, id) ON DELETE SET NULL (book_id)', $definitions['reviews_book_id_fkey']);

        $this->grantScopedRole();
        $a = $this->scoped('a');
        $b = $this->scoped('b');
        $shared = '01a09827-0000-4000-8000-000000000001';

        // the same id under two keys: a central row copied into two tenants
        $a->table('authors')->insert(['id' => $shared, 'email' => 'same@example.com']);
        $b->table('authors')->insert(['id' => $shared, 'email' => 'same@example.com']);
        $bookId = $a->table('books')->insertGetId(['author_id' => $shared, 'author_email' => 'same@example.com'], 'id');
        $a->table('reviews')->insert(['book_id' => $bookId]);

        // a reference to another key's row is refused outright, not merely hidden
        $b->table('authors')->where('id', $shared)->delete();
        try {
            $b->table('books')->insert(['author_id' => $shared]);
            $this->fail('a foreign key must not resolve to another key\'s row');
        } catch (QueryException $e) {
            $this->assertStringContainsString('violates foreign key constraint "books_author_id_fkey"', $e->getMessage());
        }

        // ON DELETE SET NULL clears only its own column: the review keeps its key
        $a->table('books')->where('id', $bookId)->delete();
        $review = $this->owner()->table('reviews')->first();
        $this->assertNull($review->book_id);
        $this->assertSame('a', $review->tenant_id);

        $second = $this->preparer()->prepare();
        $this->assertTrue($second->isNoop(), (string) $second);
        $this->assertTrue($this->coverage()->probe()->complete());
    }

    public function test_a_foreign_key_into_an_unprepared_table_is_left_alone(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE countries (code text PRIMARY KEY);
            CREATE TABLE addresses (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), country_code text NOT NULL REFERENCES countries(code));
            SQL);

        $report = $this->preparer(exclude: ['migrations', 'countries'])->prepare();

        $this->assertSame(['code'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'countries')['columns']);
        $this->assertSame(['tenant_id', 'id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'addresses')['columns']);
        $this->assertSame('FOREIGN KEY (country_code) REFERENCES countries(code)', $this->owner()->selectOne("select pg_get_constraintdef(oid) as def from pg_constraint where conname = 'addresses_country_code_fkey'")->def);
        $this->assertSame([], $report->skippedItems(), 'a central reference is not a skip');
    }

    public function test_a_key_referenced_from_an_unprepared_table_stays_unique_and_is_reported(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE plans (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
            CREATE TABLE plan_audit (id serial PRIMARY KEY, plan_id uuid REFERENCES plans(id));
            CREATE TABLE subscriptions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), plan_id uuid REFERENCES plans(id));
            SQL);

        $report = $this->preparer(exclude: ['migrations', 'plan_audit'])->prepare();
        $catalog = new Catalog($this->owner());

        $this->assertSame(['id'], $catalog->primaryKey(self::SCHEMA, 'plans')['columns']);
        $skipped = collect($report->skippedItems()['plans'] ?? [])->pluck('reason', 'subject');
        $this->assertStringContainsString('referenced by foreign key plan_audit_plan_id_fkey on rls_test.plan_audit, which is outside the prepared tables', $skipped['primary key plans_pkey']);
        $this->assertStringContainsString('the key it references, plans_pkey, cannot be', collect($report->skippedItems()['subscriptions'])->pluck('reason', 'subject')['foreign key subscriptions_plan_id_fkey']);

        $this->assertTrue($this->preparer(exclude: ['migrations', 'plan_audit'])->prepare()->isNoop());
    }

    public function test_a_foreign_key_with_the_column_on_one_side_only_is_left_as_written(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE teams (id text PRIMARY KEY);
            CREATE TABLE members (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text REFERENCES teams(id));
            SQL);

        $report = $this->preparer()->prepare();

        $this->assertSame(['id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'teams')['columns']);
        $this->assertStringContainsString('carries tenant_id on one side only', collect($report->skippedItems()['teams'])->pluck('reason', 'subject')['primary key teams_pkey']);
        $this->assertTrue($this->preparer()->prepare()->isNoop());
        $this->assertTrue($this->coverage()->probe()->complete(), (string) $this->coverage()->probe());
    }

    public function test_a_primary_key_a_view_depends_on_is_left_unique_and_reported(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE authors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
            CREATE TABLE books (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), author_id uuid NOT NULL);
            CREATE VIEW author_book_counts AS SELECT a.id, a.name, count(b.id) FROM authors a LEFT JOIN books b ON b.author_id = a.id GROUP BY a.id;
            SQL);

        $report = $this->preparer()->prepare();

        $this->assertSame(['id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'authors')['columns']);
        $this->assertStringContainsString('view author_book_counts depends on it', collect($report->skippedItems()['authors'])->pluck('reason', 'subject')['primary key authors_pkey']);
        $this->assertSame(['tenant_id', 'id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'books')['columns']);
        $this->assertTrue($this->coverage()->probe()->complete());
    }

    public function test_an_existing_cross_key_reference_refuses_the_rewrite_and_applies_nothing(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE posts (id uuid PRIMARY KEY, tenant_id text NOT NULL DEFAULT current_setting('app.tenant_id'));
            CREATE TABLE comments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL DEFAULT current_setting('app.tenant_id'), post_id uuid REFERENCES posts(id));
            INSERT INTO posts (id, tenant_id) VALUES ('01a09827-0000-4000-8000-000000000002', 'a');
            INSERT INTO comments (tenant_id, post_id) VALUES ('b', '01a09827-0000-4000-8000-000000000002');
            SQL);

        try {
            $this->preparer()->prepare();
            $this->fail('re-adding the scoped foreign key over a cross-key reference must fail');
        } catch (QueryException $e) {
            $this->assertStringContainsString('comments_post_id_fkey', $e->getMessage());
        }

        $this->assertSame(['id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'posts')['columns'], 'one transaction: nothing applied');
        $this->assertSame([], $this->owner()->select("select 1 from pg_policies where schemaname = 'rls_test'"));
    }

    public function test_an_outdated_policy_is_replaced_when_the_body_changes(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $before = Policy::name('posts', 'tenant_id', 'app.tenant_id');
        $after = Policy::name('posts', 'tenant_id', 'app.other_key');
        $this->assertNotSame($before, $after);

        $report = $this->preparer(setting: 'app.other_key')->prepare();

        $applied = $report->appliedStatements()['posts'];
        $this->assertContains(sprintf('DROP POLICY "%s" ON "rls_test"."posts"', $before), $applied);
        $this->assertStringContainsString(sprintf('CREATE POLICY "%s"', $after), implode("\n", $applied));
        $this->assertSame([$after], (new Catalog($this->owner()))->policies(self::SCHEMA, 'posts'));
    }

    public function test_a_policy_with_our_prefix_and_a_stale_hash_is_replaced(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();

        $expected = Policy::name('posts', 'tenant_id', 'app.tenant_id');
        $this->owner()->unprepared(sprintf('DROP POLICY "%s" ON posts', $expected));
        $this->owner()->unprepared('CREATE POLICY posts_rls_policy_000000 ON posts USING (true)');

        $report = $this->preparer()->prepare();

        $this->assertContains('DROP POLICY "posts_rls_policy_000000" ON "rls_test"."posts"', $report->appliedStatements()['posts']);
        $this->assertSame([$expected], (new Catalog($this->owner()))->policies(self::SCHEMA, 'posts'));
    }

    public function test_a_foreign_policy_on_the_table_is_left_alone(): void
    {
        $this->createSpikeTables();
        $this->owner()->unprepared('CREATE POLICY posts_house_rule ON posts USING (true)');

        $this->preparer()->prepare();

        $this->assertContains('posts_house_rule', (new Catalog($this->owner()))->policies(self::SCHEMA, 'posts'));
    }

    public function test_a_zombie_policy_on_an_excluded_table_is_dropped(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $this->owner()->unprepared('CREATE POLICY migrations_rls_policy_abcdef ON migrations USING (true)');

        $report = $this->preparer()->prepare();

        $this->assertSame(
            ['DROP POLICY "migrations_rls_policy_abcdef" ON "rls_test"."migrations"'],
            $report->appliedStatements()['migrations'],
        );
        $this->assertSame([], (new Catalog($this->owner()))->policies(self::SCHEMA, 'migrations'));
        $this->assertFalse((new Catalog($this->owner()))->rowSecurity(self::SCHEMA, 'migrations')['enabled'], 'an excluded table is otherwise untouched');
    }

    public function test_drop_policies_opens_a_window_in_which_a_scoped_connection_reads_zero(): void
    {
        $this->createSpikeTables();
        $this->preparer()->prepare();
        $this->grantScopedRole();
        $this->scoped('a')->table('posts')->insert(['slug' => 'hello']);

        $window = $this->preparer()->dropPolicies();

        $this->assertSame(2, $window->appliedCount());
        $this->assertSame(0, $this->scoped('a')->table('posts')->count(), 'RLS stays enabled with no policy: nothing is visible');
        $this->assertSame(1, $this->owner()->table('posts')->count(), 'the owner still reads through the window');
        $this->assertTrue((new Catalog($this->owner()))->rowSecurity(self::SCHEMA, 'posts')['enabled']);

        try {
            $this->scoped('a')->table('posts')->insert(['slug' => 'during']);
            $this->fail('an insert during the window must be refused');
        } catch (QueryException $e) {
            $this->assertStringContainsString('row-level security policy', $e->getMessage());
        }

        $restored = $this->preparer()->prepare();

        $this->assertSame(2, $restored->appliedCount(), 'only the two policies come back');
        $this->assertSame(1, $this->scoped('a')->table('posts')->count());
    }

    public function test_force_makes_the_owner_subject_to_the_policy(): void
    {
        $this->createSpikeTables();
        $this->preparer(force: true)->prepare();
        $this->grantScopedRole();
        $this->scoped('a')->table('posts')->insert(['slug' => 'hello']);

        $this->assertTrue((new Catalog($this->owner()))->rowSecurity(self::SCHEMA, 'posts')['forced']);
        $this->assertSame(0, $this->owner()->table('posts')->count(), 'the owner has no setting bound, so FORCE hides every row');

        $relaxed = $this->preparer(force: false)->prepare();

        $this->assertContains('ALTER TABLE "rls_test"."posts" NO FORCE ROW LEVEL SECURITY', $relaxed->appliedStatements()['posts']);
        $this->assertSame(1, $this->owner()->table('posts')->count());
    }

    public function test_an_existing_column_is_repaired_rather_than_duplicated(): void
    {
        $this->owner()->unprepared('CREATE TABLE loose (id serial PRIMARY KEY, tenant_id text)');

        $report = $this->preparer()->prepare();

        $applied = $report->appliedStatements()['loose'];
        $this->assertContains('ALTER TABLE "rls_test"."loose" ALTER COLUMN tenant_id SET DEFAULT current_setting(\'app.tenant_id\')', $applied);
        $this->assertContains('ALTER TABLE "rls_test"."loose" ALTER COLUMN tenant_id SET NOT NULL', $applied);
        $this->assertTrue($this->coverage()->probe()->table('loose')->columnPresentWithDefault);
        $this->assertTrue($this->preparer()->prepare()->isNoop());
    }

    public function test_a_non_text_discriminator_column_is_reported_and_the_table_left_alone(): void
    {
        $this->owner()->unprepared('CREATE TABLE wrong (id serial PRIMARY KEY, tenant_id integer NOT NULL)');

        $report = $this->preparer()->prepare();

        $this->assertArrayNotHasKey('wrong', $report->appliedStatements());
        $this->assertStringContainsString('exists with type integer', $report->skippedItems()['wrong'][0]['reason']);
        $this->assertSame([], (new Catalog($this->owner()))->policies(self::SCHEMA, 'wrong'));
    }

    public function test_preparing_a_populated_table_stamps_existing_rows_with_the_bound_setting(): void
    {
        $this->owner()->unprepared("CREATE TABLE seeded (id serial PRIMARY KEY, name text NOT NULL); INSERT INTO seeded (name) VALUES ('one'), ('two')");

        try {
            $this->preparer()->prepare();
            $this->fail('preparing a populated table must throw when the setting is unbound');
        } catch (QueryException $e) {
            $this->assertStringContainsString('contains null values', $e->getMessage());
        }

        $this->assertFalse((new Catalog($this->owner()))->column(self::SCHEMA, 'seeded', 'tenant_id')['present'], 'the failed run rolled back');

        $this->owner()->statement("select set_config('app.tenant_id', 'seed', false)");
        $this->preparer()->prepare();

        $this->assertSame(['seed', 'seed'], $this->owner()->table('seeded')->orderBy('id')->pluck('tenant_id')->all());
    }

    public function test_the_setting_must_be_namespaced(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must be namespaced');

        new SchemaPreparer($this->owner(), self::SCHEMA, 'tenant_id', 'tenant_id');
    }

    public function test_the_column_must_be_a_plain_identifier(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new SchemaPreparer($this->owner(), self::SCHEMA, 'Tenant Id');
    }

    public function test_the_column_must_fit_a_postgres_identifier(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at most 63 bytes');

        new SchemaPreparer($this->owner(), self::SCHEMA, str_repeat('c', 64));
    }

    public function test_from_config_applies_overrides_over_config_over_defaults(): void
    {
        $this->createSpikeTables();

        $preparer = SchemaPreparer::fromConfig(
            $this->owner(),
            self::SCHEMA,
            ['column' => 'tenant_id', 'setting' => 'app.tenant_id', 'exclude' => ['migrations', 'comments'], 'force' => false],
            ['force' => true],
        );
        $report = $preparer->prepare();

        $this->assertSame(['posts'], $report->tables());
        $this->assertContains('ALTER TABLE "rls_test"."posts" FORCE ROW LEVEL SECURITY', $report->appliedStatements()['posts']);
    }
}
