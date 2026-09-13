<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Support\Facades\DB;
use Rushing\PostgresRls\Query\ScopedPostgresGrammar;

class ScopeConflictTargetsTest extends TestCase
{
    public function test_a_scoped_upsert_on_a_widened_index_lands_under_its_own_key(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE counters (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), target text NOT NULL, window_start text NOT NULL, count int NOT NULL);
            CREATE UNIQUE INDEX counters_target_window_unique ON counters (target, window_start);
            SQL);
        $this->preparer()->prepare();
        $this->grantScopedRole();

        $a = $this->scoped('a');
        $b = $this->scoped('b');
        $this->assertInstanceOf(ScopedPostgresGrammar::class, $a->getQueryGrammar());

        foreach ([$a, $a, $b] as $connection) {
            $connection->table('counters')->upsert(
                [['target' => 't', 'window_start' => 'w', 'count' => 1]],
                ['target', 'window_start'],
                ['count' => DB::raw('counters.count + 1')],
            );
        }

        $this->assertSame(2, $a->table('counters')->value('count'));
        $this->assertSame(1, $b->table('counters')->value('count'));
        $this->assertStringContainsString('on conflict ("tenant_id", "target", "window_start")', $this->compiled($a, ['target', 'window_start']));
    }

    public function test_a_target_that_still_matches_an_index_is_left_as_written(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE settings (name text PRIMARY KEY, value text);
            CREATE TABLE plain (code text PRIMARY KEY, value text);
            SQL);
        $this->preparer(exclude: ['migrations', 'plain'])->prepare();
        $this->grantScopedRole();
        $this->owner()->unprepared('GRANT SELECT, INSERT, UPDATE ON plain TO '.self::SCOPED_ROLE);

        $a = $this->scoped('a');

        // widened primary key: scoped
        $this->assertStringContainsString('on conflict ("tenant_id", "name")', $this->compiled($a, ['name'], 'settings'));
        // a table the preparer left alone: unchanged
        $this->assertStringContainsString('on conflict ("code")', $this->compiled($a, ['code'], 'plain'));
        // already names the column: unchanged
        $this->assertStringContainsString('on conflict ("tenant_id", "name")', $this->compiled($a, ['tenant_id', 'name'], 'settings'));

        $a->table('plain')->upsert([['code' => 'x', 'value' => '1']], ['code'], ['value']);
        $a->table('plain')->upsert([['code' => 'x', 'value' => '2']], ['code'], ['value']);
        $this->assertSame('2', $this->owner()->table('plain')->value('value'));
    }

    public function test_a_partial_unique_index_is_scoped_and_a_pretended_compile_is_not_cached(): void
    {
        $this->owner()->unprepared(<<<'SQL'
            CREATE TABLE accounts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL, deleted_at timestamp);
            CREATE UNIQUE INDEX accounts_email_live ON accounts (email) WHERE deleted_at IS NULL;
            SQL);
        $this->preparer()->prepare();
        $this->grantScopedRole();

        $a = $this->scoped('a');
        $a->pretend(fn () => $this->compiled($a, ['email'], 'accounts'));

        $this->assertStringContainsString('on conflict ("tenant_id", "email")', $this->compiled($a, ['email'], 'accounts'));
    }

    public function test_an_unscoped_connection_keeps_its_grammar(): void
    {
        $this->assertNotInstanceOf(ScopedPostgresGrammar::class, $this->owner()->getQueryGrammar());
        $this->assertNotInstanceOf(ScopedPostgresGrammar::class, $this->unset()->getQueryGrammar());
    }

    /**
     * @param  list<string>  $uniqueBy
     */
    private function compiled(\Illuminate\Database\Connection $connection, array $uniqueBy, string $table = 'counters'): string
    {
        $query = $connection->table($table);

        return $query->getGrammar()->compileUpsert($query, [array_fill_keys($uniqueBy, 'x')], $uniqueBy, ['value']);
    }
}
