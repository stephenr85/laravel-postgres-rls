<?php

namespace Rushing\PostgresRls\Tests;

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Rushing\PostgresRls\Query\ScopedPostgresSchemaGrammar;
use Rushing\PostgresRls\RowLevelSecurity\Catalog;

/**
 * review finding (ticket 11): once `users_pkey` is `(tenant_id, id)`, a later migration's
 * `foreignId('user_id')->constrained()` has no unique `(id)` to reference. A migration connection that
 * carries the pool's session setting writes it scoped instead.
 */
class ScopedMigrationForeignKeysTest extends TestCase
{
    protected function tearDown(): void
    {
        DB::purge('owner_scoped');

        parent::tearDown();
    }

    private function ownerScoped(): \Illuminate\Database\Connection
    {
        config(['database.connections.owner_scoped' => ['session_settings' => ['app.tenant_id' => 'pool:x']] + config('database.connections.owner')]);

        return DB::connection('owner_scoped');
    }

    public function test_a_later_migration_adds_a_scoped_foreign_key_into_a_prepared_table(): void
    {
        $this->owner()->unprepared('CREATE TABLE users (id uuid PRIMARY KEY, email text NOT NULL)');
        $this->preparer()->prepare();

        // The plain owner connection cannot: nothing unique covers (id) any more.
        try {
            Schema::connection('owner')->create('drafts', function (Blueprint $table) {
                $table->uuid('id')->primary();
                $table->foreignUuid('user_id')->constrained();
            });
            $this->fail('an unscoped foreign key into a prepared table must fail');
        } catch (QueryException $e) {
            $this->assertStringContainsString('no unique constraint matching given keys', $e->getMessage());
        }

        $scoped = $this->ownerScoped();
        $this->assertInstanceOf(ScopedPostgresSchemaGrammar::class, $scoped->getSchemaGrammar());

        Schema::connection('owner_scoped')->create('posts', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('user_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignUuid('editor_id')->nullable()->constrained('users')->cascadeOnDelete();
        });

        $definitions = collect($this->owner()->select("select conname, pg_get_constraintdef(oid) as def from pg_constraint where contype = 'f' and conrelid = 'posts'::regclass"))->pluck('def', 'conname');
        $this->assertSame('FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE SET NULL (user_id)', $definitions['posts_user_id_foreign']);
        $this->assertSame('FOREIGN KEY (tenant_id, editor_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE', $definitions['posts_editor_id_foreign']);

        // The preparer finishes the table and has nothing left to do on its keys.
        $this->preparer()->prepare();
        $this->assertSame(['tenant_id', 'id'], (new Catalog($this->owner()))->primaryKey(self::SCHEMA, 'posts')['columns']);
        $this->assertTrue($this->preparer()->prepare()->isNoop());
        $this->assertTrue($this->coverage()->probe()->complete());
    }

    public function test_a_foreign_key_into_an_unprepared_table_compiles_unchanged(): void
    {
        $this->ownerScoped();

        Schema::connection('owner_scoped')->create('countries', fn (Blueprint $table) => $table->string('code')->primary());
        Schema::connection('owner_scoped')->create('addresses', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('country_code');
            $table->foreign('country_code')->references('code')->on('countries');
        });

        $this->assertSame('FOREIGN KEY (country_code) REFERENCES countries(code)', $this->owner()->selectOne("select pg_get_constraintdef(oid) as def from pg_constraint where conname = 'addresses_country_code_foreign'")->def);
    }

    public function test_a_connection_with_only_built_in_settings_keeps_its_grammars(): void
    {
        config(['database.connections.owner_timeout' => ['session_settings' => ['statement_timeout' => '5s']] + config('database.connections.owner')]);

        $this->assertNotInstanceOf(ScopedPostgresSchemaGrammar::class, DB::connection('owner_timeout')->getSchemaGrammar());
        $this->assertStringNotContainsString('Scoped', get_class(DB::connection('owner_timeout')->getQueryGrammar()));

        DB::purge('owner_timeout');
    }
}
