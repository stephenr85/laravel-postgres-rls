<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;

/**
 * Makes every table in one schema row-level-secure on a discriminator column whose value the
 * database fills from a session setting. After `prepare()`, a connection that carries the
 * setting sees and writes only rows bearing its key, a connection without it sees nothing,
 * and application code never names the column.
 *
 * Per table in scope (base tables in the schema minus `exclude`), in this order:
 *
 *  1. column   — `ADD COLUMN <col> text`, `SET DEFAULT current_setting('<setting>')`,
 *                `SET NOT NULL` (three statements; see `ensureColumn()` for why not one), or
 *                repair the DEFAULT / NOT NULL of an existing text column.
 *  2. index    — a btree index leading with the column, `<table>_<col>_idx`.
 *  3. security — `ENABLE ROW LEVEL SECURITY`; `FORCE` or `NO FORCE` to match `$force`.
 *  4. policy   — `CREATE POLICY <table>_rls_policy_<hash>` with the {@see Policy} body; any
 *                other policy carrying this package's suffix on the table is outdated and is
 *                dropped first.
 *  5. uniques  — every unique index whose key columns lack the column is dropped and
 *                re-created under the same name with the column prepended (through
 *                `DROP/ADD CONSTRAINT` when a UNIQUE constraint owns it). Primary keys are
 *                skipped silently; an index a FOREIGN KEY references is skipped and REPORTED,
 *                because Postgres will not drop it and the referencing table would need the
 *                key in its own FK columns to stay valid.
 *
 * Then policies with this package's suffix on tables outside scope are dropped as zombies.
 * Policy naming, hashing and zombie removal follow stancl/tenancy v4's
 * `CreateUserWithRLSPolicies` (prior art, attributed in {@see Policy}).
 *
 * The whole run is one transaction — Postgres DDL is transactional — so a failure applies nothing.
 *
 * Populated tables: Postgres evaluates an ADD COLUMN default ONCE at ALTER time and stamps every
 * existing row with it (`current_setting` is STABLE, so it takes the fast path and rewrites
 * nothing). So when a table already holds rows the setting must be bound on the PREPARING
 * connection — every existing row then lands under that key — and when it is not, the run
 * fails at `SET NOT NULL` with `column "<col>" ... contains null values` and the transaction
 * rolls back. An empty table needs no setting.
 *
 * Privileges: run this as the table owner (the role that runs migrations). With `$force` off the
 * owner is not subject to the policy and can read every key; with it on, the owner needs the
 * setting bound too, or `BYPASSRLS`, which managed Postgres (Cloud SQL, RDS) cannot grant.
 *
 * Migration window: {@see dropPolicies()} removes every policy so a migration can run without
 * a policy referencing a column it is about to change; RLS stays ENABLED, so a non-owner
 * connection reads ZERO rows until `prepare()` runs again — fail-closed, never open.
 */
final class SchemaPreparer
{
    private readonly Catalog $catalog;

    /** @var list<string> */
    private readonly array $exclude;

    /**
     * @param  list<string>  $exclude  tables in the schema to leave untouched
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly string $schema,
        private readonly string $column = 'tenant_id',
        private readonly string $setting = 'app.tenant_id',
        array $exclude = ['migrations'],
        private readonly bool $force = false,
    ) {
        Identifier::assertSchema($schema);
        Identifier::assertColumn($column);
        Identifier::assertSetting($setting);

        $this->exclude = array_values($exclude);
        $this->catalog = new Catalog($connection);
    }

    /**
     * Build from the package config (`config/postgres-rls.php`), with per-call overrides.
     *
     * @param  array{column?: string, setting?: string, exclude?: list<string>, force?: bool}  $config
     * @param  array{column?: ?string, setting?: ?string, exclude?: ?list<string>, force?: ?bool}  $overrides
     */
    public static function fromConfig(Connection $connection, string $schema, array $config, array $overrides = []): self
    {
        $pick = fn (string $key, mixed $default) => ($overrides[$key] ?? null) ?? ($config[$key] ?? $default);

        return new self(
            $connection,
            $schema,
            (string) $pick('column', 'tenant_id'),
            (string) $pick('setting', 'app.tenant_id'),
            (array) $pick('exclude', ['migrations']),
            (bool) $pick('force', false),
        );
    }

    public function prepare(): PreparationReport
    {
        $report = new PreparationReport($this->schema);

        $this->connection->transaction(function () use ($report) {
            $all = $this->catalog->tables($this->schema);
            $inScope = array_values(array_diff($all, $this->exclude));

            foreach ($inScope as $table) {
                $report->inspected($table);

                if (! $this->ensureColumn($table, $report)) {
                    continue;
                }

                $this->ensureIndex($table, $report);
                $this->ensureRowSecurity($table, $report);
                $this->ensurePolicy($table, $report);
                $this->rewriteUniqueIndexes($table, $report);
            }

            $this->dropZombiePolicies($inScope, $report);
        });

        return $report;
    }

    /**
     * Drop every policy this package minted in the schema. RLS stays enabled on every table, so
     * until `prepare()` runs again a non-owner connection reads zero rows and cannot insert.
     */
    public function dropPolicies(): PreparationReport
    {
        $report = new PreparationReport($this->schema);

        $this->connection->transaction(function () use ($report) {
            foreach ($this->catalog->ourPoliciesBySchema($this->schema) as $table => $policies) {
                foreach ($policies as $policy) {
                    $this->apply($report, $table, sprintf(
                        'DROP POLICY %s ON %s',
                        Identifier::quote($policy),
                        Identifier::qualified($this->schema, $table),
                    ));
                }
            }
        });

        return $report;
    }

    /** Returns false when the table cannot be prepared (column present with a non-text type). */
    private function ensureColumn(string $table, PreparationReport $report): bool
    {
        $info = $this->catalog->column($this->schema, $table, $this->column);
        $relation = Identifier::qualified($this->schema, $table);
        $default = sprintf('current_setting(%s)', Identifier::literal($this->setting));

        if (! $info['present']) {
            // Three steps, not one: Postgres evaluates an ADD COLUMN default ONCE at ALTER time
            // to stamp existing rows (the fast-default path) — even on an empty table — and the
            // strict `current_setting(name)` throws when the setting is unbound. The lenient
            // two-argument form yields NULL instead, so the column always lands; SET DEFAULT then
            // installs the strict form for future inserts without evaluating it; and SET NOT NULL
            // is what fails, with "contains null values", when a populated table was prepared
            // with no setting bound.
            $this->apply($report, $table, sprintf(
                'ALTER TABLE %s ADD COLUMN %s text DEFAULT current_setting(%s, true)',
                $relation,
                $this->column,
                Identifier::literal($this->setting),
            ));
            $this->apply($report, $table, sprintf('ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s', $relation, $this->column, $default));
            $this->apply($report, $table, sprintf('ALTER TABLE %s ALTER COLUMN %s SET NOT NULL', $relation, $this->column));

            return true;
        }

        if (! in_array($info['type'], ['text', 'character varying', 'character'], true)) {
            $report->skipped($table, 'column '.$this->column, sprintf(
                'exists with type %s; the discriminator must be a text column, so this table was left untouched',
                $info['type'],
            ));

            return false;
        }

        if (! $this->catalog->isSettingDefault($info['default'], $this->setting)) {
            $this->apply($report, $table, sprintf(
                'ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s',
                $relation,
                $this->column,
                $default,
            ));
        }

        if ($info['nullable']) {
            $this->apply($report, $table, sprintf(
                'ALTER TABLE %s ALTER COLUMN %s SET NOT NULL',
                $relation,
                $this->column,
            ));
        }

        return true;
    }

    private function ensureIndex(string $table, PreparationReport $report): void
    {
        if ($this->catalog->hasLeadingIndex($this->schema, $table, $this->column)) {
            return;
        }

        $this->apply($report, $table, sprintf(
            'CREATE INDEX %s ON %s (%s)',
            Identifier::quote(substr($table.'_'.$this->column, 0, 59).'_idx'),
            Identifier::qualified($this->schema, $table),
            $this->column,
        ));
    }

    private function ensureRowSecurity(string $table, PreparationReport $report): void
    {
        $state = $this->catalog->rowSecurity($this->schema, $table);
        $relation = Identifier::qualified($this->schema, $table);

        if (! $state['enabled']) {
            $this->apply($report, $table, sprintf('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', $relation));
        }

        if ($state['forced'] !== $this->force) {
            $this->apply($report, $table, sprintf(
                'ALTER TABLE %s %s ROW LEVEL SECURITY',
                $relation,
                $this->force ? 'FORCE' : 'NO FORCE',
            ));
        }
    }

    private function ensurePolicy(string $table, PreparationReport $report): void
    {
        $expected = Policy::name($table, $this->column, $this->setting);
        $existing = $this->catalog->policies($this->schema, $table);
        $relation = Identifier::qualified($this->schema, $table);

        foreach ($existing as $policy) {
            if ($policy !== $expected && Policy::isOurs($policy)) {
                $this->apply($report, $table, sprintf('DROP POLICY %s ON %s', Identifier::quote($policy), $relation));
            }
        }

        if (! in_array($expected, $existing, true)) {
            $this->apply($report, $table, sprintf(
                'CREATE POLICY %s ON %s %s',
                Identifier::quote($expected),
                $relation,
                Policy::body($this->column, $this->setting),
            ));
        }
    }

    private function rewriteUniqueIndexes(string $table, PreparationReport $report): void
    {
        $relation = Identifier::qualified($this->schema, $table);

        foreach ($this->catalog->uniqueIndexes($this->schema, $table) as $index) {
            if ($index->includesColumn($this->column)) {
                continue;
            }

            if ($index->backsForeignKey()) {
                $report->skipped($table, 'unique index '.$index->name, sprintf(
                    'referenced by foreign key %s; not rewritten, so it stays unique across keys',
                    implode(', ', $index->referencingForeignKeys),
                ));

                continue;
            }

            if ($index->backsConstraint()) {
                $rewritten = preg_replace('/\(/', '('.$this->column.', ', (string) $index->constraintDefinition, 1);

                $this->apply($report, $table, sprintf('ALTER TABLE %s DROP CONSTRAINT %s', $relation, Identifier::quote((string) $index->constraintName)));
                $this->apply($report, $table, sprintf('ALTER TABLE %s ADD CONSTRAINT %s %s', $relation, Identifier::quote((string) $index->constraintName), $rewritten));

                continue;
            }

            $rewritten = preg_replace('/ USING (\S+) \(/', ' USING $1 ('.$this->column.', ', $index->indexDefinition, 1);

            if ($rewritten === $index->indexDefinition) {
                $report->skipped($table, 'unique index '.$index->name, 'definition not understood; not rewritten: '.$index->indexDefinition);

                continue;
            }

            $this->apply($report, $table, sprintf('DROP INDEX %s', Identifier::qualified($this->schema, $index->name)));
            $this->apply($report, $table, $rewritten);
        }
    }

    /**
     * @param  list<string>  $inScope
     */
    private function dropZombiePolicies(array $inScope, PreparationReport $report): void
    {
        foreach ($this->catalog->ourPoliciesBySchema($this->schema) as $table => $policies) {
            if (in_array($table, $inScope, true)) {
                continue;
            }

            foreach ($policies as $policy) {
                $this->apply($report, $table, sprintf(
                    'DROP POLICY %s ON %s',
                    Identifier::quote($policy),
                    Identifier::qualified($this->schema, $table),
                ));
            }
        }
    }

    private function apply(PreparationReport $report, string $table, string $statement): void
    {
        $this->connection->statement($statement);
        $report->applied($table, $statement);
    }
}
