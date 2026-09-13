<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;

/**
 * Read-only probe: reports, per table in scope, whether it is in the state {@see SchemaPreparer}
 * would leave it in — RLS enabled, forced or not as configured, the current policy present,
 * the column present with its default, and unique indexes, the primary key and foreign keys between
 * prepared tables carrying the column (as {@see KeyPlan} decides). Writes nothing;
 * a doctor audit or a post-migrate gate reads {@see CoverageReport::complete()}.
 *
 * Reads `pg_class.relrowsecurity` / `relforcerowsecurity`, `pg_policies`,
 * `information_schema.columns` and `pg_index`.
 */
final class Coverage
{
    private readonly Catalog $catalog;

    /** @var list<string> */
    private readonly array $exclude;

    /**
     * @param  list<string>  $exclude
     */
    public function __construct(
        Connection $connection,
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

    public function probe(): CoverageReport
    {
        $inScope = array_values(array_diff($this->catalog->tables($this->schema), $this->exclude));

        // The tables the preparer would carry the column on: absent (it adds one) or text (it repairs one).
        $preparable = array_values(array_filter($inScope, function (string $table) {
            $info = $this->catalog->column($this->schema, $table, $this->column);

            return ! $info['present'] || in_array($info['type'], ['text', 'character varying', 'character'], true);
        }));

        $plan = KeyPlan::build($this->catalog, $this->schema, $this->column, $preparable);
        $tables = [];

        foreach ($inScope as $table) {
            $tables[] = $this->probeTable($table, $plan);
        }

        return new CoverageReport($this->schema, $this->force, $tables);
    }

    private function probeTable(string $table, KeyPlan $plan): TableCoverage
    {
        $security = $this->catalog->rowSecurity($this->schema, $table);
        $policies = $this->catalog->policies($this->schema, $table);
        $expected = Policy::name($table, $this->column, $this->setting);

        $uncovered = [];
        $unrewritable = [];

        foreach ($this->catalog->uniqueIndexes($this->schema, $table) as $index) {
            if ($index->includesColumn($this->column)) {
                continue;
            }

            if ($plan->blockedBecause($index->name) !== []) {
                $unrewritable[] = sprintf('unique index %s (%s)', $index->name, implode('; ', $plan->blockedBecause($index->name)));
            } elseif ($index->rewrittenDefinition($this->column) === null) {
                $unrewritable[] = sprintf('unique index %s (definition not understood)', $index->name);
            } else {
                $uncovered[] = $index->name;
            }
        }

        $primaryKey = $this->catalog->primaryKey($this->schema, $table);
        $uncoveredPrimaryKey = null;

        if ($primaryKey !== null && ! in_array($this->column, $primaryKey['columns'], true)) {
            if ($plan->blockedBecause($primaryKey['index']) !== []) {
                $unrewritable[] = sprintf('primary key %s (%s)', $primaryKey['name'], implode('; ', $plan->blockedBecause($primaryKey['index'])));
            } else {
                $uncoveredPrimaryKey = $primaryKey['name'];
            }
        }

        foreach ($plan->leftAlone[$table] ?? [] as $name => $reason) {
            $unrewritable[] = sprintf('foreign key %s (%s)', $name, $reason);
        }

        return new TableCoverage(
            table: $table,
            rlsEnabled: $security['enabled'],
            rlsForced: $security['forced'],
            policyPresent: array_filter($policies, Policy::isOurs(...)) !== [],
            policyCurrent: in_array($expected, $policies, true),
            columnPresentWithDefault: $this->catalog->columnDefaultsFromSetting($this->schema, $table, $this->column, $this->setting),
            uncoveredUniqueIndexes: $uncovered,
            uncoveredPrimaryKey: $uncoveredPrimaryKey,
            uncoveredForeignKeys: array_map(fn (ForeignKey $foreignKey) => $foreignKey->name, $plan->rewritesOn($table)),
            unrewritableKeys: $unrewritable,
        );
    }
}
