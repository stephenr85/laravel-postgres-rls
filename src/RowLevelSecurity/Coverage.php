<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;

/**
 * Read-only probe: reports, per table in scope, whether it is in the state {@see SchemaPreparer}
 * would leave it in — RLS enabled, forced or not as configured, the current policy present,
 * the column present with its default, and unique indexes carrying the column. Writes nothing;
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
        $tables = [];

        foreach (array_diff($this->catalog->tables($this->schema), $this->exclude) as $table) {
            $tables[] = $this->probeTable($table);
        }

        return new CoverageReport($this->schema, $this->force, $tables);
    }

    private function probeTable(string $table): TableCoverage
    {
        $security = $this->catalog->rowSecurity($this->schema, $table);
        $policies = $this->catalog->policies($this->schema, $table);
        $expected = Policy::name($table, $this->column, $this->setting);

        $uncovered = [];
        $foreignKeyBacked = [];

        foreach ($this->catalog->uniqueIndexes($this->schema, $table) as $index) {
            if ($index->includesColumn($this->column)) {
                continue;
            }

            if ($index->backsForeignKey()) {
                $foreignKeyBacked[] = $index->name;
            } else {
                $uncovered[] = $index->name;
            }
        }

        return new TableCoverage(
            table: $table,
            rlsEnabled: $security['enabled'],
            rlsForced: $security['forced'],
            policyPresent: array_filter($policies, Policy::isOurs(...)) !== [],
            policyCurrent: in_array($expected, $policies, true),
            columnPresentWithDefault: $this->catalog->columnDefaultsFromSetting($this->schema, $table, $this->column, $this->setting),
            uncoveredUniqueIndexes: $uncovered,
            foreignKeyBackedUniqueIndexes: $foreignKeyBacked,
        );
    }
}
