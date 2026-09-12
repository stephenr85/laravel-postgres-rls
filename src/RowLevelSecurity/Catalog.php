<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Illuminate\Database\Connection;

/**
 * Read-only queries over the Postgres catalog, shared by {@see SchemaPreparer} (which acts on
 * the answers) and {@see Coverage} (which only reports them). Every method is one round trip
 * and writes nothing.
 */
final class Catalog
{
    public function __construct(private readonly Connection $connection) {}

    /**
     * Base and partitioned tables in the schema, sorted.
     *
     * @return list<string>
     */
    public function tables(string $schema): array
    {
        $rows = $this->connection->select(
            "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = ? and c.relkind in ('r', 'p') order by c.relname",
            [$schema]
        );

        return array_map(fn ($row) => $row->relname, $rows);
    }

    /**
     * @return array{present: bool, type: ?string, nullable: bool, default: ?string}
     */
    public function column(string $schema, string $table, string $column): array
    {
        $row = $this->connection->selectOne(
            'select data_type, is_nullable, column_default from information_schema.columns where table_schema = ? and table_name = ? and column_name = ?',
            [$schema, $table, $column]
        );

        return [
            'present' => $row !== null,
            'type' => $row?->data_type,
            'nullable' => $row !== null && $row->is_nullable === 'YES',
            'default' => $row?->column_default,
        ];
    }

    /**
     * Whether the column has a DEFAULT of `current_setting('<setting>')` — the strict form —
     * as the catalog renders it (`current_setting('app.key'::text)`).
     */
    public function columnDefaultsFromSetting(string $schema, string $table, string $column, string $setting): bool
    {
        $info = $this->column($schema, $table, $column);

        return $info['present'] && ! $info['nullable'] && $this->isSettingDefault($info['default'], $setting);
    }

    public function isSettingDefault(?string $default, string $setting): bool
    {
        if ($default === null) {
            return false;
        }

        $normalised = preg_replace('/::text/', '', $default);

        return $normalised === sprintf("current_setting('%s')", $setting);
    }

    /** Whether any btree index on the table leads with the column. */
    public function hasLeadingIndex(string $schema, string $table, string $column): bool
    {
        $row = $this->connection->selectOne(
            <<<'SQL'
            select i.relname
            from pg_index x
            join pg_class c on c.oid = x.indrelid
            join pg_class i on i.oid = x.indexrelid
            join pg_namespace n on n.oid = c.relnamespace
            join pg_am am on am.oid = i.relam
            join pg_attribute a on a.attrelid = c.oid and a.attnum = x.indkey[0]
            where n.nspname = ? and c.relname = ? and am.amname = 'btree' and a.attname = ?
            limit 1
            SQL,
            [$schema, $table, $column]
        );

        return $row !== null;
    }

    /**
     * @return array{enabled: bool, forced: bool}
     */
    public function rowSecurity(string $schema, string $table): array
    {
        $row = $this->connection->selectOne(
            'select c.relrowsecurity as enabled, c.relforcerowsecurity as forced from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = ? and c.relname = ?',
            [$schema, $table]
        );

        return [
            'enabled' => (bool) ($row?->enabled ?? false),
            'forced' => (bool) ($row?->forced ?? false),
        ];
    }

    /**
     * Policy names on the table.
     *
     * @return list<string>
     */
    public function policies(string $schema, string $table): array
    {
        $rows = $this->connection->select(
            'select policyname from pg_policies where schemaname = ? and tablename = ? order by policyname',
            [$schema, $table]
        );

        return array_map(fn ($row) => $row->policyname, $rows);
    }

    /**
     * Every policy in the schema that this package minted, keyed by table.
     *
     * @return array<string, list<string>>
     */
    public function ourPoliciesBySchema(string $schema): array
    {
        $rows = $this->connection->select(
            'select tablename, policyname from pg_policies where schemaname = ? order by tablename, policyname',
            [$schema]
        );

        $result = [];

        foreach ($rows as $row) {
            if (Policy::isOurs($row->policyname)) {
                $result[$row->tablename][] = $row->policyname;
            }
        }

        return $result;
    }

    /**
     * Unique, non-primary indexes on the table, with their key columns, whether a UNIQUE
     * constraint owns the index (rewrite via ALTER TABLE rather than DROP INDEX), the
     * constraint or index definition, and the names of any foreign keys that reference it.
     *
     * @return list<UniqueIndex>
     */
    public function uniqueIndexes(string $schema, string $table): array
    {
        $rows = $this->connection->select(
            <<<'SQL'
            select
                i.relname as index_name,
                x.indnkeyatts as key_count,
                x.indexrelid as index_oid,
                pg_get_indexdef(x.indexrelid) as index_def,
                u.conname as constraint_name,
                case when u.oid is null then null else pg_get_constraintdef(u.oid) end as constraint_def,
                (select coalesce(string_agg(f.conname, ',' order by f.conname), '')
                   from pg_constraint f where f.contype = 'f' and f.conindid = x.indexrelid) as referencing_fks
            from pg_index x
            join pg_class c on c.oid = x.indrelid
            join pg_class i on i.oid = x.indexrelid
            join pg_namespace n on n.oid = c.relnamespace
            left join pg_constraint u on u.conindid = x.indexrelid and u.contype = 'u' and u.conrelid = c.oid
            where n.nspname = ? and c.relname = ? and x.indisunique and not x.indisprimary
            order by i.relname
            SQL,
            [$schema, $table]
        );

        $indexes = [];

        foreach ($rows as $row) {
            $columns = $this->indexKeyColumns((int) $row->index_oid, (int) $row->key_count);

            $indexes[] = new UniqueIndex(
                name: $row->index_name,
                keyColumns: $columns,
                constraintName: $row->constraint_name,
                constraintDefinition: $row->constraint_def,
                indexDefinition: $row->index_def,
                referencingForeignKeys: $row->referencing_fks === '' ? [] : explode(',', $row->referencing_fks),
            );
        }

        return $indexes;
    }

    /**
     * @return list<string>
     */
    private function indexKeyColumns(int $indexOid, int $keyCount): array
    {
        if ($keyCount < 1) {
            return [];
        }

        $rows = $this->connection->select(
            'select pg_get_indexdef(?, g.k, true) as expr from generate_series(1, ?) as g(k) order by g.k',
            [$indexOid, $keyCount]
        );

        return array_map(fn ($row) => $row->expr, $rows);
    }

    /**
     * The role the connection authenticates as, as Postgres sees it.
     *
     * @return array{name: string, superuser: bool, bypassrls: bool}
     */
    public function currentRole(): array
    {
        $row = $this->connection->selectOne('select rolname, rolsuper, rolbypassrls from pg_roles where rolname = current_user');

        return [
            'name' => (string) $row->rolname,
            'superuser' => (bool) $row->rolsuper,
            'bypassrls' => (bool) $row->rolbypassrls,
        ];
    }

    /**
     * Schemas and tables among `$schemas` that `$role` owns.
     *
     * @param  list<string>  $schemas
     * @return array{schemas: list<string>, tables: list<string>}
     */
    public function ownedIn(string $role, array $schemas): array
    {
        if ($schemas === []) {
            return ['schemas' => [], 'tables' => []];
        }

        $placeholders = implode(', ', array_fill(0, count($schemas), '?'));

        $ownedSchemas = $this->connection->select(
            "select nspname from pg_namespace where pg_get_userbyid(nspowner) = ? and nspname in ($placeholders) order by nspname",
            [$role, ...$schemas]
        );
        $ownedTables = $this->connection->select(
            "select schemaname || '.' || tablename as name from pg_tables where tableowner = ? and schemaname in ($placeholders) order by 1",
            [$role, ...$schemas]
        );

        return [
            'schemas' => array_map(fn ($row) => $row->nspname, $ownedSchemas),
            'tables' => array_map(fn ($row) => $row->name, $ownedTables),
        ];
    }

    /**
     * Tables in scope whose row security is not FORCEd — where the owner reads every row.
     *
     * @param  list<string>  $exclude
     * @return list<string>
     */
    public function unforcedTables(string $schema, array $exclude = []): array
    {
        $rows = $this->connection->select(
            "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = ? and c.relkind in ('r', 'p') and not c.relforcerowsecurity order by c.relname",
            [$schema]
        );

        return array_values(array_diff(array_map(fn ($row) => $row->relname, $rows), $exclude));
    }

    /**
     * @return list<string>
     */
    public function superusers(): array
    {
        return array_map(fn ($row) => $row->rolname, $this->connection->select('select rolname from pg_roles where rolsuper order by rolname'));
    }

    public function schemaOwner(string $schema): ?string
    {
        $row = $this->connection->selectOne(
            'select pg_get_userbyid(nspowner) as owner from pg_namespace where nspname = ?',
            [$schema]
        );

        return $row?->owner;
    }
}
