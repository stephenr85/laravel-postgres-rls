<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Connection;

/**
 * The column sets of a table's unique indexes, read from the catalog — what Postgres will accept as an
 * `ON CONFLICT` arbiter or as the target of a FOREIGN KEY. Shared by the two scoped grammars.
 */
final class UniqueKeySets
{
    /** @var array<string, list<array{columns: list<string>, partial: bool}>> */
    private array $cache = [];

    public function __construct(
        private readonly Connection $connection,
        private readonly bool $cached,
    ) {}

    /**
     * Valid, immediate unique indexes over plain columns (expression indexes are left out).
     *
     * @return list<array{columns: list<string>, partial: bool}>
     */
    public function of(string $table): array
    {
        $relation = $this->relation($table);

        if ($this->cached && array_key_exists($relation, $this->cache)) {
            return $this->cache[$relation];
        }

        // A pretended query returns nothing; caching that would leave every later statement unscoped.
        if ($this->connection->pretending()) {
            return [];
        }

        $rows = $this->connection->select(
            <<<'SQL'
            select json_agg(a.attname order by a.attname) as columns, bool_or(x.indpred is not null) as partial
            from pg_index x
            cross join lateral unnest(x.indkey::int2[]) with ordinality as k(attnum, ord)
            left join pg_attribute a on a.attrelid = x.indrelid and a.attnum = k.attnum and k.attnum > 0
            where x.indrelid = to_regclass(?) and x.indisunique and x.indisvalid and x.indimmediate and k.ord <= x.indnkeyatts
            group by x.indexrelid
            having count(a.attname) = count(*)
            SQL,
            [$relation]
        );

        $sets = array_map(fn ($row) => ['columns' => (array) json_decode((string) $row->columns, true), 'partial' => (bool) $row->partial], $rows);

        if ($this->cached) {
            $this->cache[$relation] = $sets;
        }

        return $sets;
    }

    public function forget(): void
    {
        $this->cache = [];
    }

    /**
     * @param  list<array{columns: list<string>, partial: bool}>  $sets
     * @param  list<string>  $columns
     */
    public static function contains(array $sets, array $columns, bool $includePartial = true): bool
    {
        $wanted = array_values(array_unique($columns));
        sort($wanted);

        foreach ($sets as $set) {
            if ($set['partial'] && ! $includePartial) {
                continue;
            }

            $have = $set['columns'];
            sort($have);

            if ($have === $wanted) {
                return true;
            }
        }

        return false;
    }

    /**
     * `to_regclass` text for a Laravel table name: the connection prefix on the LAST segment (as
     * `Grammar::wrapTable` applies it), an `as` alias dropped, every segment quoted.
     */
    private function relation(string $table): string
    {
        $segments = explode('.', trim((string) preg_split('/\s+as\s+/i', $table)[0]));
        $last = array_key_last($segments);
        $segments[$last] = $this->connection->getTablePrefix().$segments[$last];

        return implode('.', array_map(fn (string $part) => '"'.str_replace('"', '""', trim($part, '"')).'"', $segments));
    }
}
