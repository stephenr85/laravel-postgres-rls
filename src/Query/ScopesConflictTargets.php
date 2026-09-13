<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Query\Builder;

/**
 * Prepends the discriminator column to an upsert's conflict target when the table's unique index
 * carries it — so `upsert($rows, ['slug'])` keeps working on a table whose `(slug)` index the
 * preparer rewrote to `(tenant_id, slug)`, and the model still never names the column.
 *
 * Postgres infers the arbiter index for `ON CONFLICT (cols)` only from a unique index over exactly
 * those columns, so once the preparer widens an index every upsert naming the old columns fails with
 * "there is no unique or exclusion constraint matching the ON CONFLICT specification". The rewrite is
 * decided from the catalog, never assumed: the target gains the column only when the table has a
 * unique index over exactly `{column} ∪ target` and none over exactly `target`. Partial indexes count,
 * so tpetry's `upsertPartial()` is scoped too. A table with no such index (a central table reached
 * through the search_path, an excluded pool-level table) compiles unchanged.
 *
 * Cached per table for the grammar's life (one connection object; stancl rebuilds the tenant connection
 * on every initialisation). A long-lived connection that outlives a `prepare()` calls
 * {@see forgetUniqueKeys()}. `insertOrIgnore()` compiles `ON CONFLICT DO NOTHING` with no target.
 */
trait ScopesConflictTargets
{
    private string $scopeColumn = 'tenant_id';

    private ?UniqueKeySets $uniqueKeys = null;

    public function scopeBy(string $column): static
    {
        $this->scopeColumn = $column;
        $this->uniqueKeys = null;

        return $this;
    }

    public function forgetUniqueKeys(): void
    {
        $this->uniqueKeys?->forget();
    }

    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        return parent::compileUpsert($query, $values, $this->scopedConflictTarget($query, $uniqueBy), $update);
    }

    /**
     * @param  list<string>  $uniqueBy
     * @return list<string>
     */
    public function scopedConflictTarget(Builder $query, array $uniqueBy): array
    {
        if ($uniqueBy === [] || in_array($this->scopeColumn, $uniqueBy, true) || ! is_string($query->from)) {
            return $uniqueBy;
        }

        $this->uniqueKeys ??= new UniqueKeySets($this->connection, cached: true);
        $sets = $this->uniqueKeys->of($query->from);

        if (UniqueKeySets::contains($sets, $uniqueBy) || ! UniqueKeySets::contains($sets, [$this->scopeColumn, ...$uniqueBy])) {
            return $uniqueBy;
        }

        return [$this->scopeColumn, ...$uniqueBy];
    }
}
