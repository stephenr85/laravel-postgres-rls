<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Fluent;

/**
 * A migration that adds a foreign key into an already-prepared table — `$table->foreignId('user_id')
 * ->constrained()` in a pool whose `users` key is `(tenant_id, id)` — would fail: nothing unique covers
 * `(id)` alone any more. On a scoped connection this schema grammar writes the foreign key the way the
 * preparer would have left it, `(tenant_id, user_id) REFERENCES users (tenant_id, id)`, adding the
 * discriminator column to the referencing table first when it has none yet (the preparer then gives it
 * its default and NOT NULL). An ON DELETE SET NULL/DEFAULT names its own columns.
 *
 * Decided from the catalog at compile time, uncached (migrations change it): only when the referenced
 * table has a non-partial unique key over exactly `{column} ∪ references` and none over `references`.
 * A reference into a central table, or into a table created earlier in the same run and not yet
 * prepared, compiles unchanged. ON UPDATE SET NULL/DEFAULT cannot name its columns and is left to fail
 * as it would have.
 *
 * Emitted as one `DO` block: Laravel runs each compiled statement as a prepared statement, which takes
 * one command, and tpetry's grammar declares this method's return as a single string.
 */
trait ScopesForeignKeys
{
    private string $scopeColumn = 'tenant_id';

    public function scopeBy(string $column): static
    {
        $this->scopeColumn = $column;

        return $this;
    }

    public function compileForeign(Blueprint $blueprint, Fluent $command): string
    {
        $columns = (array) $command->columns;
        $references = (array) $command->references;
        // `constrained()` names the table as a Stringable (`Str::of(...)->plural()`).
        $on = is_string($command->on) || $command->on instanceof \Stringable ? (string) $command->on : null;

        if ($on === null
            || in_array($this->scopeColumn, $columns, true)
            || in_array($this->scopeColumn, $references, true)
            || in_array(strtolower((string) $command->onUpdate), ['set null', 'set default'], true)
            || array_filter([...$columns, ...$references], fn ($column) => ! is_string($column)) !== []) {
            return parent::compileForeign($blueprint, $command);
        }

        $sets = (new UniqueKeySets($this->connection, cached: false))->of($on);

        if (UniqueKeySets::contains($sets, $references, includePartial: false) || ! UniqueKeySets::contains($sets, [$this->scopeColumn, ...$references], includePartial: false)) {
            return parent::compileForeign($blueprint, $command);
        }

        $scoped = new Fluent($command->getAttributes());
        $scoped->columns = [$this->scopeColumn, ...$columns];
        $scoped->references = [$this->scopeColumn, ...$references];

        if (in_array(strtolower((string) $command->onDelete), ['set null', 'set default'], true)) {
            $scoped->onDelete = $command->onDelete.' ('.$this->columnize($columns).')';
        }

        return sprintf(
            'do $$ begin alter table %s add column if not exists %s text; %s; end $$',
            $this->wrapTable($blueprint),
            $this->wrap($this->scopeColumn),
            parent::compileForeign($blueprint, $scoped),
        );
    }
}
