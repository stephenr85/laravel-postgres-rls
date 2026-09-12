<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

/**
 * One unique, non-primary index as the catalog describes it.
 */
final class UniqueIndex
{
    /**
     * @param  list<string>  $keyColumns  key columns or expressions, in index order (INCLUDE columns excluded)
     * @param  ?string  $constraintName  set when a UNIQUE constraint owns the index
     * @param  ?string  $constraintDefinition  `pg_get_constraintdef`, e.g. `UNIQUE (a, b)`
     * @param  string  $indexDefinition  `pg_get_indexdef`, e.g. `CREATE UNIQUE INDEX n ON s.t USING btree (a, b)`
     * @param  list<string>  $referencingForeignKeys  foreign-key constraint names whose target is this index
     */
    public function __construct(
        public readonly string $name,
        public readonly array $keyColumns,
        public readonly ?string $constraintName,
        public readonly ?string $constraintDefinition,
        public readonly string $indexDefinition,
        public readonly array $referencingForeignKeys,
    ) {}

    public function includesColumn(string $column): bool
    {
        return in_array($column, $this->keyColumns, true);
    }

    public function backsConstraint(): bool
    {
        return $this->constraintName !== null;
    }

    public function backsForeignKey(): bool
    {
        return $this->referencingForeignKeys !== [];
    }
}
