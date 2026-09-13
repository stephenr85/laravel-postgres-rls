<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

/**
 * One table's row-level-security state as {@see Coverage} read it.
 */
final class TableCoverage
{
    /**
     * @param  bool  $policyPresent  a policy carrying this package's suffix exists on the table
     * @param  bool  $policyCurrent  the policy named for the CURRENT column and setting exists
     * @param  list<string>  $uncoveredUniqueIndexes  unique indexes whose key columns lack the column and that the preparer would rewrite
     * @param  ?string  $uncoveredPrimaryKey  the primary key's name when it lacks the column and the preparer would rewrite it
     * @param  list<string>  $uncoveredForeignKeys  foreign keys on this table into a prepared table that lack the column and that the preparer would rewrite
     * @param  list<string>  $unrewritableKeys  keys lacking the column that the preparer cannot rewrite, each with why — reported, but they do not make the table incomplete
     */
    public function __construct(
        public readonly string $table,
        public readonly bool $rlsEnabled,
        public readonly bool $rlsForced,
        public readonly bool $policyPresent,
        public readonly bool $policyCurrent,
        public readonly bool $columnPresentWithDefault,
        public readonly array $uncoveredUniqueIndexes,
        public readonly ?string $uncoveredPrimaryKey = null,
        public readonly array $uncoveredForeignKeys = [],
        public readonly array $unrewritableKeys = [],
    ) {}

    public function uniqueIndexesCovered(): bool
    {
        return $this->uncoveredUniqueIndexes === [];
    }

    /**
     * @return list<string> what a `prepare()` run would still have to change; empty when complete
     */
    public function problems(bool $expectForced): array
    {
        $problems = [];

        if (! $this->columnPresentWithDefault) {
            $problems[] = 'column absent, nullable, or not defaulted from the setting';
        }

        if (! $this->rlsEnabled) {
            $problems[] = 'row level security not enabled';
        }

        if ($expectForced && ! $this->rlsForced) {
            $problems[] = 'row level security not forced';
        }

        if (! $this->policyCurrent) {
            $problems[] = $this->policyPresent ? 'policy present but outdated (hash differs)' : 'policy absent';
        }

        if ($this->uncoveredUniqueIndexes !== []) {
            $problems[] = 'unique index(es) lacking the column: '.implode(', ', $this->uncoveredUniqueIndexes);
        }

        if ($this->uncoveredPrimaryKey !== null) {
            $problems[] = 'primary key lacking the column: '.$this->uncoveredPrimaryKey;
        }

        if ($this->uncoveredForeignKeys !== []) {
            $problems[] = 'foreign key(s) lacking the column: '.implode(', ', $this->uncoveredForeignKeys);
        }

        return $problems;
    }

    /**
     * FORCEd while `force` is off: strictly safer (the owner is subject too), so not a problem —
     * but worth naming, because an owner connection that expected to read across keys will not.
     */
    public function forcedBeyondConfig(bool $expectForced): bool
    {
        return $this->rlsForced && ! $expectForced;
    }

    public function complete(bool $expectForced): bool
    {
        return $this->problems($expectForced) === [];
    }
}
