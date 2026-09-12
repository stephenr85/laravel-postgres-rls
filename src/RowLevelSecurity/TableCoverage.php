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
     * @param  list<string>  $foreignKeyBackedUniqueIndexes  unique indexes lacking the column that a foreign key references — the preparer skips these, so they are reported but do not make the table incomplete
     */
    public function __construct(
        public readonly string $table,
        public readonly bool $rlsEnabled,
        public readonly bool $rlsForced,
        public readonly bool $policyPresent,
        public readonly bool $policyCurrent,
        public readonly bool $columnPresentWithDefault,
        public readonly array $uncoveredUniqueIndexes,
        public readonly array $foreignKeyBackedUniqueIndexes,
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
