<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Stringable;

/**
 * The read-only answer to "is every table in this schema covered?", one row per table.
 */
final class CoverageReport implements Stringable
{
    /**
     * @param  list<TableCoverage>  $tables
     */
    public function __construct(
        public readonly string $schema,
        public readonly bool $expectForced,
        public readonly array $tables,
    ) {}

    public function complete(): bool
    {
        return $this->incomplete() === [];
    }

    /** @return list<TableCoverage> */
    public function incomplete(): array
    {
        return array_values(array_filter(
            $this->tables,
            fn (TableCoverage $table) => ! $table->complete($this->expectForced),
        ));
    }

    public function table(string $name): ?TableCoverage
    {
        foreach ($this->tables as $table) {
            if ($table->table === $name) {
                return $table;
            }
        }

        return null;
    }

    /** @return list<string> */
    public function lines(): array
    {
        $lines = [sprintf(
            'schema %s: %d table(s), %d incomplete',
            $this->schema,
            count($this->tables),
            count($this->incomplete()),
        )];

        foreach ($this->tables as $table) {
            $problems = $table->problems($this->expectForced);
            $lines[] = sprintf('  %s: %s', $table->table, $problems === [] ? 'covered' : implode('; ', $problems));

            if ($table->forcedBeyondConfig($this->expectForced)) {
                $lines[] = '    note: row level security is FORCEd although force is off; the owner is subject to the policy here';
            }

            foreach ($table->foreignKeyBackedUniqueIndexes as $index) {
                $lines[] = sprintf('    note: unique index %s lacks the column but backs a foreign key; left as is', $index);
            }
        }

        return $lines;
    }

    public function __toString(): string
    {
        return implode(PHP_EOL, $this->lines());
    }
}
