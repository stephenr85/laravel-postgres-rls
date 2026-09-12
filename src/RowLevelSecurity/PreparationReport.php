<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

use Stringable;

/**
 * What one {@see SchemaPreparer::prepare()} (or `dropPolicies()`) run did, per table: the DDL it
 * executed and the items it deliberately left alone with the reason. A second run over an
 * already-prepared schema reports zero applied statements — that is the idempotence check.
 */
final class PreparationReport implements Stringable
{
    /** @var list<string> */
    private array $inspected = [];

    /** @var array<string, list<string>> */
    private array $applied = [];

    /** @var array<string, list<array{subject: string, reason: string}>> */
    private array $skipped = [];

    public function __construct(public readonly string $schema) {}

    public function inspected(string $table): void
    {
        if (! in_array($table, $this->inspected, true)) {
            $this->inspected[] = $table;
        }
    }

    public function applied(string $table, string $statement): void
    {
        $this->inspected($table);
        $this->applied[$table][] = $statement;
    }

    public function skipped(string $table, string $subject, string $reason): void
    {
        $this->inspected($table);
        $this->skipped[$table][] = ['subject' => $subject, 'reason' => $reason];
    }

    /** @return list<string> */
    public function tables(): array
    {
        return $this->inspected;
    }

    /** @return array<string, list<string>> */
    public function appliedStatements(): array
    {
        return $this->applied;
    }

    /** @return array<string, list<array{subject: string, reason: string}>> */
    public function skippedItems(): array
    {
        return $this->skipped;
    }

    public function appliedCount(): int
    {
        return array_sum(array_map('count', $this->applied));
    }

    public function skippedCount(): int
    {
        return array_sum(array_map('count', $this->skipped));
    }

    public function isNoop(): bool
    {
        return $this->applied === [];
    }

    /** @return list<string> */
    public function lines(): array
    {
        $lines = [sprintf(
            'schema %s: %d table(s) inspected, %d statement(s) applied, %d item(s) skipped',
            $this->schema,
            count($this->inspected),
            $this->appliedCount(),
            $this->skippedCount(),
        )];

        foreach ($this->inspected as $table) {
            $applied = $this->applied[$table] ?? [];
            $skipped = $this->skipped[$table] ?? [];

            if ($applied === [] && $skipped === []) {
                $lines[] = sprintf('  %s: up to date', $table);

                continue;
            }

            $lines[] = sprintf('  %s:', $table);

            foreach ($applied as $statement) {
                $lines[] = '    applied  '.$statement;
            }

            foreach ($skipped as $item) {
                $lines[] = sprintf('    skipped  %s — %s', $item['subject'], $item['reason']);
            }
        }

        return $lines;
    }

    public function __toString(): string
    {
        return implode(PHP_EOL, $this->lines());
    }
}
