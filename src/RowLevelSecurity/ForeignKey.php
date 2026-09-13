<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

/**
 * One FOREIGN KEY constraint as the catalog describes it, in parts rather than as
 * `pg_get_constraintdef` text: the preparer re-issues it with the discriminator prepended on both
 * sides, and a definition string renders the referenced table however the reading connection's
 * search_path happens to qualify it.
 */
final class ForeignKey
{
    private const ACTIONS = ['a' => 'NO ACTION', 'r' => 'RESTRICT', 'c' => 'CASCADE', 'n' => 'SET NULL', 'd' => 'SET DEFAULT'];

    /**
     * @param  list<string>  $columns  referencing columns, in key order
     * @param  list<string>  $referencedColumns  referenced columns, in key order
     * @param  string  $onUpdate  `pg_constraint.confupdtype` (a, r, c, n, d)
     * @param  string  $onDelete  `pg_constraint.confdeltype`
     * @param  list<string>  $deleteSetColumns  `confdelsetcols` (Postgres 15+): the columns an ON DELETE SET NULL/DEFAULT touches; empty = all of them
     * @param  string  $matchType  `confmatchtype` (s simple, f full, p partial)
     * @param  string  $referencedIndex  the unique index the constraint depends on (`conindid`)
     */
    public function __construct(
        public readonly string $name,
        public readonly string $schema,
        public readonly string $table,
        public readonly array $columns,
        public readonly string $referencedSchema,
        public readonly string $referencedTable,
        public readonly array $referencedColumns,
        public readonly string $onUpdate,
        public readonly string $onDelete,
        public readonly array $deleteSetColumns,
        public readonly string $matchType,
        public readonly bool $deferrable,
        public readonly bool $deferred,
        public readonly bool $validated,
        public readonly string $referencedIndex,
    ) {}

    public function includesColumn(string $column): bool
    {
        return in_array($column, $this->columns, true);
    }

    /**
     * Why prepending the discriminator would change what this constraint means, or null when it would not.
     *
     * MATCH FULL demands all-null or no-null key columns, so a never-null discriminator beside a nullable
     * column would reject every row whose reference is null. ON UPDATE SET NULL/DEFAULT takes no column
     * list, so it would null or reset the discriminator itself.
     */
    public function unrewritableBecause(): ?string
    {
        if ($this->matchType === 'f') {
            return 'it is MATCH FULL, which a never-null discriminator column would change';
        }

        if (in_array($this->onUpdate, ['n', 'd'], true)) {
            return sprintf('it is ON UPDATE %s, which cannot be limited to its own columns and would reset the discriminator', self::ACTIONS[$this->onUpdate]);
        }

        return null;
    }

    /**
     * `ALTER TABLE … ADD CONSTRAINT` body with `$column` leading both key lists. An ON DELETE SET NULL
     * or SET DEFAULT names its own columns (Postgres 15+), so a cascade never clears the discriminator.
     */
    public function scopedDefinition(string $column): string
    {
        $onDelete = self::ACTIONS[$this->onDelete];

        if (in_array($this->onDelete, ['n', 'd'], true)) {
            $onDelete .= ' ('.$this->columnList($this->deleteSetColumns === [] ? $this->columns : $this->deleteSetColumns).')';
        }

        return trim(sprintf(
            'FOREIGN KEY (%s) REFERENCES %s (%s)%s ON UPDATE %s ON DELETE %s%s%s',
            $this->columnList([$column, ...$this->columns]),
            Identifier::qualified($this->referencedSchema, $this->referencedTable),
            $this->columnList([$column, ...$this->referencedColumns]),
            $this->matchType === 'p' ? ' MATCH PARTIAL' : '',
            self::ACTIONS[$this->onUpdate],
            $onDelete,
            $this->deferrable ? ' DEFERRABLE'.($this->deferred ? ' INITIALLY DEFERRED' : '') : '',
            $this->validated ? '' : ' NOT VALID',
        ));
    }

    /**
     * @param  list<string>  $columns
     */
    private function columnList(array $columns): string
    {
        return implode(', ', array_map(Identifier::quote(...), $columns));
    }
}
