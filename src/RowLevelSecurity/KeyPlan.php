<?php

namespace Rushing\PostgresRls\RowLevelSecurity;

/**
 * Which keys in a schema can carry the discriminator, decided once from the catalog and shared by
 * {@see SchemaPreparer} (which acts on it) and {@see Coverage} (which reports against it), so the two
 * never disagree about what "covered" means.
 *
 * A primary key or unique index that lacks the column is rewritten to lead with it — the same id may then
 * exist under two keys, which is what a shared schema holding copies of central rows needs. Every foreign
 * key between two prepared tables must follow it, as `(column, …) REFERENCES (column, …)`, which also makes
 * a reference to another key's row impossible rather than merely invisible.
 *
 * A referenced key is left unique on its own, and reported, when any foreign key into it cannot follow:
 *
 *  - the referencing table is not prepared (excluded, in another schema, or skipped for its column type);
 *  - the foreign key is MATCH FULL or ON UPDATE SET NULL/DEFAULT (see {@see ForeignKey::unrewritableBecause()});
 *  - the foreign key already carries the column on one side but not the other (a host's own design);
 *  - (primary keys) a view depends on the key through a functional dependency.
 *
 * Foreign keys into tables outside the prepared set (central tables in `public`, excluded pool-level
 * tables) are not this plan's business and are left exactly as they are.
 */
final class KeyPlan
{
    /**
     * @param  list<ForeignKey>  $rewrite  foreign keys to drop before the key rewrites and re-add scoped after them
     * @param  array<string, list<string>>  $blocked  referenced index name => why it stays unique on its own
     * @param  array<string, array<string, string>>  $leftAlone  table => foreign key name => why it is not rewritten
     */
    private function __construct(
        public readonly array $rewrite,
        public readonly array $blocked,
        public readonly array $leftAlone,
    ) {}

    /**
     * @param  list<string>  $prepared  tables in the schema that carry (or are about to carry) the column
     */
    public static function build(Catalog $catalog, string $schema, string $column, array $prepared): self
    {
        $candidates = [];
        $blocked = [];
        $leftAlone = [];

        foreach ($catalog->foreignKeys($schema) as $foreignKey) {
            $intoPrepared = $foreignKey->referencedSchema === $schema && in_array($foreignKey->referencedTable, $prepared, true);

            if (! $intoPrepared) {
                continue;
            }

            $referencing = $foreignKey->includesColumn($column);
            $referenced = in_array($column, $foreignKey->referencedColumns, true);

            if ($referencing && $referenced) {
                continue;
            }

            if ($referencing || $referenced) {
                $blocked[$foreignKey->referencedIndex][] = sprintf('referenced by foreign key %s, which carries %s on one side only', $foreignKey->name, $column);
                $leftAlone[$foreignKey->table][$foreignKey->name] = sprintf('carries %s on one side only; left as the host wrote it', $column);

                continue;
            }

            $fromPrepared = $foreignKey->schema === $schema && in_array($foreignKey->table, $prepared, true);

            if (! $fromPrepared) {
                $blocked[$foreignKey->referencedIndex][] = sprintf(
                    'referenced by foreign key %s on %s.%s, which is outside the prepared tables',
                    $foreignKey->name,
                    $foreignKey->schema,
                    $foreignKey->table,
                );

                continue;
            }

            $reason = $foreignKey->unrewritableBecause();

            if ($reason !== null) {
                $blocked[$foreignKey->referencedIndex][] = sprintf('referenced by foreign key %s, which is not rewritten because %s', $foreignKey->name, $reason);
                $leftAlone[$foreignKey->table][$foreignKey->name] = sprintf('not rewritten because %s; %s stays unique across keys', $reason, $foreignKey->referencedIndex);

                continue;
            }

            $candidates[] = $foreignKey;
        }

        foreach ($prepared as $table) {
            $primaryKey = $catalog->primaryKey($schema, $table);

            foreach ($primaryKey['views'] ?? [] as $view) {
                $blocked[$primaryKey['index']][] = sprintf('view %s depends on it', $view);
            }
        }

        $rewrite = [];

        foreach ($candidates as $foreignKey) {
            if (isset($blocked[$foreignKey->referencedIndex])) {
                $leftAlone[$foreignKey->table][$foreignKey->name] = sprintf('not rewritten because the key it references, %s, cannot be', $foreignKey->referencedIndex);

                continue;
            }

            $rewrite[] = $foreignKey;
        }

        return new self($rewrite, $blocked, $leftAlone);
    }

    /**
     * @return list<ForeignKey>
     */
    public function rewritesOn(string $table): array
    {
        return array_values(array_filter($this->rewrite, fn (ForeignKey $foreignKey) => $foreignKey->table === $table));
    }

    /**
     * @return list<string>
     */
    public function blockedBecause(string $index): array
    {
        return $this->blocked[$index] ?? [];
    }
}
