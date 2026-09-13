<?php

namespace Rushing\PostgresRls\Audits;

use Illuminate\Database\ConnectionResolverInterface;
use Rushing\Doctor\DoctorAudit;
use Rushing\Doctor\Finding;
use Rushing\PostgresRls\RowLevelSecurity\Coverage;
use Throwable;

/**
 * **Question:** is every base table in each prepared schema in the state `prepare()` leaves it —
 * RLS enabled (and forced, when `force` is on; a table forced while `force` is off is strictly
 * safer and is noted, not failed), the current policy present, the discriminator column present
 * with its default, every unique index and primary key carrying the column, and every foreign key
 * between prepared tables carrying it on both sides?
 *
 * One finding per schema. **Gate-shaped: a Fail is a table that can leak.** A table that shipped
 * without a policy is readable across keys by any scoped connection, which is the defect this map
 * exists to prevent (`SPEC.md` user story 5), so a host should register this audit as a gate.
 *
 * **What a Pass does NOT prove.** Nothing about which role reads the schema — the owner reads every
 * row with `force` off and a superuser always does (see {@see RoleAudit}, {@see OwnerExposureAudit});
 * nothing about whether the connector applied the setting at runtime ({@see FrameAudit}); nothing
 * about a key the preparer cannot rewrite (a foreign key into it from an unprepared table, MATCH FULL,
 * ON UPDATE SET NULL) — those are reported here in the detail and counted as covered. And nothing about
 * schemas not named in the scope: an unlisted pooled schema is not measured. An empty scope, or a
 * schema with no tables in it, is `inconclusive`, not clean.
 *
 * Reads through `AuditScope::$connection` (the owner, or a superuser — the catalog is readable
 * either way). A connection that cannot be opened is a Fail, not a Pass: a gate that cannot run
 * has not verified anything.
 */
final class CoverageAudit implements DoctorAudit
{
    public const CHECK = 'postgres-rls.coverage';

    public function __construct(
        private readonly ConnectionResolverInterface $db,
        private readonly AuditScope $scope,
    ) {}

    /**
     * @return list<Finding>
     */
    public function run(): array
    {
        if ($this->scope->schemas === []) {
            return [Finding::inconclusive(self::CHECK, 'No prepared schemas are configured (postgres-rls.audits.schemas), so no table was measured.')];
        }

        $findings = [];

        foreach ($this->scope->schemas as $schema) {
            $findings[] = $this->measure($schema);
        }

        return $findings;
    }

    private function measure(string $schema): Finding
    {
        try {
            $report = (new Coverage(
                $this->db->connection($this->scope->connection),
                $schema,
                $this->scope->column,
                $this->scope->setting,
                $this->scope->exclude,
                $this->scope->force,
            ))->probe();
        } catch (Throwable $e) {
            return Finding::fail(self::CHECK, sprintf('Could not read schema "%s" through connection "%s", so coverage is unverified: %s', $schema, $this->scope->connection ?? '(default)', $e->getMessage()));
        }

        if ($report->tables === []) {
            return Finding::inconclusive(self::CHECK, sprintf('Schema "%s" has no tables in scope, so nothing was measured.', $schema));
        }

        $notes = [];
        $forced = [];

        foreach ($report->tables as $table) {
            if ($table->forcedBeyondConfig($this->scope->force)) {
                $forced[] = $table->table;
            }

            foreach ($table->unrewritableKeys as $key) {
                $notes[] = sprintf('%s: %s', $table->table, $key);
            }
        }

        $noteText = $notes === [] ? '' : ' Keys the preparer cannot rewrite (left unique across keys): '.implode(', ', $notes).'.';
        $noteText .= $forced === [] ? '' : sprintf(' %d table(s) are FORCEd although force is off (strictly safer; the owner is subject there): %s.', count($forced), implode(', ', $forced));

        if ($report->complete()) {
            return Finding::pass(self::CHECK, sprintf(
                'Schema "%s": all %d table(s) carry the column with its default, row level security enabled%s, and the current policy; every rewritable unique index, primary key and foreign key carries the column.%s',
                $schema,
                count($report->tables),
                $this->scope->force ? ' and forced' : '',
                $noteText,
            ));
        }

        $problems = [];

        foreach ($report->incomplete() as $table) {
            $problems[] = sprintf('%s: %s', $table->table, implode('; ', $table->problems($this->scope->force)));
        }

        return Finding::fail(self::CHECK, sprintf(
            'Schema "%s": %d of %d table(s) are not covered and can leak across keys — %s. Run `postgres-rls:prepare %s`.%s',
            $schema,
            count($report->incomplete()),
            count($report->tables),
            implode(' | ', $problems),
            $schema,
            $noteText,
        ));
    }
}
