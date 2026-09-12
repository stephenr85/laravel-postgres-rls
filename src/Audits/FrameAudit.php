<?php

namespace Rushing\PostgresRls\Audits;

use Illuminate\Database\ConnectionResolverInterface;
use Rushing\Doctor\DoctorAudit;
use Rushing\Doctor\Finding;
use Rushing\PostgresRls\SessionSettingsPostgresConnector;
use Throwable;

/**
 * **Question:** at runtime, on a live connection, is the setting where it should be? On a
 * connection carrying `session_settings`, `current_setting(name, true)` must be the configured
 * value; on a connection without them that reaches a prepared schema, it must be NULL.
 *
 * This is the runtime half of the pooler probe (pooled-storage ticket 01, check 17): the schema
 * can be perfectly prepared and the role perfectly unprivileged, and a connection can still be
 * unscoped because the connector was never bound (another package holds `db.connector.pgsql`, see
 * README "Install") or scoped by a stale frame because a pooler handed back a session that still
 * carried another key's setting. Neither is visible in the catalog; only a live read shows it.
 *
 * One finding per connection. **ADVISORY: never Fail, never throw.** A missing setting is
 * fail-closed (zero rows), and a doctor run from a shell with no database up must stay runnable,
 * so a broken invariant is a Warn and an unopenable connection is `inconclusive`.
 *
 * **What a Pass does NOT prove.** That the value stays bound for the life of the process — the
 * audit reads once, on the connection the doctor opened, not on a pooled session under load; that
 * a connection built at runtime and never listed in config was seen (pass those in
 * `AuditScope::$scopedConnections`); anything about the policy or the role. No connections to check
 * is `inconclusive`.
 */
final class FrameAudit implements DoctorAudit
{
    public const CHECK = 'postgres-rls.frame';

    public function __construct(
        private readonly ConnectionResolverInterface $db,
        private readonly AuditScope $scope,
        private readonly ConnectionConfig $connections,
    ) {}

    /**
     * @return list<Finding>
     */
    public function run(): array
    {
        $scoped = $this->scope->scopedConnections ?? $this->connections->scoped();

        // Expected-NULL connections are those reaching a prepared schema with NO session_settings in
        // config; a connection carrying them is never expected NULL, whether or not the scope lists it.
        $unscoped = array_values(array_diff($this->connections->reaching($this->scope->schemas), $scoped, $this->connections->scoped()));

        if ($scoped === [] && $unscoped === []) {
            return [Finding::inconclusive(self::CHECK, 'No connection carries session_settings and none reaches a prepared schema, so no frame was read.')];
        }

        $findings = [];

        foreach ($scoped as $name) {
            $findings[] = $this->measure($name, expected: true);
        }

        foreach ($unscoped as $name) {
            $findings[] = $this->measure($name, expected: false);
        }

        return $findings;
    }

    private function measure(string $name, bool $expected): Finding
    {
        try {
            $value = $this->db->connection($name)->selectOne('select current_setting(?, true) as v', [$this->scope->setting])->v;
        } catch (Throwable $e) {
            return Finding::inconclusive(self::CHECK, sprintf('Could not open connection "%s", so its frame was not read: %s', $name, $e->getMessage()));
        }

        $configured = $this->connections->get($name)[SessionSettingsPostgresConnector::CONFIG_KEY][$this->scope->setting] ?? null;

        if ($expected) {
            if ($value === null || $value === '') {
                return Finding::warn(self::CHECK, sprintf(
                    'Connection "%s" carries session_settings but %s is NOT bound on the live session: it reads zero rows. Is %s bound at db.connector.pgsql? (Another package holding that key wins; see README "Install".)',
                    $name,
                    $this->scope->setting,
                    SessionSettingsPostgresConnector::class,
                ));
            }

            if ($configured !== null && (string) $configured !== $value) {
                return Finding::warn(self::CHECK, sprintf(
                    'Connection "%s" has %s = "%s" on the live session but config says "%s": a stale frame, the pooler-reuse shape.',
                    $name,
                    $this->scope->setting,
                    $value,
                    (string) $configured,
                ));
            }

            return Finding::pass(self::CHECK, sprintf('Connection "%s": %s = "%s" on the live session, as configured.', $name, $this->scope->setting, $value));
        }

        if ($value !== null && $value !== '') {
            return Finding::warn(self::CHECK, sprintf(
                'Connection "%s" carries no session_settings yet %s = "%s" on the live session: a leaked frame (a reused session, or a SET issued outside the connector).',
                $name,
                $this->scope->setting,
                $value,
            ));
        }

        return Finding::pass(self::CHECK, sprintf('Connection "%s": %s is NULL on the live session, as expected for an unscoped connection.', $name, $this->scope->setting));
    }
}
