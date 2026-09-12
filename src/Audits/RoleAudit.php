<?php

namespace Rushing\PostgresRls\Audits;

use Illuminate\Database\ConnectionResolverInterface;
use Rushing\Doctor\DoctorAudit;
use Rushing\Doctor\Finding;
use Rushing\PostgresRls\RowLevelSecurity\Catalog;
use Throwable;

/**
 * **Question:** does every scoped connection — one carrying `session_settings` — authenticate as a
 * role the policy actually applies to? A policy binds only a role that is neither a superuser, nor
 * `BYPASSRLS`, nor the owner of the table (unless FORCE is on). On a developer machine every app
 * connection is typically a superuser, so a pool can look scoped in every test and be wide open.
 *
 * One finding per scoped connection; the Pass NAMES the role it checked (`current_user` as the
 * connection itself reports it, not the config's `username`, so a DSN-built connection is measured
 * too). **Gate-shaped: a Fail is a connection that reads every key.**
 *
 * Fails when the role is `rolsuper`, holds `rolbypassrls`, owns any prepared schema, or owns any
 * table in one. Ownership is checked against `AuditScope::$schemas`; with FORCE on an owner is
 * subject to the policy, but the audit still fails it, because FORCE is per table and a later
 * `prepare(force: false)` would silently reopen the pool.
 *
 * **What a Pass does NOT prove.** That the setting is bound on the connection ({@see FrameAudit});
 * that the tables carry a policy ({@see CoverageAudit}); anything about a scoped connection the
 * host assembles at runtime and never lists in `database.connections` — pass those by name in
 * `AuditScope::$scopedConnections`. No scoped connections at all is `inconclusive`. A connection that
 * cannot be opened is a Fail, because an unverified gate is not a passed one.
 */
final class RoleAudit implements DoctorAudit
{
    public const CHECK = 'postgres-rls.role';

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
        $names = $this->scope->scopedConnections ?? $this->connections->scoped();

        if ($names === []) {
            return [Finding::inconclusive(self::CHECK, 'No connection carries session_settings, so no scoped role was checked.')];
        }

        return array_map($this->measure(...), $names);
    }

    private function measure(string $name): Finding
    {
        try {
            $connection = $this->db->connection($name);
            $catalog = new Catalog($connection);
            $role = $catalog->currentRole();
            $owned = $catalog->ownedIn($role['name'], $this->scope->schemas);
        } catch (Throwable $e) {
            return Finding::fail(self::CHECK, sprintf('Could not open scoped connection "%s", so its role is unverified: %s', $name, $e->getMessage()));
        }

        $reasons = [];

        if ($role['superuser']) {
            $reasons[] = 'is a SUPERUSER, which bypasses every policy';
        }

        if ($role['bypassrls']) {
            $reasons[] = 'holds BYPASSRLS';
        }

        if ($owned['schemas'] !== []) {
            $reasons[] = 'owns schema(s) '.implode(', ', $owned['schemas']);
        }

        if ($owned['tables'] !== []) {
            $reasons[] = 'owns table(s) '.implode(', ', $owned['tables']).' (an owner is not subject to the policy unless FORCE is on)';
        }

        if ($reasons === []) {
            return Finding::pass(self::CHECK, sprintf(
                'Scoped connection "%s" authenticates as role "%s": not a superuser, no BYPASSRLS, owns no prepared schema and no table in %s; the policy applies to it.',
                $name,
                $role['name'],
                $this->scope->schemas === [] ? '(no schemas configured)' : implode(', ', $this->scope->schemas),
            ));
        }

        return Finding::fail(self::CHECK, sprintf(
            'Scoped connection "%s" authenticates as role "%s", which %s — it reads every key. Connect scoped traffic as a non-owner role (see RoleGrants).',
            $name,
            $role['name'],
            implode(', ', $reasons),
        ));
    }
}
