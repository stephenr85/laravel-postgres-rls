<?php

namespace Rushing\PostgresRls\Audits;

use Illuminate\Database\ConnectionResolverInterface;
use Rushing\Doctor\DoctorAudit;
use Rushing\Doctor\Finding;
use Rushing\PostgresRls\RowLevelSecurity\Catalog;
use Throwable;

/**
 * **Question:** does any configured connection that can reach a prepared schema — every entry in
 * `database.connections` whose `search_path` names it — authenticate as that schema's owner? With
 * `force` off the owner is not subject to the policy, so such a connection on a request path reads
 * and writes every key. The owner belongs on the migration path only.
 *
 * One finding per schema. **Gate-shaped.** Connections named in `AuditScope::$maintenanceConnections`
 * are the declared migration path and are exempt; nothing else is, including the connection the
 * audits themselves read the catalog through — list it explicitly, so a misdeclared catalog
 * connection cannot exempt itself.
 *
 * Read from config only — nothing here is opened: the exposure IS the configuration (which user a
 * request path is told to authenticate as), so config is the honest instrument, and it is the only
 * audit of the four that stays closed. {@see RoleAudit} and {@see FrameAudit} do open the scoped
 * connections, with read-only selects, because the role a connection really authenticates as and
 * the setting on its live session cannot be read from config. The config `username` is compared
 * with the schema owner from `pg_namespace`; that is a string comparison, so this audit can Pass a
 * connection RoleAudit would Fail — a `url` DSN whose user is not in `username`, or a role that is a
 * MEMBER of the owner. A connection with no `search_path` key is taken to reach `public`, which is
 * what Laravel's connector defaults it to. When every table in the schema is FORCEd the owner is
 * subject to the policy and the finding is a Pass that says so; a single unforced table makes it a
 * Fail, because that table is readable across keys. No connection reaching the schema at all is
 * `inconclusive`: nothing was measured.
 *
 * **What a Pass does NOT prove.** That a connection built at runtime (not in `database.connections`)
 * is safe; that a `url`-style config's user was seen (only `username` is read — the {@see RoleAudit}
 * measures scoped connections as they really authenticate); anything about superusers, which are
 * not owners but read everything anyway (RoleAudit covers scoped connections; an unscoped superuser
 * connection reaching the schema is reported here as a Warn, not a Fail, since it is the ordinary
 * shape of a developer machine). An empty scope is `inconclusive`.
 */
final class OwnerExposureAudit implements DoctorAudit
{
    public const CHECK = 'postgres-rls.owner-exposure';

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
        if ($this->scope->schemas === []) {
            return [Finding::inconclusive(self::CHECK, 'No prepared schemas are configured (postgres-rls.audits.schemas), so no connection was checked.')];
        }

        return array_map($this->measure(...), $this->scope->schemas);
    }

    private function measure(string $schema): Finding
    {
        try {
            $catalog = new Catalog($this->db->connection($this->scope->connection));
            $owner = $catalog->schemaOwner($schema);
            $unforced = $catalog->unforcedTables($schema, $this->scope->exclude);
            $superusers = $catalog->superusers();
        } catch (Throwable $e) {
            return Finding::fail(self::CHECK, sprintf('Could not read schema "%s" through connection "%s", so owner exposure is unverified: %s', $schema, $this->scope->connection ?? '(default)', $e->getMessage()));
        }

        if ($owner === null) {
            return Finding::fail(self::CHECK, sprintf('Schema "%s" does not exist on connection "%s".', $schema, $this->scope->connection ?? '(default)'));
        }

        $reaching = array_values(array_diff($this->connections->reaching([$schema]), $this->scope->maintenanceConnections));
        $asOwner = [];
        $asSuperuser = [];

        foreach ($reaching as $name) {
            $username = (string) ($this->connections->get($name)['username'] ?? '');

            if ($username === $owner) {
                $asOwner[] = $name;
            } elseif (in_array($username, $superusers, true)) {
                $asSuperuser[] = $name;
            }
        }

        if ($reaching === []) {
            return Finding::inconclusive(self::CHECK, sprintf(
                'No configured connection reaches schema "%s" outside the maintenance path (%s), so owner exposure was not measured.',
                $schema,
                $this->scope->maintenanceConnections === [] ? 'none declared' : 'declared: '.implode(', ', $this->scope->maintenanceConnections),
            ));
        }

        $checked = sprintf('%d connection(s) reach schema "%s" outside the maintenance path (%s)', count($reaching), $schema, implode(', ', $reaching));

        if ($asOwner !== [] && $unforced !== []) {
            return Finding::fail(self::CHECK, sprintf(
                'Connection(s) %s reach schema "%s" as its owner "%s" while %d table(s) are not FORCEd (%s): the owner reads every key there. Move the owner to the migration path (postgres-rls.audits.maintenance_connections) or connect as a non-owner role.',
                implode(', ', $asOwner),
                $schema,
                $owner,
                count($unforced),
                implode(', ', $unforced),
            ));
        }

        if ($asSuperuser !== []) {
            return Finding::warn(self::CHECK, sprintf(
                'Connection(s) %s reach schema "%s" as a SUPERUSER, which reads every key regardless of the policy. Ordinary on a developer machine; never on a request path in production. %s.',
                implode(', ', $asSuperuser),
                $schema,
                $checked,
            ));
        }

        if ($asOwner !== []) {
            return Finding::pass(self::CHECK, sprintf(
                'Connection(s) %s reach schema "%s" as its owner "%s", but every table there is FORCEd, so the owner is subject to the policy. %s.',
                implode(', ', $asOwner),
                $schema,
                $owner,
                $checked,
            ));
        }

        return Finding::pass(self::CHECK, sprintf('No connection reaches schema "%s" as its owner "%s" outside the maintenance path. %s.', $schema, $owner, $checked));
    }
}
