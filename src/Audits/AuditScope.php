<?php

namespace Rushing\PostgresRls\Audits;

use Rushing\PostgresRls\RowLevelSecurity\Identifier;

/**
 * What the four audits are pointed at: the prepared schemas, the connection to read the catalog
 * through, which configured connections are scoped (carry `session_settings`) and which are
 * allowed to authenticate as the schema owner, plus the column/setting/exclude/force the schemas
 * were prepared with. Built from `config/postgres-rls.php` by the provider, or by hand where a host
 * assembles its connections at runtime and wraps an audit with its own scope.
 */
final class AuditScope
{
    /** @var list<string> */
    public readonly array $schemas;

    /** @var list<string> */
    public readonly array $exclude;

    /** @var list<string> */
    public readonly array $maintenanceConnections;

    /**
     * @param  list<string>  $schemas  prepared schemas to audit
     * @param  ?string  $connection  connection that reads the catalog (the owner or a superuser); null = the default connection
     * @param  ?list<string>  $scopedConnections  connections expected to carry `session_settings`; null = every pgsql entry in `database.connections` that does
     * @param  list<string>  $maintenanceConnections  connections allowed to authenticate as the schema owner (the migration path)
     * @param  list<string>  $exclude
     */
    public function __construct(
        array $schemas,
        public readonly ?string $connection = null,
        public readonly ?array $scopedConnections = null,
        array $maintenanceConnections = [],
        public readonly string $column = 'tenant_id',
        public readonly string $setting = 'app.tenant_id',
        array $exclude = ['migrations'],
        public readonly bool $force = false,
    ) {
        Identifier::assertColumn($column);
        Identifier::assertSetting($setting);

        $this->schemas = array_values(array_map(Identifier::assertSchema(...), $schemas));
        $this->exclude = array_values($exclude);
        $this->maintenanceConnections = array_values($maintenanceConnections);
    }

    /**
     * @param  array<string, mixed>  $config  the `postgres-rls` config array
     */
    public static function fromConfig(array $config): self
    {
        $audits = (array) ($config['audits'] ?? []);

        return new self(
            schemas: (array) ($audits['schemas'] ?? []),
            connection: $audits['connection'] ?? null,
            scopedConnections: isset($audits['scoped_connections']) ? (array) $audits['scoped_connections'] : null,
            maintenanceConnections: (array) ($audits['maintenance_connections'] ?? []),
            column: (string) ($config['column'] ?? 'tenant_id'),
            setting: (string) ($config['setting'] ?? 'app.tenant_id'),
            exclude: (array) ($config['exclude'] ?? ['migrations']),
            force: (bool) ($config['force'] ?? false),
        );
    }
}
