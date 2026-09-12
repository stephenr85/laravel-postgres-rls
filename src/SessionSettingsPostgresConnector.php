<?php

namespace Rushing\PostgresRls;

use Illuminate\Database\Connectors\PostgresConnector;
use PDO;

/**
 * A pgsql connector that applies `session_settings` from the connection config on every
 * connect — and therefore on every reconnect, because Laravel's `Connection::reconnect()`
 * goes back through the connector.
 *
 * Config shape:
 *
 *     'connections' => [
 *         'scoped' => [
 *             'driver' => 'pgsql',
 *             // ... the usual keys ...
 *             'session_settings' => [
 *                 'app.tenant_id' => 'abc',
 *                 'statement_timeout' => '5s',
 *             ],
 *         ],
 *     ],
 *
 * Each pair becomes a prepared `select set_config(?, ?, false)`: the third argument `false`
 * makes the setting session-scoped rather than transaction-local, so it survives every
 * transaction on the PDO. Values are cast to string, because that is what Postgres stores.
 *
 * Why a connector and not a `SET` after connect: a plain `SET` issued once is lost when the
 * PDO is dropped and re-established (a server restart, a pooler recycle, or an explicit
 * `reconnect()`), and the next query runs unscoped. Riding the connector puts the settings
 * on the same path the connection itself takes, with no global state to remember.
 *
 * Custom settings must carry a namespace (`app.key`, never `key`): Postgres refuses to set an
 * unnamespaced name it does not recognise. Built-in settings (`statement_timeout`) carry none.
 */
class SessionSettingsPostgresConnector extends PostgresConnector
{
    public const CONFIG_KEY = 'session_settings';

    /**
     * @param  array<string, mixed>  $config
     */
    public function connect(array $config): PDO
    {
        $pdo = parent::connect($config);

        $this->applySessionSettings($pdo, $config[self::CONFIG_KEY] ?? []);

        return $pdo;
    }

    /**
     * @param  array<string, scalar|\Stringable|null>  $settings
     */
    protected function applySessionSettings(PDO $pdo, array $settings): void
    {
        if ($settings === []) {
            return;
        }

        $statement = $pdo->prepare('select set_config(?, ?, false)');

        foreach ($settings as $name => $value) {
            $statement->execute([(string) $name, (string) $value]);
        }
    }
}
