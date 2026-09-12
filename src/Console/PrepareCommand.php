<?php

namespace Rushing\PostgresRls\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConnectionResolverInterface;
use Rushing\PostgresRls\RowLevelSecurity\SchemaPreparer;

/**
 * `postgres-rls:prepare {schema}` — runs {@see SchemaPreparer} over one schema and prints the
 * report. Options fall back to `config/postgres-rls.php`. Run it as the schema owner.
 */
class PrepareCommand extends Command
{
    protected $signature = 'postgres-rls:prepare
        {schema : The schema whose tables to prepare}
        {--connection= : The connection to run on (the default connection when omitted)}
        {--column= : The discriminator column (config: postgres-rls.column)}
        {--setting= : The namespaced session setting the column defaults from (config: postgres-rls.setting)}
        {--exclude=* : Tables to leave untouched (config: postgres-rls.exclude)}
        {--force : FORCE ROW LEVEL SECURITY, making the table owner subject to the policy too}';

    protected $description = 'Add the discriminator column, enable row level security and install the policy on every table in a schema';

    public function handle(ConnectionResolverInterface $db, Repository $config): int
    {
        $connection = $db->connection($this->option('connection') ?: null);

        $preparer = SchemaPreparer::fromConfig(
            $connection,
            (string) $this->argument('schema'),
            (array) $config->get('postgres-rls', []),
            [
                'column' => $this->option('column') ?: null,
                'setting' => $this->option('setting') ?: null,
                'exclude' => $this->option('exclude') ?: null,
                'force' => $this->option('force') ? true : null,
            ],
        );

        $report = $preparer->prepare();

        foreach ($report->lines() as $line) {
            $this->line($line);
        }

        return self::SUCCESS;
    }
}
