<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Schema\Grammars\PostgresGrammar;

/**
 * Laravel's Postgres schema grammar with {@see ScopesForeignKeys}.
 */
class ScopedPostgresSchemaGrammar extends PostgresGrammar
{
    use ScopesForeignKeys;
}
