<?php

namespace Rushing\PostgresRls\Query;

use Illuminate\Database\Query\Grammars\PostgresGrammar;

/**
 * Laravel's Postgres query grammar with {@see ScopesConflictTargets}.
 */
class ScopedPostgresGrammar extends PostgresGrammar
{
    use ScopesConflictTargets;
}
