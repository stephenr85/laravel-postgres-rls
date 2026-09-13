<?php

namespace Rushing\PostgresRls\Query;

use Tpetry\PostgresqlEnhanced\Query\Grammar;

/**
 * `tpetry/laravel-postgresql-enhanced`'s query grammar with {@see ScopesConflictTargets}. Loaded only
 * when that package's grammar is the connection's grammar, so this package does not require it.
 * Its `upsertReturning()` and `upsertPartial()` compile through `compileUpsert()` and are covered;
 * `insertOrIgnoreReturning($uniqueBy)` writes its own conflict clause and is not.
 */
class ScopedEnhancedGrammar extends Grammar
{
    use ScopesConflictTargets;
}
