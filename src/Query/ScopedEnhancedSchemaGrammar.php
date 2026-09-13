<?php

namespace Rushing\PostgresRls\Query;

use Tpetry\PostgresqlEnhanced\Schema\Grammars\Grammar;

/**
 * `tpetry/laravel-postgresql-enhanced`'s schema grammar with {@see ScopesForeignKeys}. Loaded only when
 * that package's grammar is the connection's, so this package does not require it.
 */
class ScopedEnhancedSchemaGrammar extends Grammar
{
    use ScopesForeignKeys;
}
