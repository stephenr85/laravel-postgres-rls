<?php

namespace Rushing\PostgresRls\Tests;

use PHPUnit\Framework\TestCase as PhpUnit;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * The consumer of `extra.package-topology.sourceNeverReferences` in composer.json, asserted here
 * rather than left to a consuming app's topology test: a `Splicewire\`, `Schemastud\` or `Stancl\`
 * symbol in `src/`, or a `Tenant`/`Beam` word in a code identifier, would be the host vocabulary
 * this package exists to stay free of, whether or not composer.json ever declares the edge.
 *
 * Token scan, not a substring scan: comments and string literals are ignored, so a docblock may
 * SAY "stancl/tenancy v4" as prior art and a default may be the string 'tenant_id' — describing
 * the seam is not crossing it. Modelled on laravel-beam-tenancy's CommerceSeamGuardTest, without
 * the graphine dependency (this package requires illuminate/* only).
 *
 * Plain PHPUnit, deliberately not the Postgres-backed TestCase: the scan needs no database.
 */
class TopologySeamGuardTest extends PhpUnit
{
    private const FORBIDDEN_PREFIXES = ['Splicewire\\', 'Schemastud\\', 'Stancl\\'];

    private const FORBIDDEN_WORDS = '/Tenant|Beam/';

    public function test_src_references_no_host_namespace_and_no_host_vocabulary(): void
    {
        $offenders = [];

        foreach ($this->sourceFiles() as $file) {
            foreach ($this->offendersIn((string) file_get_contents($file)) as $offender) {
                $offenders[] = basename($file).': '.$offender;
            }
        }

        $this->assertSame([], $offenders);
    }

    public function test_the_scan_catches_a_reference_in_code_and_ignores_prose(): void
    {
        $snippet = <<<'PHP'
            <?php
            namespace Rushing\PostgresRls;

            use Stancl\Tenancy\Tenant;

            /** Prior art: stancl/tenancy v4, Splicewire\Beam\Tenancy\Tenant. */
            final class Probe
            {
                public string $column = 'tenant_id';

                public function forTenant(\Splicewire\Beam\Tenant $tenant): void {}

                public function fine(string $setting = 'Beam\\Thing'): void {}
            }
            PHP;

        $this->assertSame(
            ['Stancl\Tenancy\Tenant', 'forTenant', '\Splicewire\Beam\Tenant'],
            $this->offendersIn($snippet),
        );
    }

    /**
     * @return list<string>
     */
    private function offendersIn(string $source): array
    {
        $offenders = [];

        foreach (token_get_all($source) as $token) {
            if (! is_array($token)) {
                continue;
            }

            [$id, $text] = $token;

            $isName = in_array($id, [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE], true);

            if (! $isName) {
                continue;
            }

            $bare = ltrim($text, '\\');

            foreach (self::FORBIDDEN_PREFIXES as $prefix) {
                if (str_starts_with($bare, $prefix)) {
                    $offenders[] = $text;

                    continue 2;
                }
            }

            if (preg_match(self::FORBIDDEN_WORDS, $bare)) {
                $offenders[] = $text;
            }
        }

        return $offenders;
    }

    /**
     * @return list<string>
     */
    private function sourceFiles(): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../src'));

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        sort($files);
        $this->assertNotEmpty($files, 'the scan must find src/ or it proves nothing');

        return $files;
    }
}
