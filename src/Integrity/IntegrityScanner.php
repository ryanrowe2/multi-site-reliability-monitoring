<?php

declare(strict_types=1);

namespace Portfolio\Integrity;

use RuntimeException;
use Throwable;

/** Inspect only synthetic fixture sites; results are not proof that WordPress code executes. */
final class IntegrityScanner
{
    /** @param array<string,mixed> $config
     * @return array{issues:array<string,array{code:string,detail:string}>,fingerprints:array<string,string>,core_fingerprints:array<string,string>}
     */
    public static function scan(array $config): array
    {
        if (!is_string($config['core_baseline_sha256'] ?? null) ||
            !preg_match('/\A[a-f0-9]{64}\z/D', $config['core_baseline_sha256']) ||
            !is_string($config['baseline_sha256'] ?? null) ||
            !preg_match('/\A[a-f0-9]{64}\z/D', $config['baseline_sha256']) ||
            !is_string($config['update_lock_sha256'] ?? null) ||
            !preg_match('/\A[a-f0-9]{64}\z/D', $config['update_lock_sha256'])) {
            throw new RuntimeException('Approved fixture fingerprints are required.');
        }
        $root = $config['root'] ?? null;
        if (!is_string($root) || !is_dir($root) || is_link($root)) {
            throw new RuntimeException('Invalid fixture root.');
        }
        $resolvedRoot = realpath($root);
        if ($resolvedRoot === false) {
            throw new RuntimeException('Cannot resolve fixture root.');
        }
        $problems = [];
        $fingerprints = [];
        $coreFingerprints = [];
        foreach ($config['sites'] as $site) {
            try {
                $result = self::scanSite($resolvedRoot, $site, $config);
                $problems[$site] = $result['problems'];
                if ($result['fingerprint'] !== null) {
                    $fingerprints[$site] = $result['fingerprint'];
                }
                if ($result['core_fingerprint'] !== null) {
                    $coreFingerprints[$site] = $result['core_fingerprint'];
                }
            } catch (Throwable $e) {
                // Isolate a single invalid site without silently treating it as healthy.
                $message = strtolower($e->getMessage());
                $category = match (true) {
                    str_contains($message, 'symlink'), str_contains($message, 'escapes') => 'scan_error_unsafe_path',
                    str_contains($message, 'hash'), str_contains($message, 'fingerprint') => 'scan_error_hash',
                    str_contains($message, 'read'), str_contains($message, 'permission') => 'scan_error_unreadable',
                    str_contains($message, 'enumerate') => 'scan_error_enumeration',
                    default => 'scan_error_invalid_fixture',
                };
                // Intentionally do not expose filesystem paths or exception text.
                $problems[$site] = [$category];
            }
        }
        // Cross-site equality is supplemental; a known-good baseline is separately enforced.
        if (count(array_unique(array_values($fingerprints))) > 1) {
            foreach ($fingerprints as $site => $fingerprint) {
                // With an approved shared baseline, a matching site is known-good.
                // Do not report a per-site incident on that site because another
                // synthetic site diverged.
                if (!hash_equals($config['baseline_sha256'], $fingerprint)) {
                    $problems[$site][] = 'fleet_pro_fingerprint_divergence';
                }
            }
        }
        ksort($problems, SORT_STRING);
        ksort($fingerprints, SORT_STRING);
        ksort($coreFingerprints, SORT_STRING);
        $issues = [];
        foreach ($problems as $site => $codes) {
            if ($codes !== []) {
                sort($codes, SORT_STRING);
                $issues[$site] = ['code' => 'integrity_problem', 'detail' => implode(', ', array_unique($codes))];
            }
        }
        return ['issues' => $issues, 'fingerprints' => $fingerprints, 'core_fingerprints' => $coreFingerprints];
    }

    /** @param array<string,mixed> $config
     * @return array{problems:list<string>,fingerprint:?string,core_fingerprint:?string}
     */
    private static function scanSite(string $root, string $site, array $config): array
    {
        $siteDir = $root . DIRECTORY_SEPARATOR . $site;
        $plugins = $siteDir . '/wp-content/plugins';
        foreach ([$siteDir, $siteDir . '/wp-content', $plugins, $plugins . '/elementor',
            $plugins . '/elementor-pro', $siteDir . '/wp-content/mu-plugins'] as $component) {
            if (is_link($component)) {
                throw new RuntimeException('Symlink in a fixture site.');
            }
        }
        $siteReal = realpath($siteDir);
        if ($siteReal !== false && !str_starts_with($siteReal, $root . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Fixture site escapes root.');
        }
        $core = $plugins . '/elementor/elementor.php';
        $problems = [];
        $fingerprint = null;
        $coreFingerprint = null;
        if (!is_file($core) || is_link($core)) {
            $problems[] = 'missing_elementor_core';
        } else {
            if (self::headerVersion($core) !== $config['core_version']) {
                $problems[] = 'core_version_mismatch';
            }
            $coreFingerprint = DirectoryFingerprint::hash($plugins . '/elementor');
            if (!hash_equals($config['core_baseline_sha256'], $coreFingerprint)) {
                $problems[] = 'core_baseline_fingerprint_mismatch';
            }
        }
        $proDirs = glob($plugins . '/elementor-pro*', GLOB_ONLYDIR);
        if ($proDirs === false) {
            throw new RuntimeException('Cannot enumerate synthetic plugin directories.');
        }
        $expectedDir = $plugins . '/elementor-pro';
        if (count($proDirs) !== 1 || $proDirs[0] !== $expectedDir || !is_file($expectedDir . '/elementor-pro.php')) {
            $problems[] = 'invalid_pro_installation_count';
        } else {
            $proFile = $expectedDir . '/elementor-pro.php';
            if (is_link($proFile)) {
                throw new RuntimeException('Symlinked plugin entry.');
            }
            if (self::headerVersion($proFile) !== $config['pro_header_version']) {
                $problems[] = 'pro_header_version_mismatch';
            }
            if (self::runtimeVersion($proFile) !== $config['pro_runtime_version']) {
                $problems[] = 'pro_runtime_version_mismatch';
            }
            $fingerprint = DirectoryFingerprint::hash($expectedDir);
            if (isset($config['baseline_sha256']) && !hash_equals($config['baseline_sha256'], $fingerprint)) {
                $problems[] = 'pro_baseline_fingerprint_mismatch';
            }
        }
        $lock = $siteDir . '/wp-content/mu-plugins/' . $config['update_lock'];
        if (!is_file($lock) || is_link($lock)) {
            $problems[] = 'missing_update_lock';
        } elseif (filesize($lock) === 0) {
            $problems[] = 'empty_update_lock';
        } elseif (isset($config['update_lock_sha256'])) {
            $digest = hash_file('sha256', $lock);
            if ($digest === false) {
                throw new RuntimeException('Cannot hash update lock.');
            }
            if (!hash_equals($config['update_lock_sha256'], $digest)) {
                $problems[] = 'update_lock_fingerprint_mismatch';
            }
        }
        return ['problems' => $problems, 'fingerprint' => $fingerprint, 'core_fingerprint' => $coreFingerprint];
    }

    /** Parse a version only from an actual leading PHP block comment. */
    private static function headerVersion(string $file): ?string
    {
        $text = @file_get_contents($file, false, null, 0, 16384);
        if ($text === false) {
            throw new RuntimeException('Cannot read plugin header.');
        }
        $tokens = token_get_all($text);
        $seenOpen = false;
        $versions = [];
        foreach ($tokens as $token) {
            if (!is_array($token)) {
                break;
            }
            if ($token[0] === T_OPEN_TAG) {
                $seenOpen = true;
                continue;
            }
            if (!$seenOpen) {
                break;
            }
            if ($token[0] === T_WHITESPACE) {
                continue;
            }
            if ($token[0] !== T_COMMENT && $token[0] !== T_DOC_COMMENT) {
                break;
            }
            if (!str_starts_with(ltrim($token[1]), '/*')) {
                continue;
            }
            if (preg_match_all('/^[ \t]*\*?[ \t]*Version:[ \t]*([^\s*]+)/mi', $token[1], $matches)) {
                array_push($versions, ...$matches[1]);
            }
        }
        return count($versions) === 1 ? $versions[0] : null;
    }

    /**
     * Accept only a simple, top-level metadata declaration in a synthetic fixture.
     * This is strict source-shape validation, NOT a claim about PHP execution.
     * The independently required baseline hash attests all fixture contents.
     */
    private static function runtimeVersion(string $file): ?string
    {
        $text = @file_get_contents($file, false, null, 0, 16384);
        if ($text === false) {
            throw new RuntimeException('Cannot read plugin metadata.');
        }
        $tokens = [];
        foreach (token_get_all($text) as $token) {
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $tokens[] = $token;
        }
        // No conditionals, functions, other expressions, or unreachable branches.
        if (count($tokens) !== 8 || !is_array($tokens[0]) || $tokens[0][0] !== T_OPEN_TAG ||
            !is_array($tokens[1]) || $tokens[1][0] !== T_STRING || strtolower($tokens[1][1]) !== 'define' ||
            $tokens[2] !== '(' || $tokens[4] !== ',' || $tokens[6] !== ')' || $tokens[7] !== ';' ||
            !is_array($tokens[3]) || $tokens[3][0] !== T_CONSTANT_ENCAPSED_STRING ||
            !is_array($tokens[5]) || $tokens[5][0] !== T_CONSTANT_ENCAPSED_STRING) {
            return null;
        }
        $name = substr($tokens[3][1], 1, -1);
        return $name === 'ELEMENTOR_PRO_VERSION' ? substr($tokens[5][1], 1, -1) : null;
    }
}
