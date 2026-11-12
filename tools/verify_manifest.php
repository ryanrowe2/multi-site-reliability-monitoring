<?php

declare(strict_types=1);

/**
 * Fail closed unless a release manifest lists every published file exactly once,
 * excluding the manifest itself, and each recorded SHA-256 matches its bytes.
 * Run against the clean extracted ZIP or tracked-source release staging directory.
 */
try {
    if ($argc > 2) {
        throw new RuntimeException('Usage: php tools/verify_manifest.php [release-directory]');
    }
    $root = realpath($argv[1] ?? dirname(__DIR__));
    if ($root === false || !is_dir($root) || is_link($argv[1] ?? dirname(__DIR__))) {
        throw new RuntimeException('Release directory is invalid.');
    }
    $file = $root . '/MANIFEST.sha256';
    if (!is_file($file) || is_link($file) || filesize($file) > 200000) {
        throw new RuntimeException('Release manifest is missing or invalid.');
    }
    $contents = file($file, FILE_IGNORE_NEW_LINES);
    if ($contents === false || $contents === []) {
        throw new RuntimeException('Release manifest cannot be read.');
    }
    $expected = [];
    foreach ($contents as $line) {
        if (!preg_match('/\A([a-f0-9]{64})  (\S+)\z/D', $line, $parts)) {
            throw new RuntimeException('Malformed manifest entry.');
        }
        $relative = $parts[2];
        $segments = explode('/', $relative);
        if ($relative === 'MANIFEST.sha256' || str_starts_with($relative, '/') || str_contains($relative, '\\') ||
            in_array('', $segments, true) || in_array('.', $segments, true) || in_array('..', $segments, true) ||
            isset($expected[$relative])) {
            throw new RuntimeException('Unsafe or duplicate manifest entry.');
        }
        $expected[$relative] = $parts[1];
    }
    $actual = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $entry) {
        if ($entry->isLink()) {
            throw new RuntimeException('Release contains a symlink.');
        }
        if ($entry->isDir()) {
            continue;
        }
        if (!$entry->isFile()) {
            throw new RuntimeException('Release contains an unsupported entry.');
        }
        $relative = str_replace('\\', '/', substr($entry->getPathname(), strlen($root) + 1));
        if ($relative === 'MANIFEST.sha256') {
            continue;
        }
        if (!isset($expected[$relative])) {
            throw new RuntimeException('Unlisted file in release: ' . $relative);
        }
        $hash = @hash_file('sha256', $entry->getPathname());
        if ($hash === false || !hash_equals($expected[$relative], $hash)) {
            throw new RuntimeException('SHA-256 mismatch: ' . $relative);
        }
        $actual[$relative] = true;
    }
    if (count($actual) !== count($expected)) {
        throw new RuntimeException('Manifest lists a missing release file.');
    }
    echo 'Manifest verified: ' . count($actual) . " files.\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'Manifest verification failed: ' . $e->getMessage() . "\n");
    exit(1);
}
