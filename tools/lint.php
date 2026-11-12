<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$dirs = [$root . '/src', $root . '/bin', $root . '/tests', $root . '/tools', $root . '/examples/fixtures'];
$count = 0;
foreach ($dirs as $dir) {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }
        $command = escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file->getPathname());
        exec($command . ' 2>&1', $output, $code);
        if ($code !== 0) {
            fwrite(STDERR, implode("\n", $output) . PHP_EOL);
            exit(1);
        }
        $output = [];
        $count++;
    }
}
echo "Syntax-valid PHP files: {$count}\n";
