<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use Portfolio\Support\StaticSvgValidator;

$directory = realpath($argv[1] ?? dirname(__DIR__) . '/diagrams');
if ($directory === false || !is_dir($directory)) {
    fwrite(STDERR, "Missing SVG diagram directory.\n");
    exit(1);
}
$count = 0;
$failed = [];
foreach (new DirectoryIterator($directory) as $file) {
    if ($file->isDot()) { continue; }
    if (!$file->isFile() || strtolower($file->getExtension()) !== 'svg') {
        $failed[] = $file->getFilename() . ': unexpected diagram entry';
        continue;
    }
    ++$count;
    $content = file_get_contents($file->getPathname());
    if ($content === false || !StaticSvgValidator::isWellFormed($content)) {
        $failed[] = $file->getFilename() . ': malformed static SVG XML';
    }
}
if ($count === 0) { $failed[] = 'No SVG diagrams found'; }
if ($failed !== []) {
    fwrite(STDERR, implode("\n", $failed) . "\n");
    exit(1);
}
echo "Validated {$count} static SVG diagrams.\n";
