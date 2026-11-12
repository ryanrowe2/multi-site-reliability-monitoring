<?php

declare(strict_types=1);

namespace Portfolio\Integrity;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;

final class DirectoryFingerprint
{
    public static function hash(string $directory): string
    {
        if (!is_dir($directory) || is_link($directory)) {
            throw new RuntimeException('Fingerprint root missing or a symlink.');
        }
        $root = realpath($directory);
        if ($root === false) {
            throw new RuntimeException('Cannot resolve fingerprint root.');
        }
        $entries = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $file) {
            if ($file->isLink()) {
                throw new RuntimeException('Symlinks are not permitted in fingerprint inputs.');
            }
            $path = $file->getPathname();
            $relative = substr($path, strlen($root) + 1);
            if ($file->isDir()) {
                $entries['d:' . $relative] = '';
            } elseif ($file->isFile() && is_readable($path)) {
                $digest = @hash_file('sha256', $path);
                if ($digest === false) {
                    throw new RuntimeException('Cannot hash a file.');
                }
                $entries['f:' . $relative] = $digest;
            } else {
                throw new RuntimeException('Unreadable or unsupported filesystem entry.');
            }
        }
        ksort($entries, SORT_STRING);
        return hash('sha256', json_encode($entries, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }
}
