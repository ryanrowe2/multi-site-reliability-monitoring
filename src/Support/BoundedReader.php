<?php

declare(strict_types=1);

namespace Portfolio\Support;

use InvalidArgumentException;

/** Read only regular files, rejecting oversize input before allocating it. */
final class BoundedReader
{
    public static function read(string $path, int $maxBytes): string
    {
        if ($maxBytes < 1 || is_link($path) || !is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException('Input must be a readable regular file.');
        }
        $size = @filesize($path);
        if ($size !== false && $size > $maxBytes) {
            throw new InvalidArgumentException('Input exceeds maximum permitted size.');
        }
        $file = @fopen($path, 'rb');
        if ($file === false) {
            throw new InvalidArgumentException('Cannot open input file.');
        }
        try {
            $stat = fstat($file);
            if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > $maxBytes) {
                throw new InvalidArgumentException('Input is not a bounded regular file.');
            }
            $buffer = '';
            do {
                $piece = fread($file, min(8192, $maxBytes + 1 - strlen($buffer)));
                if ($piece === false) {
                    throw new InvalidArgumentException('Input read failed.');
                }
                $buffer .= $piece;
                if (strlen($buffer) > $maxBytes) {
                    throw new InvalidArgumentException('Input exceeds maximum permitted size.');
                }
                if ($piece === '' && !feof($file)) {
                    throw new InvalidArgumentException('Input read stalled.');
                }
            } while (!feof($file));
            return $buffer;
        } finally {
            fclose($file);
        }
    }
}
