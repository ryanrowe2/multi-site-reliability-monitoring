<?php

declare(strict_types=1);

namespace Portfolio\Support;

use InvalidArgumentException;

/** Detect duplicate JSON object members (including escaped Unicode aliases) before lossy decoding. */
final class UniqueJsonKeys
{
    public static function assertUnique(string $raw): void
    {
        /** @var list<array{object:bool,expect_key:bool,seen:array<string,bool>}> $stack */
        $stack = [];
        $length = strlen($raw);
        for ($i = 0; $i < $length; ++$i) {
            $char = $raw[$i];
            if ($char === '"') {
                $start = $i++;
                for (; $i < $length; ++$i) {
                    if ($raw[$i] === '\\') {
                        ++$i; // Skip escaped quote or escaped backslash.
                    } elseif ($raw[$i] === '"') {
                        break;
                    }
                }
                if ($i >= $length) {
                    throw new InvalidArgumentException('Unterminated JSON string.');
                }
                $last = count($stack) - 1;
                if ($last >= 0 && $stack[$last]['object'] && $stack[$last]['expect_key']) {
                    $key = json_decode(substr($raw, $start, $i - $start + 1), true, 512, JSON_THROW_ON_ERROR);
                    if (!is_string($key) || isset($stack[$last]['seen'][$key])) {
                        throw new InvalidArgumentException('Duplicate JSON object member; state unchanged.');
                    }
                    $stack[$last]['seen'][$key] = true;
                    $stack[$last]['expect_key'] = false;
                }
                continue;
            }
            if ($char === '{' || $char === '[') {
                $stack[] = ['object' => $char === '{', 'expect_key' => $char === '{', 'seen' => []];
            } elseif ($char === '}' || $char === ']') {
                array_pop($stack);
            } elseif ($char === ',' && $stack !== []) {
                $last = count($stack) - 1;
                if ($stack[$last]['object']) {
                    $stack[$last]['expect_key'] = true;
                }
            }
        }
    }
}
