<?php

declare(strict_types=1);

namespace Portfolio\Support;

/**
 * XML well-formedness for the intentionally narrow, static SVG publication
 * subset. No DTD, entities, processing instructions or external resolution.
 * This is a strict lexical validator, not a general XML 1.0 parser. The
 * release scanner independently rejects active/externally loaded content.
 */
final class StaticSvgValidator
{
    public static function isWellFormed(string $xml): bool
    {
        if (strlen($xml) > 5_000_000 || str_contains($xml, '&') || str_contains($xml, '\\') ||
            preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $xml) === 1 ||
            preg_match('//u', $xml) !== 1) {
            return false;
        }
        $length = strlen($xml);
        $position = 0;
        $stack = [];
        $roots = 0;
        $namespaces = ['xml' => 'http://www.w3.org/XML/1998/namespace'];
        while ($position < $length) {
            $start = strpos($xml, '<', $position);
            if ($start === false) {
                return trim(substr($xml, $position)) === '' && $stack === [] && $roots === 1;
            }
            if ($stack === [] && trim(substr($xml, $position, $start - $position)) !== '') {
                return false;
            }
            if (substr($xml, $start, 4) === '<!--') {
                $end = strpos($xml, '-->', $start + 4);
                if ($end === false || str_contains(substr($xml, $start + 4, $end - ($start + 4)), '--')) {
                    return false;
                }
                $position = $end + 3;
                continue;
            }
            // Reject DTD, CDATA and all processing instructions. The packaged
            // diagrams do not need them and rejecting them avoids XXE.
            if (substr($xml, $start, 2) === '<!' || substr($xml, $start, 2) === '<?') {
                return false;
            }
            $quote = null;
            $end = null;
            for ($i = $start + 1; $i < $length; ++$i) {
                $c = $xml[$i];
                if ($quote !== null) {
                    if ($c === $quote) { $quote = null; }
                } elseif ($c === '"' || $c === "'") {
                    $quote = $c;
                } elseif ($c === '<') {
                    return false;
                } elseif ($c === '>') {
                    $end = $i;
                    break;
                }
            }
            if ($end === null) { return false; }
            $markup = substr($xml, $start, $end - $start + 1);
            if (str_starts_with($markup, '</')) {
                if (preg_match('~^</([A-Za-z_][A-Za-z0-9_.:-]*)\s*>$~D', $markup, $closing) !== 1 ||
                    array_pop($stack) !== $closing[1]) {
                    return false;
                }
            } else {
                if (preg_match('~^<([A-Za-z_][A-Za-z0-9_.:-]*)~', $markup, $opening) !== 1) {
                    return false;
                }
                $name = $opening[1];
                if (str_contains($name, ':')) {
                    [$prefix] = explode(':', $name, 2);
                    if (!isset($namespaces[$prefix])) { return false; }
                }
                if ($stack === []) {
                    if ($name !== 'svg' || $roots !== 0) { return false; }
                    ++$roots;
                }
                $attributes = substr($markup, 1 + strlen($name), -1);
                $selfClosing = str_ends_with(rtrim($attributes), '/');
                if ($selfClosing) { $attributes = substr(rtrim($attributes), 0, -1); }
                $offset = 0;
                $seen = [];
                $total = strlen($attributes);
                while ($offset < $total) {
                    if (trim(substr($attributes, $offset)) === '') { break; }
                    if (preg_match('/\G\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"<]*)"|\x27([^\x27<]*)\x27)/A',
                        $attributes, $match, 0, $offset) !== 1) {
                        return false;
                    }
                    if (strtolower($match[1]) === 'style') { return false; }
                    if (isset($seen[$match[1]])) { return false; }
                    $seen[$match[1]] = true;
                    $attributeName = $match[1];
                    $attributeValue = $match[2] !== '' ? $match[2] : ($match[3] ?? '');
                    if ($attributeName === 'xmlns') {
                        if ($name !== 'svg' || $attributeValue !== 'http://www.w3.org/2000/svg') { return false; }
                        $namespaces[''] = $attributeValue;
                    } elseif (str_starts_with($attributeName, 'xmlns:')) {
                        // Custom prefix declarations are outside the allowed static subset.
                        return false;
                    } elseif (str_contains($attributeName, ':')) {
                        [$prefix] = explode(':', $attributeName, 2);
                        if (!isset($namespaces[$prefix])) { return false; }
                    }
                    $offset += strlen($match[0]);
                }
                if ($name === 'svg' && $roots === 1 && !isset($namespaces[''])) { return false; }
                if (!$selfClosing) { $stack[] = $name; }
            }
            $position = $end + 1;
        }
        return $stack === [] && $roots === 1;
    }
}
