<?php

declare(strict_types=1);

namespace Portfolio\Support;

/**
 * Portable Unicode 15.1 canonical NFC for small health sentinels and page text.
 * Generated canonical decomposition, composition exclusions and combining-class
 * tables come from UnicodeData via Python's unicodedata 15.1; Hangul is algorithmic.
 * Full NFC rules are applied even when ext-intl is unavailable.
 */
final class PortableNfc
{
    private const S_BASE = 0xAC00;
    private const L_BASE = 0x1100;
    private const V_BASE = 0x1161;
    private const T_BASE = 0x11A7;
    private const L_COUNT = 19;
    private const V_COUNT = 21;
    private const T_COUNT = 28;
    private const N_COUNT = 588;
    private const S_COUNT = 11172;

    private static ?array $tables = null;

    private static function tables(): array
    {
        if (self::$tables === null) {
            $raw = file_get_contents(dirname(__DIR__, 2) . '/resources/unicode-nfc.json');
            if ($raw === false) { throw new \RuntimeException('Unicode normalization tables unavailable.'); }
            self::$tables = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        }
        return self::$tables;
    }

    private static function ord(string $char): int
    {
        $a = ord($char[0]);
        if ($a < 0x80) { return $a; }
        $b = ord($char[1]) & 0x3f;
        if ($a < 0xe0) { return (($a & 0x1f) << 6) | $b; }
        $c = ord($char[2]) & 0x3f;
        if ($a < 0xf0) { return (($a & 0x0f) << 12) | ($b << 6) | $c; }
        return (($a & 7) << 18) | ($b << 12) | ($c << 6) | (ord($char[3]) & 0x3f);
    }

    private static function chr(int $code): string
    {
        if ($code < 0x80) { return chr($code); }
        if ($code < 0x800) { return chr(0xc0 | ($code >> 6)) . chr(0x80 | ($code & 63)); }
        if ($code < 0x10000) {
            return chr(0xe0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 63)) . chr(0x80 | ($code & 63));
        }
        return chr(0xf0 | ($code >> 18)) . chr(0x80 | (($code >> 12) & 63)) .
            chr(0x80 | (($code >> 6) & 63)) . chr(0x80 | ($code & 63));
    }

    private static function decompose(int $cp, array $table, array &$out): void
    {
        $index = $cp - self::S_BASE;
        if ($index >= 0 && $index < self::S_COUNT) {
            $l = intdiv($index, self::N_COUNT);
            $v = intdiv($index % self::N_COUNT, self::T_COUNT);
            $t = $index % self::T_COUNT;
            $out[] = self::L_BASE + $l;
            $out[] = self::V_BASE + $v;
            if ($t !== 0) { $out[] = self::T_BASE + $t; }
            return;
        }
        if (isset($table[(string) $cp])) {
            foreach ($table[(string) $cp] as $part) { self::decompose($part, $table, $out); }
        } else { $out[] = $cp; }
    }

    private static function combine(int $a, int $b, array $table): ?int
    {
        $l = $a - self::L_BASE;
        $v = $b - self::V_BASE;
        if ($l >= 0 && $l < self::L_COUNT && $v >= 0 && $v < self::V_COUNT) {
            return self::S_BASE + ($l * self::V_COUNT + $v) * self::T_COUNT;
        }
        $s = $a - self::S_BASE;
        $t = $b - self::T_BASE;
        if ($s >= 0 && $s < self::S_COUNT && $s % self::T_COUNT === 0 &&
            $t > 0 && $t < self::T_COUNT) { return $a + $t; }
        return $table[$a . ',' . $b] ?? null;
    }

    public static function normalize(string $text): string
    {
        if (preg_match('//u', $text) !== 1) {
            throw new \InvalidArgumentException('Invalid UTF-8 cannot be normalized.');
        }
        if (preg_match('/[\x80-\xFF]/', $text) !== 1) { return $text; }
        $tables = self::tables();
        $decomposed = [];
        foreach (preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $char) {
            self::decompose(self::ord($char), $tables['decompose'], $decomposed);
        }
        // Canonical ordering: stable insertion sort among non-starter marks.
        $ordered = [];
        foreach ($decomposed as $cp) {
            $cc = $tables['combining_class'][(string) $cp] ?? 0;
            $at = count($ordered);
            if ($cc !== 0) {
                while ($at > 0 && ($tables['combining_class'][(string) $ordered[$at - 1]] ?? 0) > $cc) { --$at; }
            }
            array_splice($ordered, $at, 0, [$cp]);
        }
        $out = [];
        $starterPos = null;
        $lastClass = 0;
        foreach ($ordered as $cp) {
            $cc = $tables['combining_class'][(string) $cp] ?? 0;
            $combined = $starterPos === null ? null : self::combine($out[$starterPos], $cp, $tables['compose']);
            if ($combined !== null && ($lastClass < $cc || $lastClass === 0)) {
                $out[$starterPos] = $combined;
                continue;
            }
            if ($cc === 0) { $starterPos = count($out); }
            $out[] = $cp;
            $lastClass = $cc;
        }
        return implode('', array_map(self::chr(...), $out));
    }
}
