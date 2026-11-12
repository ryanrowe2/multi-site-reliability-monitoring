<?php

declare(strict_types=1);

namespace Portfolio\Support;

/**
 * Canonical Unicode comparison for the bounded offline monitor.
 * Uses ICU NFC when ext-intl is present; otherwise composes the common
 * Unicode Latin/Greek/Cyrillic canonical two-codepoint combinations.
 * Unsupported combinations remain byte-distinct; no lossy ASCII folding.
 */
final class CanonicalText
{
    public static function assertComparable(?string $sentinel): void
    {
        if ($sentinel !== null && preg_match('//u', $sentinel) !== 1) {
            throw new \InvalidArgumentException('Content sentinel must be valid UTF-8.');
        }
    }

    public static function normalize(string $text): string
    {
        if (class_exists(\Normalizer::class)) {
            $result = \Normalizer::normalize($text, \Normalizer::FORM_C);
            if (is_string($result)) { return $result; }
        }
        return PortableNfc::normalize($text);
    }
}
