<?php

declare(strict_types=1);

namespace Portfolio\Monitoring;

/**
 * Single conservative interpreter of inline presentation attributes for both
 * evidence of health and evidence of failure. This is not browser computed CSS.
 * Any declaration that can affect whether text is rendered but cannot be
 * interpreted reliably makes the WHOLE observation unverified.
 */
final class InlineVisibility
{
    /** @return array{hidden:bool,visibility:?bool} */
    public static function interpret(string $raw): array
    {
        if (substr_count($raw, '/*') !== substr_count($raw, '*/') ||
            str_contains($raw, '\\') || preg_match('/(?:var|calc|env|clamp|min|max)\s*\(/i', $raw)) {
            throw new MalformedHtmlException('Ambiguous inline CSS cannot establish health.');
        }
        $style = preg_replace('~/\*.*?\*/~s', '', $raw);
        if ($style === null) { throw new MalformedHtmlException('Unparseable CSS.'); }
        $rules = [];
        foreach (explode(';', $style) as $piece) {
            if (trim($piece) === '') { continue; }
            if (!preg_match('/\A\s*([a-z-]+)\s*:\s*(.*?)\s*\z/isD', $piece, $m)) {
                throw new MalformedHtmlException('Unsupported CSS declaration.');
            }
            $key = strtolower($m[1]);
            $value = trim(strtolower($m[2]));
            $important = preg_match('/!\s*important\s*\z/i', $value) === 1;
            $value = trim(preg_replace('/!\s*important\s*\z/i', '', $value) ?? $value);
            if (!isset($rules[$key]) || $important || !$rules[$key]['important']) {
                $rules[$key] = ['value' => $value, 'important' => $important];
            }
        }
        $hide = false;
        $visibility = null;
        foreach ($rules as $key => $rule) {
            $value = $rule['value'];
            if ($key === 'display') {
                if ($value === 'none') { $hide = true; }
                elseif (!preg_match('/\A(?:block|inline|inline-block|flex|grid|table|contents|list-item)\z/', $value)) {
                    throw new MalformedHtmlException('Unsupported display expression.');
                }
            } elseif ($key === 'visibility') {
                if (in_array($value, ['hidden', 'collapse'], true)) { $visibility = false; }
                elseif ($value === 'visible') { $visibility = true; }
                else { throw new MalformedHtmlException('Unsupported visibility expression.'); }
            } elseif ($key === 'content-visibility') {
                if ($value === 'hidden') { $hide = true; }
                elseif ($value !== 'visible') { throw new MalformedHtmlException('Unsupported content visibility.'); }
            } elseif ($key === 'opacity') {
                // CSS accepts percentages and exponent notation; fully transparent
                // text cannot be positive health evidence.
                if (!preg_match('/\A([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(%)?\z/i', $value, $num)) {
                    throw new MalformedHtmlException('Unsupported opacity expression.');
                }
                if ((float) $num[1] <= 0.0) { $hide = true; }
            } elseif (in_array($key, [
                'filter', 'backdrop-filter', 'transform', 'scale', 'clip', 'clip-path',
                'mask', 'mask-image', 'mask-position', 'mask-size', 'height', 'width',
                'max-height', 'max-width', 'overflow', 'text-indent', 'font-size',
                'color', 'position', 'left', 'top', 'z-index', 'animation', 'transition',
                'contain', 'content', 'white-space', 'writing-mode', 'text-shadow'
            ], true) || str_starts_with($key, '--')) {
                throw new MalformedHtmlException('Layout-dependent CSS cannot establish health.');
            } else {
                // An unrecognized property may hide text (font shorthands,
                // custom layout modules, etc.). Never silently treat it as
                // visible just because it is not on a short denylist.
                throw new MalformedHtmlException('Unsupported CSS property cannot establish health.');
            }
        }
        return ['hidden' => $hide, 'visibility' => $visibility];
    }
}
