<?php

declare(strict_types=1);

namespace Portfolio\Monitoring;

/**
 * Inspect bounded HTML as an ordered stream of structural text regions.
 * A page-level documentation hint must never suppress an error in an
 * independent section. This is an offline HTML approximation, not a browser.
 */
final class HtmlFaultDetector
{
    /** @return ?string One of the supported application-error categories. */
    public static function detect(string $html): ?string
    {
        $regions = self::regions($html);
        $ambiguous = false;
        foreach ($regions as $index => $region) {
            $text = self::normalize($region['text']);
            if ($text === '' || $region['excluded']) {
                continue;
            }
            $code = self::fault($text);
            if ($code === null) {
                // A recognizable but unsupported *error heading* must not
                // establish recovery merely because its vendor-specific text
                // is absent from our exact template catalog. Stay unknown.
                if (!preg_match('/\b(?:how to|guide to|tutorial|documentation)\b/i', $text) && !$region['pre'] && in_array($region['tag'], ['h1','h2','h3','h4','h5','h6','p','div','root'], true) &&
                    preg_match('/\A(?:(?:http\s+(?:(?:error|status)\s*)?)?(?:50[0-9])\b|(?:server|database|wordpress)\s+(?:error|failure)\b|(?:critical|fatal)\s+error\b)/i', $text)) {
                    $ambiguous = true;
                }
                continue;
            }
            // Prefixes are also used as headings in documentation. Apply the
            // same explicit instructional-context rules to every banner.
            if (self::illustrative($regions, $index, $code)) {
                $next = $regions[$index + 1] ?? null;
                if ($next && preg_match('/\Athis guide explains how to fix\b/i', self::normalize($next['text']))) {
                    $ambiguous = true;
                    continue;
                }
                if (in_array($code, ['internal_server_error', 'service_unavailable', 'bad_gateway', 'gateway_timeout'], true)) {
                    // Nearby documentation does not negate a visible server error;
                    // without browser context its meaning is genuinely unknown.
                    $ambiguous = true;
                    continue;
                }
                continue;
            }
            // A bare preformatted database/WordPress string may be a published
            // example or a real error. Without corroborating page context it
            // cannot establish either a failure or a recovery.
            if ($region['pre'] && (in_array($code, ['database_error', 'wp_critical_error'], true) ||
                self::preformattedExample($regions, $index))) {
                $ambiguous = true;
                continue;
            }
            return $code;
        }
        return $ambiguous ? 'ambiguous_error_example' : null;
    }

    /** @return list<array{text:string,section:int,excluded:bool,pre:bool,tag:string}> */
    private static function regions(string $html): array
    {
        $parts = Classifier::htmlTokens($html);
        $regions = [];
        $stack = [];
        $sequence = 0;
        $buffer = '';
        $context = null;
        $blocks = ['html','body','main','article','section','div','p','li','ul','ol','pre','h1','h2','h3','h4','h5','h6',
            'header','footer','nav','aside','blockquote','table','tr','td','th','form'];
        $flush = static function () use (&$buffer, &$context, &$regions): void {
            if ($buffer !== '' && $context !== null) {
                $regions[] = ['text' => $buffer, 'section' => $context['section'], 'excluded' => $context['excluded'],
                    'pre' => $context['pre'], 'tag' => $context['tag']];
            }
            $buffer = '';
            $context = null;
        };
        foreach ($parts as $part) {
            if (!$part['tag']) {
                $top = count($stack) ? $stack[count($stack) - 1] : null;
                if ($top !== null && ($top['hidden'] || !$top['visible'])) {
                    continue;
                }
                if ($context === null) {
                    $lastBlock = null;
                    foreach (array_reverse($stack) as $frame) {
                        if (in_array($frame['tag'], $blocks, true)) {
                            $lastBlock = $frame['tag'];
                            break;
                        }
                    }
                    $context = ['section' => $top['section'] ?? 0, 'excluded' => $top['excluded'] ?? false,
                        'pre' => $top['pre'] ?? false,
                        'tag' => $lastBlock ?? 'root'];
                }
                $buffer .= html_entity_decode($part['value'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
                continue;
            }
            if (!preg_match('~^<\s*(/?)\s*([a-z][a-z0-9-]*)\b~i', $part['value'], $match)) {
                continue;
            }
            $tag = strtolower($match[2]);
            // Inline links within a displayed heading belong to that heading's
            // text. Elsewhere link titles alone are not application failures.
            $inHeading = false;
            foreach ($stack as $ancestor) {
                if (in_array($ancestor['tag'], ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], true)) {
                    $inHeading = true;
                }
            }
            $headingAnchor = $tag === 'a' && $inHeading;
            $block = in_array($tag, $blocks, true) ||
                ($tag === 'a' && !$headingAnchor) || in_array($tag, ['code', 'textarea'], true);
            if ($tag === 'br') {
                $buffer .= ' ';
            }
            if ($block) {
                $flush();
            }
            if ($match[1] === '/') {
                for ($i = count($stack) - 1; $i >= 0; --$i) {
                    if ($stack[$i]['tag'] === $tag) {
                        $stack = array_slice($stack, 0, $i);
                        break;
                    }
                }
                continue;
            }
            $attrs = Classifier::parseAttributes(substr($part['value'], strlen($match[0]), -1));
            $style = html_entity_decode($attrs['style'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
            Classifier::assertSupportedInlineStyle($style);
            $styleInfo = InlineVisibility::interpret($style);
            $parent = count($stack) ? $stack[count($stack) - 1] : null;
            $parentHidden = $parent['hidden'] ?? false;
            if ($tag === 'summary' && $parent !== null && $parent['tag'] === 'details' &&
                $parent['details_summary_allowed'] && !$parent['summary_seen']) {
                $parentHidden = $parent['hidden_before_details'];
                $stack[count($stack) - 1]['summary_seen'] = true;
            }
            $visible = $parent['visible'] ?? true;
            if (array_key_exists('class', $attrs) || $tag === 'style' ||
                ($tag === 'link' && strtolower($attrs['rel'] ?? '') === 'stylesheet')) {
                throw new MalformedHtmlException('CSS selectors cannot establish display status.');
            }
            if ($styleInfo['visibility'] !== null) { $visible = $styleInfo['visibility']; }
            $explicitlyConcealed = array_key_exists('hidden', $attrs) ||
                strtolower(trim($attrs['aria-hidden'] ?? '')) === 'true' ||
                $styleInfo['hidden'];
            $hidden = $parentHidden || $explicitlyConcealed || Classifier::isNonRenderedElement($tag, $attrs) ||
                ($tag === 'dialog' && !array_key_exists('open', $attrs)) ||
                ($tag === 'details' && !array_key_exists('open', $attrs));
            $section = $parent['section'] ?? 0;
            if (in_array($tag, ['main','article','section'], true)) {
                $section = ++$sequence;
            }
            $excluded = ($parent['excluded'] ?? false) ||
                in_array($tag, ['nav','footer','aside','code','textarea','script','style','head','title'], true) ||
                ($tag === 'a' && !$headingAnchor);
            $frame = ['tag'=>$tag,'hidden'=>$hidden,'visible'=>$visible,'excluded'=>$excluded,
                'details_closed'=>$tag === 'details' && !array_key_exists('open',$attrs),
                'details_summary_allowed'=>$tag === 'details' && !array_key_exists('open',$attrs) && !$explicitlyConcealed,
                'hidden_before_details'=>$parentHidden,'summary_seen'=>false,
                'section'=>$section,'pre'=>($parent['pre'] ?? false) || $tag === 'pre'
            ];
            if (!str_ends_with(rtrim($part['value']), '/>') && !Classifier::isVoidTag($tag)) {
                $stack[] = $frame;
            }
        }
        $flush();
        return $regions;
    }

    private static function fault(string $line): ?string
    {
        // A heading explicitly introducing an instructional guide is not an error banner.
        if (preg_match('/\b(?:how to|guide to|tutorial|documentation|example of)\b/i', $line) &&
            preg_match('/\b(?:troubleshoot|fix|understand|debug)\b/i', $line)) {
            return null;
        }
        // A prefix is common on real error templates; tutorial text typically
        // discusses the error in a sentence rather than displaying the banner.
        if (preg_match('/\A(?:database\s+(?:error|failure)\s*:\s*)?error establishing a database connection[.!]?(?:\s+.*)?\z/i', $line)) {
            return 'database_error';
        }
        if (preg_match('/\A(?:wordpress\s+(?:error|failure)\s*:\s*)?there has been a critical error on this website[.!]?(?:\s+.*)?\z/i', $line)) {
            return 'wp_critical_error';
        }
        if (preg_match('/\A(?:PHP\s+)?fatal error:\s*(?:uncaught|call to undefined|allowed memory size|cannot redeclare|declaration|failed opening|required|class .* not found)\b/i', $line)) {
            return 'php_fatal_error';
        }
        if (preg_match('/\A(?:500\s*[-:]?\s*|http\s+error\s+500[.\s]+)?internal server error\b(?:[.!:]?(?:\s+.*)?)?\z/i', $line)) {
            return 'internal_server_error';
        }
        if (preg_match('/\A(?:http\s+error\s+)?503\s*[.: -]+\s*the service is unavailable\b(?:[.!:]?(?:\s+.*)?)?\z/i', $line)) {
            return 'service_unavailable';
        }
        if (preg_match('/\A(?:503\s+)?service (?:temporarily\s+)?unavailable\b(?:[.!:]?(?:\s+.*)?)?\z/i', $line)) {
            return 'service_unavailable';
        }
        if (preg_match('/\A(?:502\s+)?bad gateway\b(?:[.!:]?(?:\s+.*)?)?\z/i', $line)) {
            return 'bad_gateway';
        }
        if (preg_match('/\A(?:504\s+)?gateway time(?:-|\s*)out\b(?:[.!:]?(?:\s+.*)?)?\z/i', $line)) {
            return 'gateway_timeout';
        }
        return null;
    }

    /** @param list<array{text:string,section:int,excluded:bool,pre:bool,tag:string}> $regions */
    private static function preformattedExample(array $regions, int $index): bool
    {
        foreach ([-2,-1,1,2] as $offset) {
            $neighbor = $regions[$index+$offset] ?? null;
            if ($neighbor && !$neighbor['excluded'] && $neighbor['section'] === $regions[$index]['section'] &&
                preg_match('/\b(?:example|tutorial|guide|documentation|instruction)\b/i', self::normalize($neighbor['text']))) {
                return true;
            }
        }
        return false;
    }

    /** @param list<array{text:string,section:int,excluded:bool,pre:bool,tag:string}> $regions */
    private static function illustrative(array $regions, int $index, string $code): bool
    {
        $candidate = $regions[$index];
        // Server errors next to instructional text are ambiguous, not healthy;
        // the caller converts this case to unverified rather than recovery.
        $topic = match ($code) {
            'php_fatal_error' => 'php',
            'wp_critical_error' => 'wordpress|critical error',
            default => 'database|wordpress',
        };
        foreach ([-2, -1, 1, 2] as $distance) {
            $neighbor = $regions[$index + $distance] ?? null;
            if ($neighbor === null || $neighbor['excluded'] || $neighbor['section'] !== $candidate['section']) {
                continue;
            }
            $line = self::normalize($neighbor['text']);
            if ($candidate['pre'] && preg_match('/\A(?:help|support|documentation|examples?)\z/i', $line)) {
                return true;
            }
            $instructional = preg_match('/\A(?:in this (?:guide|article|tutorial)\b|this (?:guide|article|tutorial)\s+(?:explains|describes|shows|covers|teaches|walks|demonstrates)\b|(?:how to|understanding|fixing|guide to)\b)/i', $line) === 1;
            if (!$instructional) {
                continue;
            }
            // Following explanatory text immediately establishes the preceding
            // banner as an example. Previous generic instructions do not: an
            // actual outage may be rendered below an unrelated introduction.
            if ($distance > 0 || preg_match('/(?:' . $topic . ')/i', $line) === 1 ||
                in_array($code, ['internal_server_error', 'service_unavailable', 'bad_gateway', 'gateway_timeout'], true)) {
                return true;
            }
        }
        return false;
    }

    private static function normalize(string $text): string
    {
        return trim(preg_replace('/[\p{Z}\p{Cf}\s]+/u', ' ', $text) ?? $text);
    }
}
