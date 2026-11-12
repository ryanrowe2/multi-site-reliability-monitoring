<?php

declare(strict_types=1);

namespace Portfolio\Monitoring;

use InvalidArgumentException;

final class Classifier
{
    /**
     * @param array<string,mixed> $observation
     * @param array{min_body_bytes?:int,contains?:string|null} $policy
     * @return array{healthy:bool|null,code:string,detail:string,status_code:int|null}
     */
    public static function classify(string $host, array $observation, array $policy = []): array
    {
        foreach (array_keys($policy) as $name) {
            if (!is_string($name) || !in_array($name, ['min_body_bytes', 'contains', 'json_health'], true)) {
                throw new InvalidArgumentException('Unknown health-policy property.');
            }
        }
        if (array_key_exists('json_health', $policy) && $policy['json_health'] === null) {
            throw new InvalidArgumentException('JSON health contract must not be null.');
        }
        foreach (array_keys($observation) as $key) {
            if (!in_array($key, ['transport_error', 'status_code', 'redirect_location', 'body'], true)) {
                throw new InvalidArgumentException('Unexpected observation property.');
            }
        }
        $error = $observation['transport_error'] ?? null;
        if ($error !== null && !in_array($error, ['connection', 'tls', 'timeout'], true)) {
            throw new InvalidArgumentException('Invalid transport error.');
        }
        $status = $observation['status_code'] ?? null;
        if ($status !== null && (!is_int($status) || $status < 100 || $status > 599)) {
            throw new InvalidArgumentException('Invalid HTTP status code.');
        }
        $redirect = $observation['redirect_location'] ?? null;
        if ($redirect !== null && (!is_string($redirect) || strlen($redirect) > 2048 || strpbrk($redirect, "\r\n\0") !== false)) {
            throw new InvalidArgumentException('Invalid redirect Location header.');
        }
        $body = $observation['body'] ?? '';
        if (!is_string($body) || strlen($body) > 131072) {
            throw new InvalidArgumentException('Body must be a string of at most 128 KiB.');
        }
        if ($error !== null) {
            if ($status !== null || $redirect !== null || $body !== '') {
                throw new InvalidArgumentException('Transport failure cannot include an HTTP response.');
            }
            return self::problem('transport_' . $error, 'Transport ' . $error, null);
        }
        if ($status === null) {
            throw new InvalidArgumentException('Missing status_code.');
        }
        if (in_array($status, [301, 302, 303, 307, 308], true)) {
            if ($redirect === null || trim($redirect) === '') {
                return self::problem('unresolved_redirect', 'HTTP ' . $status . ' without Location', $status);
            }
            if (str_contains($redirect, '\\') || str_starts_with($redirect, '//')) {
                return self::problem('unsafe_redirect', 'Untrusted redirect authority or path', $status);
            }
            $parts = parse_url($redirect);
            if ($parts === false || isset($parts['user']) || isset($parts['pass'])) {
                return self::problem('unsafe_redirect', 'Malformed redirect', $status);
            }
            if (isset($parts['scheme']) || isset($parts['host'])) {
                if (!isset($parts['scheme'], $parts['host']) || strtolower((string) $parts['scheme']) !== 'https' ||
                    (isset($parts['port']) && $parts['port'] !== 443)) {
                    return self::problem('unsafe_redirect', 'Non-HTTPS or malformed redirect', $status);
                }
                $target = strtolower((string) $parts['host']);
                $normalize = static function (string $name): string {
                    $name = rtrim(strtolower($name), '.');
                    return str_starts_with($name, 'www.') ? substr($name, 4) : $name;
                };
                if ($normalize($target) !== $normalize($host)) {
                    return self::problem('unexpected_redirect', 'Redirect to a different host', $status);
                }
            } elseif (!isset($parts['path']) && !isset($parts['query']) && !isset($parts['fragment'])) {
                return self::problem('unsafe_redirect', 'Malformed relative redirect', $status);
            }
            // A safe Location by itself does not verify the redirected page. Unknown, not failed or recovered.
            return ['healthy' => null, 'code' => 'unverified_redirect', 'detail' => 'Destination has not been observed', 'status_code' => $status];
        }
        if ($status === 206) {
            // A partial representation cannot establish page health.
            return ['healthy' => null, 'code' => 'unverified_partial_response', 'detail' => 'HTTP 206 is not a complete representation', 'status_code' => $status];
        }
        if ($status >= 300 && $status < 400) {
            // 304 and other nonstandard 3xx responses do not prove a healthy page.
            return ['healthy' => null, 'code' => 'unverified_http_status', 'detail' => 'HTTP ' . $status . ' does not establish health', 'status_code' => $status];
        }
        if ($status < 200 || $status >= 400) {
            return self::problem('http_error', 'HTTP ' . $status, $status);
        }
        // 201 Created may legitimately supply Location; it is response metadata.
        // Enforce explicitly configured page assertions for every 2xx status.
        // Without assertions, legitimately empty 204/205 responses remain healthy.
        // Default website-page policy: an empty HTTP 200 is not proof of recovery.
        // Intentionally bodyless 204/205 remain valid unless an assertion is configured.
        // A website root is confirmed healthy by default only for a complete
        // HTTP 200 page. A deliberately bodyless 204/205 requires an explicit
        // per-host application policy; other success
        // statuses need an explicit application contract; without one their
        // semantics cannot close an earlier outage.
        $unverifiedSuccess = $status !== 200 && $policy === [];
        if ($policy !== [] && !array_key_exists('min_body_bytes', $policy) && !array_key_exists('contains', $policy) && !array_key_exists('json_health', $policy)) {
            throw new InvalidArgumentException('Empty content policy cannot establish health.');
        }
        $min = $policy['min_body_bytes'] ?? 1;
        if (!is_int($min) || $min < 0 || $min > 131072) {
            throw new InvalidArgumentException('Invalid minimum content requirement.');
        }
        $required = $policy['contains'] ?? null;
        if ($min === 0 && $required === null && !isset($policy['json_health'])) {
            throw new InvalidArgumentException('A zero-evidence policy cannot establish health.');
        }
        if ($required !== null && (!is_string($required) || $required === '')) {
            throw new InvalidArgumentException('Invalid content sentinel.');
        }
        \Portfolio\Support\CanonicalText::assertComparable($required);
        // A declared machine-readable endpoint contract avoids HTML/CSS
        // guesswork entirely. Only an explicit matching JSON field and an
        // HTTP 200 can establish health. No duplicate-key overwrites.
        $jsonHealth = $policy['json_health'] ?? null;
        if ($jsonHealth !== null) {
            if (!is_array($jsonHealth) || array_is_list($jsonHealth) ||
                count($jsonHealth) !== 2 || !is_string($jsonHealth['field'] ?? null) ||
                !preg_match('/\A[a-z][a-z0-9_]{0,63}\z/iD', $jsonHealth['field']) ||
                !is_string($jsonHealth['equals'] ?? null) || $jsonHealth['equals'] === '' ||
                strlen($jsonHealth['equals']) > 1000 || $required !== null) {
                throw new InvalidArgumentException('Invalid JSON health contract.');
            }
            if ($status !== 200) {
                return ['healthy' => null, 'code' => 'unverified_http_status',
                    'detail' => 'JSON health contract requires HTTP 200', 'status_code' => $status];
            }
            if (strlen($body) < $min || preg_match('//u', $body) !== 1) {
                return self::unverifiedHtml($status);
            }
            try {
                \Portfolio\Support\UniqueJsonKeys::assertUnique($body);
                $parsed = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
            } catch (\Throwable $e) { return self::unverifiedHtml($status); }
            if (!$parsed instanceof \stdClass || !property_exists($parsed, $jsonHealth['field'])) {
                return self::unverifiedHtml($status);
            }
            return $parsed->{$jsonHealth['field']} === $jsonHealth['equals']
                ? ['healthy' => true, 'code' => 'healthy', 'detail' => 'Explicit JSON health contract verified', 'status_code' => $status]
                : self::problem('content_assertion_failed', 'JSON health contract did not match', $status);
        }
        // Invalid encoding or ambiguous markup cannot prove recovery. The
        // result is unknown for this host; other hosts remain observable.
        if (preg_match('//u', $body) !== 1) {
            return self::unverifiedHtml($status);
        }
        try {
            // A browser-level meta refresh is navigation, not a verified response
            // from its destination; never close an active incident on this page.
            if (self::hasMetaRefresh($body)) {
                return ['healthy' => null, 'code' => 'unverified_redirect',
                    'detail' => 'HTML meta refresh destination was not observed', 'status_code' => $status];
            }
            $visible = self::visibleText($body);
            if ($visible !== '') {
                // A response with a recognizable application failure is not
                // healthy, regardless of an apparently successful HTTP code.
                $code = self::applicationError($body);
                if ($code === 'ambiguous_error_example') {
                    return self::unverifiedHtml($status);
                }
                if ($code !== null) {
                    return self::problem('application_' . $code, 'Critical application page: ' . $code, $status);
                }
            }
        } catch (MalformedHtmlException $e) {
            return self::unverifiedHtml($status);
        }
        if ($unverifiedSuccess) {
            return ['healthy' => null, 'code' => 'unverified_http_status',
                'detail' => 'Non-page success status has no explicit health contract', 'status_code' => $status];
        }
        // Unicode spaces and default-ignorable formatting characters do not make a
        // page meaningfully visible. Normalize both for minimum-length checks.
        $meaningful = preg_replace('/[\p{Z}\p{C}\s]+/u', ' ', $visible);
        if ($meaningful === null) {
            throw new InvalidArgumentException('Invalid UTF-8 visible content.');
        }
        $meaningful = trim($meaningful);
        if (strlen($meaningful) < $min || ($required !== null && !str_contains(self::normalizedText($visible), self::normalizedText($required)))) {
            return self::problem('content_assertion_failed', 'Configured content requirement not met', $status);
        }
        return ['healthy' => true, 'code' => 'healthy', 'detail' => 'Healthy HTTP response', 'status_code' => $status];
    }

    /**
     * Bounded, structural approximation of visible HTML text. This is NOT a
     * browser layout engine: classes, remote CSS and JavaScript are not run.
     * When strict visibility is needed a synthetic expected-text assertion is
     * still only an offline approximation of a rendered page.
     */
    private static function visibleText(string $html): string
    {
        // Lex markup with quote-aware tag boundaries: '>' inside a quoted
        // attribute is data, not the end of the tag.
        $pieces = self::htmlTokens($html);
        $stack = [];
        $hiddenCount = 0;
        $visibilityHidden = false;
        $output = '';
        $blocks = ['p', 'div', 'section', 'article', 'main', 'header', 'footer', 'nav', 'li', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
        foreach ($pieces as $token) {
            $piece = $token['value'];
            if (!$token['tag']) {
                if ($hiddenCount === 0 && !$visibilityHidden) {
                    $output .= html_entity_decode($piece, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                }
                continue;
            }
            if (!preg_match('~^<\s*(/?)\s*([a-z][a-z0-9-]*)\b~i', $piece, $match)) {
                continue;
            }
            $tag = strtolower($match[2]);
            $closing = $match[1] === '/';
            if ($closing) {
                // Malformed HTML cannot elevate text concealed by a still-open
                // hidden ancestor; only matched ancestors close that context.
                for ($i = count($stack) - 1; $i >= 0; --$i) {
                    if ($stack[$i]['tag'] === $tag) {
                        while (count($stack) > $i) {
                            $closed = array_pop($stack);
                            $hiddenCount -= (int) $closed['hidden'];
                            $hiddenCount += (int) ($closed['reveal'] ?? false);
                        }
                        break;
                    }
                }
                $visibilityHidden = count($stack) ? $stack[count($stack) - 1]['visibility_hidden'] : false;
                if ($hiddenCount === 0 && !$visibilityHidden && in_array($tag, $blocks, true)) {
                    $output .= "\n";
                }
                continue;
            }
            $attributes = self::parseAttributes(substr($piece, strlen($match[0]), -1));
            // Compare complete attribute names: data-style is not style,
            // and data-aria-hidden is not aria-hidden.
            $styleValue = html_entity_decode($attributes['style'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if (array_key_exists('class', $attributes) ||
                ($tag === 'link' && strtolower($attributes['rel'] ?? '') === 'stylesheet') ||
                $tag === 'style') {
                throw new MalformedHtmlException('External or selector CSS cannot prove rendered content.');
            }
            $styleInfo = InlineVisibility::interpret($styleValue);
            $invisibleStyle = $styleInfo['hidden'];
            $nextVisibilityHidden = $visibilityHidden;
            $visibilityOverride = $styleInfo['visibility'];
            if ($visibilityOverride !== null) {
                $nextVisibilityHidden = !$visibilityOverride;
            }
            $isClosedDialog = $tag === 'dialog' && !array_key_exists('open', $attributes);
            $isClosedDetails = $tag === 'details' && !array_key_exists('open', $attributes);
            // A closed <details> hides its contents, except its first direct <summary>.
            $revealSummary = false;
            $parentIndex = count($stack) - 1;
            if ($tag === 'summary' && $parentIndex >= 0 && $stack[$parentIndex]['tag'] === 'details' &&
                ($stack[$parentIndex]['details_summary_allowed'] ?? false) && !($stack[$parentIndex]['summary_seen'] ?? false)) {
                $stack[$parentIndex]['summary_seen'] = true;
                $revealSummary = true;
                $hiddenCount--;
            }
            $explicitlyConcealed = $invisibleStyle || array_key_exists('hidden', $attributes) ||
                strtolower(trim($attributes['aria-hidden'] ?? '')) === 'true';
            $isHidden = $isClosedDialog || $isClosedDetails ||
                self::isNonRenderedElement($tag, $attributes) ||
                $explicitlyConcealed ||
                ($tag === 'input' && strtolower($attributes['type'] ?? '') === 'hidden');
            if ($hiddenCount === 0 && !$nextVisibilityHidden && in_array($tag, $blocks, true)) {
                $output .= "\n";
            }
            if ($tag === 'br' && $hiddenCount === 0 && !$nextVisibilityHidden) {
                $output .= ' '; // An inline break can split a single error message.
            }
            // Self-closing and void tags have no descendant text.
            if (!str_ends_with(rtrim($piece), '/>') && !self::isVoidTag($tag)) {
                $stack[] = ['tag' => $tag, 'hidden' => $isHidden, 'reveal' => $revealSummary,
                    'visibility_hidden' => $nextVisibilityHidden,
                    'details_closed' => $isClosedDetails,
                    // A summary reveals only the default collapsed-details content,
                    // never a details element hidden by CSS, hidden, or aria-hidden.
                    'details_summary_allowed' => $isClosedDetails && !$explicitlyConcealed,
                    'summary_seen' => false];
                $hiddenCount += (int) $isHidden;
                $visibilityHidden = $nextVisibilityHidden;
            }
        }
        $output = preg_replace('/[ \t\r\f]+/u', ' ', $output) ?? $output;
        return trim($output);
    }

    /**
     * Shared default non-rendered contexts for both health assertions and
     * application fault recognition. These are browser-fallback or inactive UI
     * regions; scripts, styles and remote CSS are never executed offline.
     * @param array<string,string> $attributes
     */
    public static function isNonRenderedElement(string $tag, array $attributes): bool
    {
        return array_key_exists('popover', $attributes) || in_array($tag, [
            'script', 'style', 'noscript', 'template', 'svg', 'head', 'title',
            'datalist', 'iframe', 'canvas', 'object', 'audio', 'video',
            // Selection and option rendering depend on browser selection state;
            // a hidden/unselected choice cannot prove successful page content.
            'select', 'option', 'optgroup',
        ], true);
    }

    /** CSS escapes require computed CSS semantics we do not emulate. */
    public static function assertSupportedInlineStyle(string $style): void
    {
        if (str_contains($style, '\\')) {
            throw new MalformedHtmlException('Escaped inline CSS cannot prove page visibility.');
        }
    }

    /** HTML void elements cannot contain children, regardless of attributes. */
    public static function isVoidTag(string $tag): bool
    {
        return in_array(strtolower($tag), [
            'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
            'link', 'meta', 'param', 'source', 'track', 'wbr',
        ], true);
    }

    /**
     * Parse HTML attributes by exact names, respecting quoted and unquoted
     * values. No substring matching against attribute names is allowed.
     * First duplicate wins (the behavior of standard HTML parsers).
     * @return array<string,string>
     */
    public static function parseAttributes(string $raw): array
    {
        $attributes = [];
        $offset = 0;
        $length = strlen($raw);
        while ($offset < $length) {
            while ($offset < $length && str_contains(" \t\r\n\f", $raw[$offset])) {
                ++$offset;
            }
            if ($offset >= $length || ($raw[$offset] === '/' && trim(substr($raw, $offset)) === '/')) {
                break;
            }
            if (!preg_match('/\G([^\s=\/>"\x27`<]+)/A', $raw, $name, 0, $offset)) {
                throw new MalformedHtmlException('Invalid HTML attribute syntax.');
            }
            $offset += strlen($name[1]);
            $key = strtolower($name[1]);
            while ($offset < $length && str_contains(" \t\r\n\f", $raw[$offset])) {
                ++$offset;
            }
            $value = '';
            if ($offset < $length && $raw[$offset] === '=') {
                ++$offset;
                while ($offset < $length && str_contains(" \t\r\n\f", $raw[$offset])) {
                    ++$offset;
                }
                if ($offset >= $length) {
                    throw new MalformedHtmlException('Missing HTML attribute value.');
                }
                $quote = $raw[$offset];
                if ($quote === '"' || $quote === "'") {
                    $begin = ++$offset;
                    $end = strpos($raw, $quote, $begin);
                    if ($end === false) {
                        throw new MalformedHtmlException('Unterminated HTML attribute value.');
                    }
                    $value = substr($raw, $begin, $end - $begin);
                    $offset = $end + 1;
                } else {
                    if (!preg_match('/\G([^\s"\x27`=<>]+)/A', $raw, $val, 0, $offset)) {
                        throw new MalformedHtmlException('Invalid unquoted HTML attribute value.');
                    }
                    $value = $val[1];
                    $offset += strlen($value);
                }
            }
            if (!array_key_exists($key, $attributes)) {
                $attributes[$key] = $value;
            }
        }
        return $attributes;
    }

    /**
     * @return list<array{tag:bool,value:string}> Distinguish markup from text,
     * including raw-text bodies that start with a literal '<'.
     */
    public static function htmlTokens(string $html): array
    {
        $tokens = [];
        $offset = 0;
        $length = strlen($html);
        while ($offset < $length) {
            $start = strpos($html, '<', $offset);
            if ($start === false) {
                $tokens[] = ['tag' => false, 'value' => substr($html, $offset)];
                break;
            }
            if ($start > $offset) {
                $tokens[] = ['tag' => false, 'value' => substr($html, $offset, $start - $offset)];
            }
            if (substr($html, $start, 4) === '<!--') {
                $end = strpos($html, '-->', $start + 4);
                if ($end === false) {
                    throw new MalformedHtmlException('Malformed HTML comment.');
                }
                $tokens[] = ['tag' => true, 'value' => substr($html, $start, $end + 3 - $start)];
                $offset = $end + 3;
                continue;
            }
            // Declarations and processing instructions are markup, never
            // visitor-visible page text. In particular, DOCTYPE/XML preambles
            // must not satisfy content assertions on otherwise empty pages.
            if (substr($html, $start, 2) === '<!' || substr($html, $start, 2) === '<?') {
                $processing = $html[$start + 1] === '?';
                $quote = null;
                $brackets = 0;
                $end = null;
                for ($i = $start + 2; $i < $length; ++$i) {
                    $char = $html[$i];
                    if ($quote !== null) {
                        if ($char === $quote) { $quote = null; }
                        continue;
                    }
                    if ($char === '"' || $char === "'") {
                        $quote = $char;
                    } elseif (!$processing && $char === '[') {
                        ++$brackets;
                    } elseif (!$processing && $char === ']' && $brackets > 0) {
                        --$brackets;
                    } elseif ($char === '>' && $brackets === 0 &&
                        (!$processing || $i > $start + 2 && $html[$i - 1] === '?')) {
                        $end = $i;
                        break;
                    }
                }
                if ($end === null) {
                    throw new MalformedHtmlException('Unterminated document declaration.');
                }
                $tokens[] = ['tag' => true, 'value' => substr($html, $start, $end + 1 - $start)];
                $offset = $end + 1;
                continue;
            }
            // '< b' and similar text are not HTML tags. Do not interpret a
            // less-than sign in a text node as an opening element.
            if (preg_match('~\A</?[a-z][a-z0-9-]*\b~i', substr($html, $start, 32)) !== 1) {
                $tokens[] = ['tag' => false, 'value' => '<'];
                $offset = $start + 1;
                continue;
            }
            $quote = null;
            $end = null;
            for ($i = $start + 1; $i < $length; $i++) {
                $char = $html[$i];
                if ($quote !== null) {
                    if ($char === $quote) {
                        $quote = null;
                    }
                    continue;
                }
                if ($char === '"' || $char === "'") {
                    $quote = $char;
                } elseif ($char === '>') {
                    $end = $i;
                    break;
                } elseif ($char === '<') {
                    throw new MalformedHtmlException('Malformed HTML tag.');
                }
            }
            if ($end === null) {
                throw new MalformedHtmlException('Unterminated HTML tag.');
            }
            $complete = substr($html, $start, $end - $start + 1);
            // The self-closing flag is ignored for ordinary HTML non-void tags.
            // Rather than assume the next sibling is visible, refuse to use
            // ambiguous malformed markup as evidence of recovery.
            if (preg_match('~\A<([a-z][a-z0-9-]*)\b~i', $complete, $startTag) === 1 &&
                str_ends_with(rtrim($complete), '/>') && !self::isVoidTag(strtolower($startTag[1]))) {
                throw new MalformedHtmlException('Ambiguous non-void self-closing HTML element.');
            }
            $tokens[] = ['tag' => true, 'value' => $complete];
            $offset = $end + 1;
            // HTML raw text and RCDATA must not be parsed as markup until the
            // matching end tag. JS/CSS commonly contain '<' in valid strings.
            if (preg_match('~\A<(script|style|textarea|title)\b~i', $complete, $open) === 1 &&
                !str_ends_with(rtrim($complete), '/>')) {
                $closing = '~</\s*' . preg_quote($open[1], '~') . '\s*>~i';
                if (preg_match($closing, $html, $match, PREG_OFFSET_CAPTURE, $offset) === 1) {
                    $rawEnd = $match[0][1];
                    if ($rawEnd > $offset) {
                        $tokens[] = ['tag' => false, 'value' => substr($html, $offset, $rawEnd - $offset)];
                    }
                    $offset = $rawEnd;
                } else {
                    $tokens[] = ['tag' => false, 'value' => substr($html, $offset)];
                    break;
                }
            }
        }
        return $tokens;
    }

    /**
     * Recognize known error templates in displayed page content. Documentation
     * links and code examples are not outage evidence. A nearby explanatory
     * paragraph exempts only its own tutorial heading, not later errors.
     * This is deliberately a bounded heuristic, not a browser or a semantic AI.
     */
    /** A meta refresh is an unverified browser navigation, not a confirmed health check. */
    private static function hasMetaRefresh(string $html): bool
    {
        $stack = [];
        foreach (self::htmlTokens($html) as $token) {
            if (!$token['tag'] || preg_match('~^<\s*(/?)\s*([a-z][a-z0-9-]*)\b~i', $token['value'], $m) !== 1) {
                continue;
            }
            $tag = strtolower($m[2]);
            if ($m[1] === '/') {
                for ($i = count($stack) - 1; $i >= 0; --$i) {
                    if ($stack[$i] === $tag) { $stack = array_slice($stack, 0, $i); break; }
                }
                continue;
            }
            if ($tag === 'meta' && !in_array('template', $stack, true)) {
                $attributes = self::parseAttributes(substr($token['value'], strlen($m[0]), -1));
                $equiv = html_entity_decode($attributes['http-equiv'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $content = html_entity_decode($attributes['content'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if (strcasecmp(trim($equiv), 'refresh') === 0 &&
                    preg_match('/\A\s*(?:\d+)(?:\.\d+)?\s*(?:;\s*url\s*=\s*[^\r\n]+)?\s*\z/iD', $content) === 1) {
                    return true;
                }
            }
            if (!self::isVoidTag($tag)) { $stack[] = $tag; }
        }
        return false;
    }

    private static function applicationError(string $html): ?string
    {
        return HtmlFaultDetector::detect($html);
    }

    /** @return array{healthy:null,code:string,detail:string,status_code:int} */
    private static function unverifiedHtml(int $status): array
    {
        return ['healthy' => null, 'code' => 'unverified_html',
            'detail' => 'Page markup could not be safely classified', 'status_code' => $status];
    }

    private static function normalizedText(string $text): string
    {
        // HTML entities have already been decoded; NBSP, zero-width spaces,
        // CR/LF and other Unicode separators must not defeat a known signature.
        return \Portfolio\Support\CanonicalText::normalize(trim(
            preg_replace('/[\p{Z}\p{Cf}\s]+/u', ' ', $text) ?? $text
        ));
    }

    /** @return array{healthy:bool,code:string,detail:string,status_code:int|null} */
    private static function problem(string $code, string $detail, ?int $status): array
    {
        return ['healthy' => false, 'code' => $code, 'detail' => $detail, 'status_code' => $status];
    }
}
