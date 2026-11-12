<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

/**
 * Working-tree safety scan: exclude generated dependencies/caches.
 * --release: strict scan of EVERY file in the actual publication staging tree.
 * Heuristics cannot replace legal review, provenance checks or specialized detectors.
 */
$args = array_slice($argv, 1);
$release = false;
if (($key = array_search('--release', $args, true)) !== false) {
    $release = true;
    unset($args[$key]);
    $args = array_values($args);
}
if (count($args) > 1) {
    fwrite(STDERR, "Usage: php tools/publication_scan.php [--release] [directory]\n");
    exit(1);
}
$root = realpath($args[0] ?? dirname(__DIR__));
if ($root === false || !is_dir($root)) {
    fwrite(STDERR, "Invalid publication scan directory.\n");
    exit(1);
}
$patterns = [
    '/(?:[a-z0-9-]+\.)*machinerymovers\.(?:com|net|org)/i' => 'company hostname indicator',
    '/-----BEGIN\s+' . '(?:[A-Z ]+\s+)?' . 'PRIVATE KEY-----/i' => 'private key marker',
    '/(?:^|\n)[ \t]*(?:export[ \t]+)?[\x22\x27]?[A-Z0-9_]*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|SECRET_ACCESS_KEY|SESSION_TOKEN|AWS_ACCESS_KEY_ID)[\x22\x27]?[ \t]*[:=][ \t]*[\x22\x27]?[-a-zA-Z0-9_+\/=.:]{16,}/im' => 'possible environment secret',
    '/(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|sk-)[A-Za-z0-9_\-]{20,}/' => 'credential token pattern',
    '/\bxox[baprs]-[A-Za-z0-9\-]{18,}/' => 'possible Slack token',
    '/(?:^|\n)\s*(?:(?:\/\/)?[^\s:=]+\s*:\s*)?_authToken\s*=\s*[\"\']?[^\s\"\']{16,}/mi' => 'possible npm authentication token',
    // WordPress config constants, including salts and signing keys.
    '~\bdefine\s*\(\s*[\x22\x27](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[\x22\x27]\s*,\s*[\x22\x27][^\x22\x27\r\n]{8,}[\x22\x27]~i' => 'possible WordPress secret constant',
    // HTTP Authorization headers and generic secret-bearing configuration labels.
    '~\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._\~+/=-]{12,}~i' => 'possible bearer token',
    '~(?:^|\n)\s*[\x22\x27]?(?:GITHUB_TOKEN|SLACK_TOKEN|API_TOKEN|BEARER_TOKEN|ACCESS_TOKEN|CLIENT_SECRET|SECRET_KEY|DB_PASSWORD|AUTH_KEY)[\x22\x27]?\s*(?::|=)\s*[\x22\x27]?[A-Za-z0-9_+/.=-]{12,}~im' => 'possible labeled credential',
    // Detect PHP embedded environment variables and constant declarations,
    // even when not at the beginning of a line. Synthetic test values only.
    '~\bputenv\s*\(\s*[\x22\x27](?:AWS_)?(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|GITHUB_TOKEN|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CLIENT_SECRET|DB_PASSWORD|AUTH_KEY)\s*=\s*[^\x22\x27\r\n]{12,}[\x22\x27]~i' => 'possible PHP environment secret',
    '~\bconst\s+(?:AWS_)?(?:SECRET_ACCESS_KEY|GITHUB_TOKEN|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|DB_PASSWORD|AUTH_KEY)\s*=\s*[\x22\x27][^\x22\x27\r\n]{12,}[\x22\x27]~i' => 'possible PHP secret constant',
    // Ordinary PHP string assignments (including $db_password = "...")
    // must be checked, not just env/const declarations. Deliberately match
    // literal values rather than getenv() or symbolic nonsecret references.
    '~\$[a-z_][a-z0-9_]*(?:password|passwd|passphrase|pass|pwd|secret|token|api_?key|auth_?key|private_?key)\b\s*=\s*[\x22\x27][^\x22\x27\r\n]{12,}[\x22\x27]~i' => 'possible PHP credential assignment',
    '/[A-Za-z0-9._%+\-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/i' => 'nonexample email address',
];

/**
 * Inspect PHP syntax tokens for literal credentials in arrays, indexed
 * assignments, object properties and ordinary variables. Comments and
 * documentation strings containing examples are not executable assignments.
 * A heuristic gate: complex expressions still need independent manual review.
 */
function hasPhpCredentialAssignment(string $content): bool
{
    $stream = [];
    foreach (token_get_all($content) as $part) {
        if (is_array($part)) {
            if (in_array($part[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG, T_INLINE_HTML], true)) {
                continue;
            }
            $stream[] = ['id' => $part[0], 'text' => $part[1]];
        } else {
            $stream[] = ['id' => null, 'text' => $part];
        }
    }
    for ($i = 1, $count = count($stream); $i + 1 < $count; $i++) {
        if (!in_array($stream[$i]['text'], ['=', '=>'], true) ||
            $stream[$i + 1]['id'] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }
        $previous = $stream[$i - 1];
        // Indexed assignment: $config['db_password'] = '...'.
        if ($previous['text'] === ']' && $i >= 3 && $stream[$i - 3]['text'] === '[') {
            $previous = $stream[$i - 2];
        }
        $name = $previous['text'];
        if ($previous['id'] === T_VARIABLE) {
            $name = substr($name, 1);
        } elseif ($previous['id'] === T_CONSTANT_ENCAPSED_STRING) {
            $name = substr($name, 1, -1);
        } elseif ($previous['id'] !== T_STRING) {
            continue;
        }
        if (preg_match('/(?:password|passwd|passphrase|pass|pwd|secret|api_?key|auth_?key|private_?key|token)\z/i', $name) !== 1) {
            continue;
        }
        // A known sensitive lvalue with one or more literal string tokens is
        // a hard-coded value regardless of length. Literal concatenation is
        // intentionally rejected, not just the first token in a string run.
        $value = substr($stream[$i + 1]['text'], 1, -1);
        $cursor = $i + 2;
        while (isset($stream[$cursor], $stream[$cursor + 1]) && $stream[$cursor]['text'] === '.' &&
            $stream[$cursor + 1]['id'] === T_CONSTANT_ENCAPSED_STRING) {
            $value .= substr($stream[$cursor + 1]['text'], 1, -1);
            $cursor += 2;
        }
        if ($value !== '') { return true; }
    }
    return false;
}

/** Parse literal PHP define(NAME, value) calls using PHP's own token stream. */
function hasPhpSensitiveDefine(string $content): bool
{
    $tokens = [];
    foreach (token_get_all($content) as $part) {
        if (is_array($part)) {
            if (in_array($part[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $tokens[] = ['id' => $part[0], 'text' => $part[1]];
        } else {
            $tokens[] = ['id' => null, 'text' => $part];
        }
    }
    for ($i = 0, $count = count($tokens); $i + 4 < $count; $i++) {
        if ($tokens[$i]['id'] !== T_STRING || strtolower($tokens[$i]['text']) !== 'define' ||
            $tokens[$i+1]['text'] !== '(' || $tokens[$i+2]['id'] !== T_CONSTANT_ENCAPSED_STRING ||
            $tokens[$i+3]['text'] !== ',' || $tokens[$i+4]['id'] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }
        $name = substr($tokens[$i+2]['text'], 1, -1);
        $value = substr($tokens[$i+4]['text'], 1, -1);
        if (isSensitiveStructuredKey($name) && $value !== '') {
            return true;
        }
    }
    return false;
}

/**
 * Conservative YAML policy. Key/value parsing covers nested mappings, quoted
 * keys, inline mappings, short scalar passwords and URI userinfo. YAML aliases,
 * custom tags and multiline secret fields require separate human review.
 * It is intentionally heuristic, not a complete YAML 1.2 parser; complex
 * formats still require independent inspection.
 */
function hasYamlSecret(string $content): bool
{
    $pendingSecretName = false;
    $pendingIndent = 0;
    foreach (preg_split('/\R/u', $content) ?: [] as $line) {
        $indent = strlen($line) - strlen(ltrim($line, ' '));
        if ($pendingSecretName && $indent < $pendingIndent && trim($line) !== '') {
            $pendingSecretName = false;
        }
        // Common Kubernetes and GitHub-style environment sequence entries.
        if (preg_match('/^\s*-\s*name\s*:\s*([\x22\x27]?)([A-Za-z_][A-Za-z0-9_]*)\1\s*(?:#.*)?$/i', $line, $envName)) {
            $pendingSecretName = isSensitiveStructuredKey($envName[2]);
            $pendingIndent = $indent;
        } elseif (preg_match('/^\s*-\s*/', $line)) {
            $pendingSecretName = false;
        }
        if ($pendingSecretName && preg_match('/^\s*value\s*:\s*(.+)$/i', $line, $envValue)) {
            $value = trim($envValue[1]);
            if ($value !== '' && !in_array(strtolower($value), ['null', '~'], true)) {
                return true;
            }
        }
        // Docker Compose's environment: - KEY=value syntax.
        if (preg_match('/^\s*-\s*[\x22\x27]?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s\x22\x27#]+)/', $line, $assignment) &&
            isSensitiveStructuredKey($assignment[1])) {
            return true;
        }
        // Compose also permits environment: [KEY=value] without YAML maps.
        if (preg_match('/\b(?:env|environment)\s*:\s*\[([^\]\r\n]{0,2048})\]/i', $line, $envList)) {
            foreach (explode(',', $envList[1]) as $entry) {
                $entry = trim($entry, " \t\x22\x27");
                if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)/', $entry, $kv) &&
                    isSensitiveStructuredKey($kv[1])) {
                    return true;
                }
            }
        }
        // Inline flow sequence of Kubernetes name/value mappings.
        if (preg_match_all('/\{([^{}]{0,2048})\}/', $line, $flowMaps)) {
            foreach ($flowMaps[1] as $flowMap) {
                if (preg_match('/(?:^|,)\s*name\s*:\s*[\x22\x27]?([A-Za-z_][A-Za-z0-9_]*)/i', $flowMap, $flowName) &&
                    preg_match('/(?:^|,)\s*value\s*:\s*([^,}#\s]+)/i', $flowMap, $flowValue) &&
                    isSensitiveStructuredKey($flowName[1])) {
                    return true;
                }
            }
        }

        if (hasCredentialUrl($line)) {
            return true;
        }
        if (preg_match('/^\s*(?:-\s+)?(?:[\x22\x27]([^\x22\x27]+)[\x22\x27]|([A-Za-z0-9_.-]+))\s*:\s*(.*)$/', $line, $match)) {
            $name = $match[1] ?: $match[2];
            $value = trim($match[3]);
            if ((isSensitiveStructuredKey($name) || preg_match('/\A(?:database_?url|db_?url|dsn|connection_?string)\z/i', $name)) &&
                $value !== '' && !in_array(strtolower($value), ['null', '~'], true)) {
                return true;
            }
        }
        // Flow mappings may be nested inside a plain mapping value.
        if (preg_match_all('/[{,]\s*[\x22\x27]?([A-Za-z_][A-Za-z0-9_.-]*)[\x22\x27]?\s*:\s*([^,}#\s]+)/', $line, $flow, PREG_SET_ORDER)) {
            foreach ($flow as $field) {
                if (isSensitiveStructuredKey($field[1]) || preg_match('/\A(?:database_?url|db_?url|dsn)\z/i', $field[1])) {
                    return true;
                }
            }
        }
        // Flow-style YAML mappings and inline nested data have no meaningful
        // indentation, so inspect key/value fields anywhere in a line.
        if (preg_match_all('/(?:^|[{,])\s*[\x22\x27]?([A-Za-z_][A-Za-z0-9_.-]*)[\x22\x27]?\s*:\s*([^,}#\s]+)/', $line, $inlines, PREG_SET_ORDER)) {
            foreach ($inlines as $inline) {
                if (isSensitiveStructuredKey($inline[1]) || preg_match('/\A(?:database_?url|db_?url|dsn)\z/i', $inline[1])) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * Static-only SVG policy: publication diagrams never need links or entities.
 * Reject any entity reference, XML DTD, active tag, link attribute, CSS URL or
 * import. This policy is intentionally narrower than general SVG.
 */
function unsafeStaticSvg(string $content): bool
{
    if (str_contains($content, '&') || str_contains($content, '\\') || preg_match('/\sstyle\s*=/i', $content) === 1) {
        return true; // No entity indirection or inline CSS in a static-only SVG.
    }
    $decoded = html_entity_decode($content, ENT_QUOTES | ENT_XML1, 'UTF-8');
    return preg_match('~<\s*!\s*(?:DOCTYPE|ENTITY)\b|<\s*(?:script|style|a|image|use|link|foreignObject|iframe|object|embed|animate(?:Transform|Motion)?|set)\b|\s+on[a-z][a-z0-9_-]*\s*=|\b(?:xlink:)?href\s*=|\bjavascript\s*:|\burl\s*\(\s*(?![\x22\x27]?\s*#)|<\?\s*xml-stylesheet\b|@\s*import\b~i', $decoded) === 1;
}

/**
 * Inspect executable PHP string tokens, not comments, for credential-bearing
 * URLs and literal fragments. Concatenated quoted literals and HEREDOC bodies
 * are both checked. Complex dynamic expressions remain a manual-review risk.
 */
function hasPhpSecretLiteral(string $source): bool
{
    $tokens = token_get_all($source);
    $runs = [];
    $buffer = '';
    $previousWasString = false;
    foreach ($tokens as $token) {
        $id = is_array($token) ? $token[0] : null;
        $value = is_array($token) ? $token[1] : $token;
        if (in_array($id, [T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML], true)) {
            $previousWasString = false; $buffer = ''; continue;
        }
        if ($id === T_CONSTANT_ENCAPSED_STRING) {
            $part = substr($value, 1, -1);
            if (!$previousWasString) { $buffer = ''; }
            $buffer .= stripcslashes($part);
            $runs[] = $buffer;
            $previousWasString = true;
        } elseif ($value === '.' && $previousWasString) {
            // Preserve the literal run until the next quoted fragment.
        } elseif ($id === T_WHITESPACE && $previousWasString) {
            // Ignore whitespace between literal concatenation tokens.
        } else {
            $previousWasString = false;
            $buffer = '';
        }
        if ($id === T_ENCAPSED_AND_WHITESPACE && hasCredentialUrl($value)) {
            return true;
        }
    }
    foreach ($runs as $literal) {
        if (hasCredentialUrl($literal) ||
            preg_match('/(?:^|[?&])(?:access_token|api_key|auth_token|password|dbpass)=([^&\s]+)/i', $literal)) {
            return true;
        }
    }
    // Detect HEREDOC/nowdoc under a sensitive variable name without treating
    // harmless prose mentioning credentials as a code assignment.
    if (preg_match('/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*<<<[\x27\x22]?[A-Za-z_][A-Za-z0-9_]*/', $source, $match) &&
        isSensitiveStructuredKey($match[1])) {
        return true;
    }
    return false;
}

/** Credential-bearing connection URLs can occur under innocuous field names. */
function hasCredentialUrl(string $value): bool
{
    // Only URLs containing explicit userinfo passwords are considered a
    // credential. Plain example.com documentation links remain publishable.
    if (preg_match('~\b[a-z][a-z0-9+.-]*://~i', $value) !== 1) {
        return false;
    }
    if (preg_match_all('~[a-z][a-z0-9+.-]*://[^\s\x22\x27<>]+~i', $value, $urls)) {
        foreach ($urls[0] as $url) {
            $parts = parse_url($url);
            if (is_array($parts) && isset($parts['user'], $parts['pass']) &&
                $parts['pass'] !== '') {
                return true;
            }
        }
    }
    return false;
}

/** Known sensitive aliases and generalized credential-bearing configuration keys. */
function isSensitiveStructuredKey(string $key): bool
{
    $key = preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', $key) ?? $key;
    $key = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $key) ?? $key;
    $key = strtolower(preg_replace('/[^a-zA-Z0-9]+/', '_', $key) ?? $key);
    $pieces = array_values(array_filter(explode('_', $key), 'strlen'));
    $flat = implode('', $pieces);
    if (in_array($flat, ['dbpass','dbpasswd','dbpassword','mysqlpwd','pgpassword','pgpasswd',
        'serviceauth','sqlauth','sqlpass','servicecredential','dburi','databaseuri','databaseurl',
        'postgresurl','connectionstring','authorization','awssecretaccesskey'], true)) {
        return true;
    }
    if (preg_match('/(?:password|passwd|passphrase|secret|token|credential|credentials|privatekey|apikey|authkey|accesskey|auth|dbpass|dbpwd|pwd)\z/', $flat) === 1) {
        return true;
    }
    return preg_match('/(?:^|_)(?:password|passwd|passphrase|pass|pwd|secret|token|api_key|auth_key|private_key|access_key|authorization|credential|credentials)(?:$|_)/', $key) === 1;
}

/** @param mixed $node */
function hasStructuredSecret(mixed $node): bool
{
    if (is_string($node)) {
        return hasCredentialUrl($node);
    }
    if (!is_array($node)) {
        return false;
    }
    foreach ($node as $key => $value) {
        if (is_string($key) && isSensitiveStructuredKey($key)) {
            // Non-string JSON secrets (numeric PINs, arrays of tokens) must
            // not silently pass a publication safety review.
            if ($value !== null && $value !== '' && $value !== [] && $value !== false) {
                return true;
            }
        }
        if (hasStructuredSecret($value)) {
            return true;
        }
    }
    return false;
}

$hits = [];
$count = 0;
$excludedDirectories = ['.git', 'vendor', 'var/phpstan-cache'];
$excludedFiles = ['composer.lock'];
$filter = new RecursiveCallbackFilterIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    static function (SplFileInfo $entry) use ($root, $release, $excludedDirectories, $excludedFiles): bool {
        $relative = str_replace('\\', '/', substr($entry->getPathname(), strlen($root) + 1));
        if (!$release && $entry->isDir()) {
            return !in_array($relative, $excludedDirectories, true);
        }
        return $release || !in_array($relative, $excludedFiles, true);
    }
);
$iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);
foreach ($iterator as $entry) {
    $path = $entry->getPathname();
    $relative = str_replace('\\', '/', substr($path, strlen($root) + 1));
    if ($entry->isLink()) {
        $hits[] = $relative . ': symlink in release';
        continue;
    }
    if ($release && ($relative === '.git' || str_starts_with($relative, '.git/') ||
        $relative === 'vendor' || str_starts_with($relative, 'vendor/') ||
        str_starts_with($relative, 'var/phpstan-cache/'))) {
        $hits[] = $relative . ': generated/private working directory must not be published';
        continue;
    }
    if ($entry->isDir()) {
        continue;
    }
    if (!$entry->isFile() || !$entry->isReadable()) {
        $hits[] = $relative . ': unsupported or unreadable file';
        continue;
    }
    if ($entry->getSize() > 5_000_000) {
        $hits[] = $relative . ': unexpected large publication file';
        continue;
    }
    $content = @file_get_contents($path);
    if ($content === false) {
        $hits[] = $relative . ': file read failed';
        continue;
    }
    $count++;
    // NUL detection alone misses high-bit binary payloads with no zero bytes.
    // The public demonstration contains only bounded UTF-8 text files.
    $allowedExtensions = ['php', 'md', 'txt', 'json', 'yml', 'yaml', 'svg', 'sh', 'neon', 'lock', 'sha256', 'py'];
    $allowedSpecial = ['.gitignore', '.gitkeep', 'LICENSE'];
    $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if ($extension === 'py' && $relative !== 'tools/scan_yaml.py') {
        $hits[] = $relative . ': unexpected executable Python file requires separate review';
        continue;
    }
    if (!in_array(basename($path), $allowedSpecial, true) && !in_array($extension, $allowedExtensions, true)) {
        $hits[] = $relative . ': unapproved publication file type';
        continue;
    }
    if (preg_match('//u', $content) !== 1 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $content)) {
        $hits[] = $relative . ': binary or invalid UTF-8 content requires explicit review';
        continue;
    }
    // Structured JSON must not depend on start-of-line regexes: minified
    // object fields and nested credentials are both publication risks.
    if ($extension === 'json') {
        try {
            \Portfolio\Support\UniqueJsonKeys::assertUnique($content);
        } catch (Throwable $e) {
            $hits[] = $relative . ': duplicate or ambiguous JSON object key';
            continue;
        }
        $parsed = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $hits[] = $relative . ': malformed JSON publication file';
        } elseif (hasStructuredSecret($parsed)) {
            $hits[] = $relative . ': possible structured JSON credential';
        }
    }
    // This repository publishes only static SVG diagrams. Reject embedded
    // execution, event attributes, external fetches and XML entity expansion.
    if ($extension === 'svg') {
        if (unsafeStaticSvg($content)) {
            $hits[] = $relative . ': active, encoded or externally referenced SVG content';
        }
        if (!\Portfolio\Support\StaticSvgValidator::isWellFormed($content)) {
            $hits[] = $relative . ': invalid static SVG XML structure';
        }
    }
    if (in_array($extension, ['yml', 'yaml', 'neon'], true)) {
        // Parse decoded YAML keys, mappings and sequences, independent of
        // quoting, key order and flow-vs-block representation. Missing Python
        // or PyYAML fails closed rather than silently disabling screening.
        if (!function_exists('proc_open')) {
            $hits[] = $relative . ': required structured YAML scanner unavailable';
        } else {
            $proc = @proc_open(['python3', __DIR__ . '/scan_yaml.py', $path],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (!is_resource($proc)) {
                $hits[] = $relative . ': required YAML scanner could not start';
            } else {
                fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
                fclose($pipes[1]); fclose($pipes[2]);
                $status = proc_close($proc);
                if ($status !== 0) {
                    $hits[] = $relative . ': structured YAML credential or unsupported YAML syntax';
                }
            }
        }
    }
    if (in_array($extension, ['sh', 'txt'], true)) {
        foreach (preg_split('/\R/u', $content) ?: [] as $line) {
            if (!preg_match('/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/', $line, $setting)) {
                continue;
            }
            if (isSensitiveStructuredKey($setting[1]) &&
                !in_array(strtolower(trim($setting[2], " \t\"'")), ['','null','changeme','placeholder'], true) &&
                !preg_match('/^\$\{[^}]+\}$/', trim($setting[2]))) {
                $hits[] = $relative . ': hard-coded shell/text credential assignment';
                break;
            }
        }
    }
    if ($extension === 'php' && hasPhpSensitiveDefine($content)) {
        $hits[] = $relative . ': possible PHP define() secret';
    }
    if ($extension === 'php' && hasPhpSecretLiteral($content)) {
        $hits[] = $relative . ': credential-bearing PHP string literal';
    }
    if ($extension === 'php' && hasPhpCredentialAssignment($content)) {
        $hits[] = $relative . ': possible PHP literal credential assignment';
    }
    foreach ($patterns as $regex => $label) {
        $match = @preg_match($regex, $content);
        if ($match === false) {
            $hits[] = $relative . ': release scanner invalid pattern';
        } elseif ($match === 1) {
            $hits[] = $relative . ': ' . $label;
        }
    }
    if (preg_match('/\A(?:\.env(?:\.|\z)|wp-config\.php|id_rsa|id_ed25519|.*\.(?:pem|key|p12))\z/i', basename($path))) {
        $hits[] = $relative . ': sensitive filename';
    }
}
if ($count === 0) {
    $hits[] = 'No publication files scanned';
}
if ($hits !== []) {
    fwrite(STDERR, implode("\n", array_unique($hits)) . "\n");
    exit(1);
}
echo "Publication indicators clear across {$count} " . ($release ? 'strict-release' : 'working-tree') . " files (manual review still required).\n";
