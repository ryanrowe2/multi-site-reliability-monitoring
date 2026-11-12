<?php

declare(strict_types=1);

namespace Portfolio\Support;

use InvalidArgumentException;

final class Config
{
    /** @return array<string,mixed> */
    public static function load(string $file, string $mode = 'both'): array
    {
        if (!in_array($mode, ['both', 'uptime', 'integrity'], true)) {
            throw new InvalidArgumentException('Unknown configuration mode.');
        }
        $contents = BoundedReader::read($file, 1_000_000);
        $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        // Reject duplicate JSON members before associative decoding can silently
        // replace a host list or safety policy with the last occurrence.
        UniqueJsonKeys::assertUnique($contents);
        if (!is_array($data) || array_is_list($data)) {
            throw new InvalidArgumentException('Configuration must be a JSON object.');
        }
        self::knownKeys($data, ['hosts', 'reminder_seconds', 'expected_interval_seconds', 'integrity', 'content_policies', 'unverified_threshold_seconds', 'unverified_reminder_seconds'], 'top-level');
        foreach (['reminder_seconds', 'expected_interval_seconds'] as $field) {
            if (array_key_exists($field, $data)) {
                if (!is_array($data[$field]) || (array_is_list($data[$field]) && $data[$field] !== [])) {
                    throw new InvalidArgumentException($field . ' must be a JSON object.');
                }
                self::knownKeys($data[$field], ['uptime', 'integrity'], $field);
            }
        }
        if ($mode !== 'uptime' && array_key_exists('integrity', $data)) {
            if (!is_array($data['integrity']) || array_is_list($data['integrity'])) {
                throw new InvalidArgumentException('integrity must be an object.');
            }
            self::knownKeys($data['integrity'], [
                'root', 'sites', 'core_version', 'pro_header_version', 'pro_runtime_version',
                'update_lock', 'update_lock_sha256', 'baseline_sha256', 'core_baseline_sha256',
            ], 'integrity');
        }
        if ($mode !== 'integrity' && array_key_exists('content_policies', $data)) {
            if (!is_array($data['content_policies']) || (array_is_list($data['content_policies']) && $data['content_policies'] !== [])) {
                throw new InvalidArgumentException('content_policies must be an object.');
            }
            foreach ($data['content_policies'] as $policy) {
                if (!is_array($policy) || (array_is_list($policy) && $policy !== [])) {
                    throw new InvalidArgumentException('Invalid host content policy.');
                }
                self::knownKeys($policy, ['min_body_bytes', 'contains', 'json_health'], 'content policy');
            }
        }
        $intervals = $data['reminder_seconds'] ?? null;
        if (!is_array($intervals) || array_is_list($intervals)) {
            throw new InvalidArgumentException('reminder_seconds must be an object.');
        }
        $result = ['hosts' => [], 'reminder_seconds' => [], 'expected_interval_seconds' => [], 'integrity' => [], 'content_policies' => [], 'unverified_threshold_seconds' => 3600, 'unverified_reminder_seconds' => 21600];
        foreach ($mode === 'both' ? ['uptime', 'integrity'] : [$mode] as $key) {
            $value = $intervals[$key] ?? null;
            if (!is_int($value) || $value < 1 || $value > 31536000) {
                throw new InvalidArgumentException('Invalid ' . $key . ' reminder interval.');
            }
            $result['reminder_seconds'][$key] = $value;
            $expected = $data['expected_interval_seconds'][$key] ?? null;
            if ($expected !== null && (!is_int($expected) || $expected < 1 || $expected > 31536000)) {
                throw new InvalidArgumentException('Invalid expected monitoring interval.');
            }
            $result['expected_interval_seconds'][$key] = $expected;
        }
        if ($mode !== 'integrity') {
            foreach (['unverified_threshold_seconds', 'unverified_reminder_seconds'] as $key) {
                $value = array_key_exists($key, $data) ? $data[$key] : $result[$key];
                if (!is_int($value) || $value < 1 || $value > 31536000) {
                    throw new InvalidArgumentException('Invalid ' . $key . '.');
                }
                $result[$key] = $value;
            }
        }
        if ($mode !== 'integrity') {
            $result['hosts'] = self::hosts($data['hosts'] ?? null);
            $policyMap = $data['content_policies'] ?? [];
            if (!is_array($policyMap) || (array_is_list($policyMap) && $policyMap !== [])) {
                throw new InvalidArgumentException('content_policies must be an object.');
            }
            foreach ($policyMap as $host => $policy) {
                if (!in_array($host, $result['hosts'], true) || !is_array($policy)) {
                    throw new InvalidArgumentException('Invalid host content policy.');
                }
                $allowed = ['min_body_bytes', 'contains', 'json_health'];
                foreach (array_keys($policy) as $name) {
                    if (!in_array($name, $allowed, true)) {
                        throw new InvalidArgumentException('Unknown content policy property.');
                    }
                }
                if ($policy === [] || (!array_key_exists('contains', $policy) && !array_key_exists('min_body_bytes', $policy) && !array_key_exists('json_health', $policy))) {
                    throw new InvalidArgumentException('Empty content policy is not a health contract.');
                }
                $min = $policy['min_body_bytes'] ?? 1;
                if (!is_int($min) || $min < 0 || $min > 131072) {
                    throw new InvalidArgumentException('Invalid minimum body length.');
                }
                $contains = $policy['contains'] ?? null;
                if ($contains !== null && (!is_string($contains) || trim($contains) === '' || strlen($contains) > 1000)) {
                    throw new InvalidArgumentException('Invalid required body sentinel.');
                }
                if ($min === 0 && $contains === null && !isset($policy['json_health'])) {
                    throw new InvalidArgumentException('A zero-evidence policy cannot establish health.');
                }
                \Portfolio\Support\CanonicalText::assertComparable($contains);
                if (array_key_exists('json_health', $policy) && $policy['json_health'] === null) {
                    throw new InvalidArgumentException('JSON health contract cannot be null.');
                }
                $health = $policy['json_health'] ?? null;
                if ($health !== null) {
                    if (!is_array($health) || array_is_list($health) || count($health) !== 2 ||
                        !array_key_exists('field', $health) || !array_key_exists('equals', $health) ||
                        !is_string($health['field']) || !preg_match('/\A[a-z][a-z0-9_]{0,63}\z/iD', $health['field']) ||
                        !is_string($health['equals']) || $health['equals'] === '' || strlen($health['equals']) > 1000 ||
                        $contains !== null) {
                        throw new InvalidArgumentException('Invalid or conflicting JSON health contract.');
                    }
                }
                $result['content_policies'][$host] = ['min_body_bytes' => $min, 'contains' => $contains];
                if ($health !== null) { $result['content_policies'][$host]['json_health'] = $health; }
            }
        }
        if ($mode !== 'uptime') {
            $integrity = $data['integrity'] ?? null;
            if (!is_array($integrity) || array_is_list($integrity)) {
                throw new InvalidArgumentException('integrity must be an object.');
            }
            $integrity['sites'] = self::hosts($integrity['sites'] ?? null);
            foreach (['root', 'core_version', 'pro_header_version', 'pro_runtime_version', 'update_lock'] as $key) {
                if (!isset($integrity[$key]) || !is_string($integrity[$key]) || trim($integrity[$key]) === '') {
                    throw new InvalidArgumentException('Missing integrity configuration: ' . $key);
                }
            }
            if (!preg_match('/\A[a-zA-Z0-9_-]+\.php\z/D', $integrity['update_lock'])) {
                throw new InvalidArgumentException('Update lock must be a basename ending with .php.');
            }
            foreach (['core_version', 'pro_header_version', 'pro_runtime_version'] as $key) {
                if (!preg_match('/\A[0-9A-Za-z][0-9A-Za-z.+_-]{0,49}\z/D', $integrity[$key])) {
                    throw new InvalidArgumentException('Invalid version constraint.');
                }
            }
            // A syntactically plausible version declaration does not prove it executes.
            // Require known-good synthetic digests to attest approved fixture content.
            foreach (['update_lock_sha256', 'baseline_sha256', 'core_baseline_sha256'] as $key) {
                if (!array_key_exists($key, $integrity)) {
                    throw new InvalidArgumentException('Missing required integrity digest: ' . $key);
                }

                if (!is_string($integrity[$key]) || !preg_match('/\A[a-f0-9]{64}\z/D', $integrity[$key])) {
                    throw new InvalidArgumentException('Invalid SHA-256 constraint.');
                }
            }
            $configDirectory = dirname(realpath($file) ?: $file);
            if (str_contains($integrity['root'], "\0")) {
                throw new InvalidArgumentException('Invalid fixture root.');
            }
            $fixtureRoot = realpath($configDirectory . DIRECTORY_SEPARATOR . $integrity['root']);
            if ($fixtureRoot === false || !is_dir($fixtureRoot) || is_link($configDirectory . '/' . $integrity['root'])) {
                throw new InvalidArgumentException('Synthetic fixture root does not exist.');
            }
            $projectFixtures = realpath(dirname(__DIR__, 2) . '/examples/fixtures');
            if (!self::isInside($fixtureRoot, $configDirectory) &&
                ($projectFixtures === false || !self::isInside($fixtureRoot, $projectFixtures))) {
                throw new InvalidArgumentException('Synthetic root must be under the config directory or packaged fixture tree.');
            }
            $integrity['root'] = $fixtureRoot;
            $result['integrity'] = $integrity;
        }
        return $result;
    }

    /** @param array<string,mixed> $value @param list<string> $allowed */
    private static function knownKeys(array $value, array $allowed, string $context): void
    {
        foreach (array_keys($value) as $key) {
            if (!is_string($key) || !in_array($key, $allowed, true)) {
                throw new InvalidArgumentException('Unknown ' . $context . ' configuration key.');
            }
        }
    }

    private static function isInside(string $candidate, string $root): bool
    {
        $root = rtrim($root, DIRECTORY_SEPARATOR);
        return $candidate === $root || str_starts_with($candidate, $root . DIRECTORY_SEPARATOR);
    }

    /** @return list<string> */
    public static function hosts(mixed $input): array
    {
        if (!is_array($input) || !array_is_list($input) || $input === [] || count($input) > 1000) {
            throw new InvalidArgumentException('Expected a nonempty host list (max 1,000).');
        }
        $result = [];
        foreach ($input as $host) {
            if (!is_string($host) || strlen($host) > 253 || !preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\z/D', $host)) {
                throw new InvalidArgumentException('Host is not a lowercase ASCII DNS name.');
            }
            foreach (explode('.', $host) as $part) {
                if (strlen($part) > 63) {
                    throw new InvalidArgumentException('Invalid DNS label length.');
                }
            }
            $allowed = in_array($host, ['example.com', 'example.org', 'example.net'], true)
                || (bool) preg_match('/\.(?:example\.com|example\.org|example\.net|test)\z/D', $host);
            if (!$allowed) {
                throw new InvalidArgumentException('Demo accepts reserved example hosts only.');
            }
            if (isset($result[$host])) {
                throw new InvalidArgumentException('Duplicate hostname.');
            }
            $result[$host] = true;
        }
        return array_keys($result);
    }
}
