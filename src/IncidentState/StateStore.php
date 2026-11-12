<?php

declare(strict_types=1);

namespace Portfolio\IncidentState;

use RuntimeException;
use Portfolio\Support\BoundedReader;
use Portfolio\Support\UniqueJsonKeys;

final class StateStore
{
    public const MAX_STATE_BYTES = 5_000_000;
    public function __construct(private readonly string $path)
    {
    }

    /** @template T
     * @param callable(array<string,mixed>):array{state:array<string,mixed>,result:T} $transform
     * @return T
     */
    public function transaction(callable $transform): mixed
    {
        $dir = dirname($this->path);
        if (!is_dir($dir) || !is_writable($dir)) {
            throw new RuntimeException('State directory missing or not writable.');
        }
        $lockPath = $this->path . '.lock';
        if (is_link($this->path) || is_link($lockPath)) {
            throw new RuntimeException('Refusing symlink state or lock path.');
        }
        $lock = @fopen($lockPath, 'c');
        if ($lock === false) {
            throw new RuntimeException('Could not open state lock.');
        }
        try {
            @chmod($lockPath, 0600);
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Could not lock state.');
            }
            $state = $this->read();
            $output = $transform($state);
            if (!is_array($output) || !isset($output['state']) || !array_key_exists('result', $output)) {
                throw new RuntimeException('Transaction callback returned malformed data.');
            }
            $this->write($output['state']);
            return $output['result'];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Explicit one-time migration of pre-outbox legacy state. There is no way
     * to reconstruct undelivered alerts from a missing outbox. The caller must
     * acknowledge that risk, and the original is backed up before replacement.
     * Existing current-schema files can never be migrated by this method.
     */
    public function migrateLegacyWithBackup(bool $acknowledgeUnrecoverableAlerts): string
    {
        if (!$acknowledgeUnrecoverableAlerts) {
            throw new RuntimeException('Migration requires explicit acknowledgment of possibly lost historical alerts.');
        }
        if (!is_file($this->path) || is_link($this->path) || is_link($this->path . '.lock')) {
            throw new RuntimeException('Migration requires an existing regular state file.');
        }
        $lock = @fopen($this->path . '.lock', 'c');
        if ($lock === false) { throw new RuntimeException('Cannot acquire legacy migration lock.'); }
        try {
            @chmod($this->path . '.lock', 0600);
            if (!flock($lock, LOCK_EX)) { throw new RuntimeException('Cannot lock legacy state.'); }
            $raw = BoundedReader::read($this->path, self::MAX_STATE_BYTES);
            UniqueJsonKeys::assertUnique($raw);
            $typed = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
            self::validateJsonShapes($typed);
            $state = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($state) || ($state['schema_version'] ?? null) !== 1 ||
                array_key_exists('outbox', $state) || !is_array($state['modes'] ?? null)) {
                throw new RuntimeException('Only a genuine version-1 state missing an outbox can be explicitly migrated.');
            }
            foreach ($state['modes'] as $name => $history) {
                if (!in_array($name, ['uptime', 'integrity'], true) || !is_array($history)) {
                    throw new RuntimeException('Invalid legacy incident mode.');
                }
                StateEngine::validateHistory($history);
            }
            $state['schema_version'] = 2;
            $state['outbox'] = [];
            // Validation must succeed before creating the backup or changing data.
            $candidate = $state;
            $candidate['outbox'] = (object) [];
            $candidate['modes'] = $candidate['modes'] === [] ? (object) [] : $candidate['modes'];
            foreach (['uptime', 'integrity'] as $mode) {
                if (isset($candidate['modes'][$mode]) && is_array($candidate['modes'][$mode])) {
                    foreach (['issues','unknown_history'] as $field) {
                        if (isset($candidate['modes'][$mode][$field]) && $candidate['modes'][$mode][$field] === []) {
                            $candidate['modes'][$mode][$field] = (object) [];
                        }
                    }
                }
            }
            self::decodeValidated(json_encode($candidate, JSON_THROW_ON_ERROR));
            $backup = $this->path . '.before-explicit-v2-' . bin2hex(random_bytes(6)) . '.bak';
            $copy = @fopen($backup, 'x');
            if ($copy === false) { throw new RuntimeException('Cannot create exclusive backup.'); }
            try {
                @chmod($backup, 0600);
                $written = 0;
                while ($written < strlen($raw)) {
                    $count = fwrite($copy, substr($raw, $written));
                    if ($count === false || $count === 0) {
                        throw new RuntimeException('Legacy backup write failed.');
                    }
                    $written += $count;
                }
                if (!fflush($copy) || (function_exists('fsync') && !fsync($copy))) {
                    throw new RuntimeException('Backup was not completely persisted.');
                }
            } finally { fclose($copy); }
            $this->write($state);
            return $backup;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    /** @return array<string,mixed> */
    private function read(): array
    {
        if (!file_exists($this->path)) {
            return ['schema_version' => 2, 'modes' => [], 'outbox' => []];
        }
        if (!is_file($this->path) || !is_readable($this->path)) {
            throw new RuntimeException('State file is unreadable.');
        }
        try {
            $raw = BoundedReader::read($this->path, self::MAX_STATE_BYTES);
        } catch (\InvalidArgumentException $e) {
            throw new RuntimeException('State file cannot be read safely.', 0, $e);
        }
        return self::decodeValidated($raw);

    }

    /**
     * Single state acceptance contract. Both reads and proposed writes must
     * pass the same JSON object/list and incident-history validations.
     * @return array<string,mixed>
     */
    private static function decodeValidated(string $raw): array
    {
        try {
            $typed = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
            UniqueJsonKeys::assertUnique($raw);
            self::validateJsonShapes($typed);
            $state = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new RuntimeException('Invalid JSON state; no changes were committed.', 0, $e);
        }
        if (!is_array($state) || !in_array(($state['schema_version'] ?? null), [1, 2], true) ||
            !isset($state['modes']) || !is_array($state['modes'])) {
            throw new RuntimeException('Unknown state schema; no changes were committed.');
        }
        // Version 1 is accepted only if it already retains the outbox, or is
        // a genuinely empty pre-monitoring envelope. Nonempty legacy history
        // without an outbox is ambiguous: events may have been deleted.
        // Require an explicit, backed-up operator migration instead of
        // silently erasing undelivered incident notifications.
        if (!array_key_exists('outbox', $state) &&
            ($state['schema_version'] === 2 || $state['modes'] !== [])) {
            throw new RuntimeException('Missing outbox in monitored state; restore backup or explicitly migrate legacy history.');
        }
        foreach (array_keys($state) as $field) {
            if (!in_array($field, ['schema_version','modes','outbox'], true)) {
                throw new RuntimeException('Unknown state envelope field; state unchanged.');
            }
        }
        $modes = $state['modes'];
        if (array_is_list($modes) && $modes !== []) {
            throw new RuntimeException('Malformed state mode map; no changes committed.');
        }
        foreach ($modes as $name => $history) {
            if (!in_array($name, ['uptime', 'integrity'], true) || !is_array($history)) {
                throw new RuntimeException('Unknown or malformed incident mode; state unchanged.');
            }
            try { StateEngine::validateHistory($history); }
            catch (\InvalidArgumentException $e) {
                throw new RuntimeException('Corrupt incident history in ' . $name . '; state unchanged.', 0, $e);
            }
        }
        // This also enforces event-id and claim schemas in the outgoing state.
        foreach (($state['outbox'] ?? []) as $name => $box) {
            if (!in_array($name, ['uptime', 'integrity'], true)) {
                throw new RuntimeException('Unknown event outbox mode.');
            }
            // EventOutbox performs full entry validation during staging.
            \Portfolio\IncidentState\EventOutbox::validateMode($box);
        }
        return $state;
    }

    /** Validate JSON list/object identity before associative decoding. */
    private static function validateJsonShapes(mixed $value): void
    {
        if (!$value instanceof \stdClass || !property_exists($value, 'modes') ||
            !$value->modes instanceof \stdClass ||
            (property_exists($value, 'outbox') && !$value->outbox instanceof \stdClass)) {
            throw new RuntimeException('State JSON object envelope is malformed; state unchanged.');
        }
        foreach ($value->modes as $mode) {
            if (!$mode instanceof \stdClass) {
                throw new RuntimeException('State mode must be a JSON object.');
            }
            foreach (['issues', 'unknown_history'] as $field) {
                if (property_exists($mode, $field) && !$mode->$field instanceof \stdClass) {
                    throw new RuntimeException('State history must be a JSON object.');
                }
            }
            foreach (['inventory', 'unknown'] as $field) {
                if (property_exists($mode, $field) && !is_array($mode->$field)) {
                    throw new RuntimeException('State target collection must be a JSON array.');
                }
            }
        }
        foreach (($value->outbox ?? new \stdClass()) as $box) {
            if (!$box instanceof \stdClass || !property_exists($box, 'pending') ||
                !is_array($box->pending) || !property_exists($box, 'claim') ||
                ($box->claim !== null && !$box->claim instanceof \stdClass)) {
                throw new RuntimeException('State outbox must contain object entries.');
            }
            foreach ($box->pending as $entry) {
                if (!$entry instanceof \stdClass || !property_exists($entry, 'event') ||
                    !$entry->event instanceof \stdClass) {
                    throw new RuntimeException('Pending event must be a JSON object.');
                }
            }
        }
    }

    /** @param array<string,mixed> $state */
    private function write(array $state): void
    {
        // A PHP empty array is JSON []; incident maps are always JSON objects.
        // Normalize solely at the disk boundary, preserving composable in-memory arrays.
        $state['schema_version'] = 2;
        if (!array_key_exists('outbox', $state)) { $state['outbox'] = []; }
        if ($state['outbox'] === []) { $state['outbox'] = (object) []; }
        foreach (['uptime', 'integrity'] as $mode) {
            if (!isset($state['modes'][$mode]) || !is_array($state['modes'][$mode])) {
                continue;
            }
            foreach (['issues', 'unknown_history'] as $field) {
                if (isset($state['modes'][$mode][$field]) && $state['modes'][$mode][$field] === []) {
                    $state['modes'][$mode][$field] = (object) [];
                }
            }
        }
        if (isset($state['modes']) && $state['modes'] === []) {
            $state['modes'] = (object) [];
        }
        $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        // The writer must not commit a value rejected by its own next read.
        // Normalize object/list identities first, then apply the exact reader
        // contract to the serialized bytes before touching the target file.
        self::decodeValidated($json);
        if (strlen($json) > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Serialized state exceeds the readable size limit; no changes were committed. Drain pending events.');
        }
        $tmp = @tempnam(dirname($this->path), '.state-');
        if ($tmp === false) {
            throw new RuntimeException('Cannot create temporary state.');
        }
        try {
            @chmod($tmp, 0600);
            $handle = @fopen($tmp, 'wb');
            if ($handle === false) {
                throw new RuntimeException('Cannot open temporary state.');
            }
            try {
                $length = strlen($json);
                $written = 0;
                while ($written < $length) {
                    $count = fwrite($handle, substr($json, $written));
                    if ($count === false || $count === 0) {
                        throw new RuntimeException('Incomplete state write.');
                    }
                    $written += $count;
                }
                if (!fflush($handle)) {
                    throw new RuntimeException('State flush failed.');
                }
                if (function_exists('fsync') && !fsync($handle)) {
                    throw new RuntimeException('State file sync failed.');
                }
            } finally {
                fclose($handle);
            }
            if (!@rename($tmp, $this->path)) {
                throw new RuntimeException('Atomic state replacement failed.');
            }
            if (function_exists('fsync') && PHP_OS_FAMILY !== 'Windows') {
                // Rename has ALREADY committed the new readable file. A failed
                // directory sync is a durability warning, not an uncommitted
                // transaction. Never throw a false pre-commit failure here.
                $directory = @fopen(dirname($this->path), 'r');
                if ($directory !== false) {
                    try {
                        if (!@fsync($directory)) {
                            // The caller must not retry this committed transition.
                            // A host power-loss may still lose the directory entry.
                            @error_log('Monitor warning: directory metadata sync unavailable after commit.');
                        }
                    } finally { fclose($directory); }
                } else {
                    @error_log('Monitor warning: cannot open directory for post-commit sync.');
                }
            }
        } finally {
            if (file_exists($tmp)) {
                @unlink($tmp);
            }
        }
    }
}
