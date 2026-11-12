#!/usr/bin/env php
<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use Portfolio\IncidentState\EventOutbox;
use Portfolio\IncidentState\OutboxCapacityException;
use Portfolio\IncidentState\StateEngine;
use Portfolio\IncidentState\StateStore;
use Portfolio\Integrity\IntegrityScanner;
use Portfolio\Monitoring\Classifier;
use Portfolio\Support\Config;
use Portfolio\Support\BoundedReader;
use Portfolio\Support\UniqueJsonKeys;

function usage(): string
{
    return <<<'TEXT'
Multi-Site Infrastructure Monitoring — synthetic, offline demonstration
Usage:
  php bin/monitor.php uptime --config config/demo.json --responses examples/responses/healthy.json --state var/demo-state.json [--at 2026-01-01T00:00:00Z]
  php bin/monitor.php integrity --config config/demo.json --state var/integrity-state.json [--at 2026-01-01T00:00:00Z]
  php bin/monitor.php flush --mode uptime --state var/demo-uptime-state.json
  php bin/monitor.php --help

No live network requests are made. Each complete synthetic observation is required.
JSON is emitted to stdout; a persistent event outbox replays failed output handoffs.
Exit codes: 0 = monitoring/flush completed; 1 = input/output/state error; 2 = existing alerts delivered while new monitoring was deferred by backpressure.
TEXT;
}

/** A failed write must fail the command; stdout is the explicit handoff boundary. */
function emitJson(array $payload): void
{
    $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    $length = strlen($json);
    $pos = 0;
    while ($pos < $length) {
        $n = @fwrite(STDOUT, substr($json, $pos));
        if ($n === false || $n === 0) {
            throw new RuntimeException('stdout delivery failed; events remain pending for replay.');
        }
        $pos += $n;
    }
    if (!@fflush(STDOUT)) {
        throw new RuntimeException('stdout flush failed; events remain pending for replay.');
    }
}

try {
    $args = array_slice($argv, 1);
    if ($args === [] || $args === ['--help'] || $args === ['-h']) {
        echo usage() . PHP_EOL;
        exit(0);
    }
    $mode = array_shift($args);
    if (!in_array($mode, ['uptime', 'integrity', 'flush'], true)) {
        throw new InvalidArgumentException('Mode must be uptime, integrity or flush.');
    }
    $options = [];
    while ($args !== []) {
        $name = array_shift($args);
        if (!is_string($name) || !in_array($name, ['--config', '--responses', '--state', '--at', '--mode'], true) || isset($options[$name])) {
            throw new InvalidArgumentException('Unknown or duplicated CLI option.');
        }
        $value = array_shift($args);
        if ($value === null || str_starts_with($value, '--') || $value === '') {
            throw new InvalidArgumentException('Missing CLI option value.');
        }
        $options[$name] = $value;
    }
    $root = dirname(__DIR__);
    if ($mode === 'flush') {
        if (!isset($options['--state'], $options['--mode']) ||
            !in_array($options['--mode'], ['uptime', 'integrity'], true) ||
            count($options) !== 2) {
            throw new InvalidArgumentException('flush requires exactly --state FILE and --mode uptime|integrity.');
        }
        $flushMode = $options['--mode'];
        $flushStore = new StateStore($options['--state']);
        $batch = $flushStore->transaction(static function (array $state) use ($flushMode): array {
            $delivery = EventOutbox::stage($state, $flushMode, [], time());
            return ['state' => $delivery['state'], 'result' => $delivery];
        });
        try {
            emitJson(['mode' => $flushMode, 'type' => 'outbox_replay',
                'events' => $batch['events'], 'source' => 'synthetic_offline_demo']);
        } catch (Throwable $e) {
            if ($batch['token'] !== null) {
                $flushStore->transaction(static fn (array $state): array => [
                    'state' => EventOutbox::acknowledge($state, $flushMode, $batch['token'], false), 'result' => null,
                ]);
            }
            throw $e;
        }
        if ($batch['token'] !== null) {
            $flushStore->transaction(static fn (array $state): array => [
                'state' => EventOutbox::acknowledge($state, $flushMode, $batch['token'], true), 'result' => null,
            ]);
        }
        exit(0);
    }
    if (isset($options['--mode'])) {
        throw new InvalidArgumentException('--mode is valid only with flush.');
    }
    $config = Config::load($options['--config'] ?? $root . '/config/demo.json', $mode);
    $statePath = $options['--state'] ?? $root . '/var/demo-' . $mode . '-state.json';
    if (is_link($statePath) || is_link($statePath . '.lock')) {
        throw new InvalidArgumentException('State path and lock path must not be symlinks.');
    }
    $atString = $options['--at'] ?? gmdate('Y-m-d\TH:i:s\Z');
    if (!preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/D', $atString)) {
        throw new InvalidArgumentException('Timestamp must be an ISO UTC timestamp ending in Z.');
    }
    $atDate = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $atString, new DateTimeZone('UTC'));
    if ($atDate === false || $atDate->format('Y-m-d\TH:i:s\Z') !== $atString) {
        throw new InvalidArgumentException('Invalid timestamp.');
    }
    $at = $atDate->getTimestamp();
    $observations = [];
    $fingerprints = [];
    $coreFingerprints = [];
    $issues = [];
    $unknown = [];
    if ($mode === 'uptime') {
        if (!isset($options['--responses'])) {
            throw new InvalidArgumentException('Uptime requires an offline --responses file.');
        }
        $raw = BoundedReader::read($options['--responses'], 5_000_000);
        // Reject ambiguous host and nested observation keys before json_decode overwrites them.
        UniqueJsonKeys::assertUnique($raw);
        $rows = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($rows) || array_is_list($rows) || count($rows) !== count($config['hosts'])) {
            throw new InvalidArgumentException('Fixture must contain exactly one observation per configured host.');
        }
        foreach ($config['hosts'] as $host) {
            if (!isset($rows[$host]) || !is_array($rows[$host])) {
                throw new InvalidArgumentException('Missing or invalid host observation.');
            }
            $result = Classifier::classify($host, $rows[$host], $config['content_policies'][$host] ?? []);
            $observations[$host] = $result;
            if ($result['healthy'] === false) {
                $issues[$host] = ['code' => $result['code'], 'detail' => $result['detail']];
            } elseif ($result['healthy'] === null) {
                $unknown[] = $host;
            }
        }
        if (array_diff(array_keys($rows), $config['hosts']) !== []) {
            throw new InvalidArgumentException('Unexpected observation host.');
        }
        $inventory = $config['hosts'];
    } else {
        if (isset($options['--responses'])) {
            throw new InvalidArgumentException('--responses is only supported in uptime mode.');
        }
        $integrity = IntegrityScanner::scan($config['integrity']);
        $issues = $integrity['issues'];
        $fingerprints = $integrity['fingerprints'];
        $coreFingerprints = $integrity['core_fingerprints'];
        $inventory = $config['integrity']['sites'];
    }
    $store = new StateStore($statePath);
    $staged = $store->transaction(static function (array $state) use ($mode, $issues, $at, $config, $inventory, $unknown): array {
        $originalState = $state;
        if (!isset($state['modes']) || !is_array($state['modes'])) {
            throw new RuntimeException('Invalid mode map.');
        }
        $before = $state['modes'][$mode] ?? [];
        if (!is_array($before)) {
            throw new RuntimeException('Invalid mode history.');
        }
        $transition = StateEngine::transition($before, $issues, $at, $config['reminder_seconds'][$mode], $inventory, $unknown,
            $config['unverified_threshold_seconds'], $config['unverified_reminder_seconds']);
        $state['modes'][$mode] = $transition['mode_state'];
        $previousRun = $before['last_run'] ?? null;
        $gap = is_int($previousRun) ? $at - $previousRun : null;
        $expected = $config['expected_interval_seconds'][$mode];
        try {
            $delivery = EventOutbox::stage($state, $mode, $transition['events'], time());
            return ['state' => $delivery['state'], 'result' => ['events' => $delivery['events'], 'token' => $delivery['token'],
                'deferred' => false,
                'gap_seconds' => $gap, 'monitoring_gap_exceeded' => $gap !== null && $expected !== null && $gap > 2 * $expected]];
        } catch (OutboxCapacityException $e) {
            // No incident changes have been committed. Deliver an existing batch so
            // this backlog can shrink even during continuous fresh event churn.
            $drain = EventOutbox::stage($originalState, $mode, [], time());
            if ($drain['token'] === null) {
                throw new OutboxCapacityException('Outbox is full and an existing delivery claim is active; retry after the lease expires.');
            }
            return ['state' => $drain['state'], 'result' => ['events' => $drain['events'], 'token' => $drain['token'],
                'deferred' => true, 'gap_seconds' => null, 'monitoring_gap_exceeded' => null]];
        }
    });
    $token = $staged['token'];
    try {
        if ($staged['deferred']) {
            emitJson(['mode' => $mode, 'type' => 'backpressure_drain', 'monitoring_deferred' => true,
                'events' => $staged['events'], 'source' => 'synthetic_offline_demo']);
        } else {
        emitJson([
            'mode' => $mode, 'timestamp_utc' => $atString,
            'events' => $staged['events'],
            'active_issues' => $issues === [] ? (object) [] : $issues,
            'unverified_targets' => $unknown,
            'gap_since_previous_run_seconds' => $staged['gap_seconds'],
            'monitoring_gap_exceeded' => $staged['monitoring_gap_exceeded'],
            'observations' => $observations === [] ? (object) [] : $observations,
            'fingerprints' => $fingerprints === [] ? (object) [] : $fingerprints,
            'core_fingerprints' => $coreFingerprints === [] ? (object) [] : $coreFingerprints,
            'source' => 'synthetic_offline_demo',
        ]);
        }
    } catch (Throwable $e) {
        if ($token !== null) {
            // Release our claim immediately; pending events survive to the next run.
            $store->transaction(static fn (array $state): array => [
                'state' => EventOutbox::acknowledge($state, $mode, $token, false), 'result' => null,
            ]);
        }
        throw $e;
    }
    if ($token !== null) {
        // After stdout handoff, acknowledge the journal. A crash here causes replay, not loss.
        $store->transaction(static fn (array $state): array => [
            'state' => EventOutbox::acknowledge($state, $mode, $token, true), 'result' => null,
        ]);
    }
    if ($staged['deferred']) {
        exit(2);
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
