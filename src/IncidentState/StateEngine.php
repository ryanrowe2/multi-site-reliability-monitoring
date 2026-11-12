<?php

declare(strict_types=1);

namespace Portfolio\IncidentState;

use InvalidArgumentException;
use stdClass;

/** Pure incident transition. A generated event is an outbox candidate, not delivery evidence. */
final class StateEngine
{
    /**
     * @param array<string,mixed> $previous
     * @param array<string,array{code:string,detail:string}> $current
     * @param list<string>|null $inventory Explicit current inventory (null retains legacy all-observed scope).
     * @param list<string> $unknown Targets not confirmed healthy or failed.
     * @return array{mode_state:array<string,mixed>,events:list<array<string,mixed>>}
     */
    public static function transition(
        array $previous,
        array $current,
        int $at,
        int $reminderSeconds,
        ?array $inventory = null,
        array $unknown = [],
        int $unverifiedThresholdSeconds = 3600,
        ?int $unverifiedReminderSeconds = null
    ): array {
        $unverifiedReminderSeconds ??= $reminderSeconds;
        if ($at < 0 || $reminderSeconds < 1 || $unverifiedThresholdSeconds < 1 || $unverifiedReminderSeconds < 1) {
            throw new InvalidArgumentException('Invalid clock or reminder interval.');
        }
        self::validateHistory($previous, $at);
        $old = self::readMap($previous, 'issues');
        $oldUnknown = self::readMap($previous, 'unknown_history');
        $inventory ??= array_values(array_unique(array_merge(array_keys($old), array_keys($oldUnknown), array_keys($current))));
        self::validateNames($inventory, 'inventory');
        self::validateNames($unknown, 'unknown target');
        $active = array_fill_keys($inventory, true);
        $unknownSet = array_fill_keys($unknown, true);
        foreach ($unknown as $key) {
            if (!isset($active[$key]) || array_key_exists($key, $current)) {
                throw new InvalidArgumentException('Unknown target must be in scope and have no confirmed incident.');
            }
        }
        ksort($current, SORT_STRING);
        $next = [];
        $events = [];
        foreach ($current as $key => $issue) {
            if (!is_string($key) || $key === '' || !isset($active[$key]) || !is_array($issue) ||
                !isset($issue['code'], $issue['detail']) || !is_string($issue['code']) ||
                !is_string($issue['detail']) || $issue['code'] === '') {
                throw new InvalidArgumentException('Current incident is malformed or outside inventory.');
            }
            EventSchema::issue($key, $issue);
            // Last confirmed failure may have been suspended during an unverified period.
            $prev = $old[$key] ?? ($oldUnknown[$key]['last_confirmed_issue'] ?? null);
            $type = null;
            if ($prev === null) {
                $type = 'new';
            } elseif ($prev['code'] !== $issue['code'] || $prev['detail'] !== $issue['detail']) {
                $type = 'changed';
            } elseif ($at - $prev['last_notified'] >= $reminderSeconds) {
                $type = 'reminder';
            }
            $next[$key] = [
                'code' => $issue['code'], 'detail' => $issue['detail'],
                'first_seen' => $prev !== null && $type !== 'changed' ? $prev['first_seen'] : $at,
                'last_seen' => $at,
                'last_notified' => $type !== null ? $at : $prev['last_notified'],
            ];
            if ($type !== null) {
                $events[] = ['type' => $type, 'target' => $key, 'code' => $issue['code'], 'detail' => $issue['detail'], 'at' => $at];
            }
        }
        foreach ($old as $key => $record) {
            if (array_key_exists($key, $current)) {
                continue;
            }
            if (isset($unknownSet[$key])) {
                // Move the last confirmed failure into unverified history below;
                // do not claim it is actively confirmed failed while unverified.
                continue;
            } else {
                $events[] = [
                    'type' => isset($active[$key]) ? 'recovered' : 'retired',
                    'target' => $key, 'code' => $record['code'], 'detail' => $record['detail'], 'at' => $at,
                ];
            }
        }
        // A formerly unverified host that carried a suspended confirmed failure
        // must emit recovery only after an actual healthy observation. Its
        // failure was not erased merely because subsequent checks were unknown.
        foreach ($oldUnknown as $key => $record) {
            if (!isset($record['last_confirmed_issue']) || isset($unknownSet[$key]) || array_key_exists($key, $current)) {
                continue;
            }
            $issue = $record['last_confirmed_issue'];
            $events[] = [
                'type' => isset($active[$key]) ? 'recovered' : 'retired',
                'target' => $key, 'code' => $issue['code'], 'detail' => $issue['detail'], 'at' => $at,
            ];
        }
        // Close a previously escalated verification gap only after an actual
        // verified observation, or retire it if removed from the inventory.
        foreach ($oldUnknown as $key => $record) {
            if (isset($unknownSet[$key]) || $record['last_notified'] === null) {
                continue;
            }
            $events[] = [
                'type' => isset($active[$key]) ? 'verification_restored' : 'verification_retired',
                'target' => $key,
                'code' => 'unverified',
                'detail' => isset($active[$key]) ? 'Target health verification resumed' : 'Target removed from verified inventory',
                'at' => $at,
            ];
        }
        $nextUnknown = [];
        foreach ($unknown as $key) {
            $prev = $oldUnknown[$key] ?? null;
            $first = $prev['first_seen'] ?? $at;
            $notified = $prev['last_notified'] ?? null;
            $type = null;
            if ($at - $first >= $unverifiedThresholdSeconds) {
                if ($notified === null) {
                    $type = 'verification_gap';
                } elseif ($at - $notified >= $unverifiedReminderSeconds) {
                    $type = 'verification_gap_reminder';
                }
            }
            $nextUnknown[$key] = ['first_seen' => $first, 'last_seen' => $at,
                'last_notified' => $type !== null ? $at : $notified];
            $suspended = $old[$key] ?? ($prev['last_confirmed_issue'] ?? null);
            if ($suspended !== null) {
                $nextUnknown[$key]['last_confirmed_issue'] = $suspended;
            }
            if ($type !== null) {
                $events[] = ['type' => $type, 'target' => $key, 'code' => 'unverified',
                    'detail' => 'Target health could not be verified', 'at' => $at];
            }
        }
        ksort($next, SORT_STRING);
        ksort($nextUnknown, SORT_STRING);
        usort($events, static fn (array $a, array $b): int => strcmp($a['target'], $b['target']) ?: strcmp($a['type'], $b['type']));
        sort($inventory, SORT_STRING);
        sort($unknown, SORT_STRING);
        // Keep *arrays* in memory; the persistence layer serializes empty maps as {}.
        return ['mode_state' => [
            'issues' => $next,
            'last_run' => $at,
            'inventory' => $inventory,
            'unknown' => $unknown,
            'unknown_history' => $nextUnknown,
        ], 'events' => $events];
    }

    /** @param array<string,mixed> $previous */
    public static function validateHistory(array $previous, ?int $at = null): void
    {
        $at ??= PHP_INT_MAX;
        if (array_key_exists('last_run', $previous) &&
            (!is_int($previous['last_run']) || $previous['last_run'] < 0 || $at < $previous['last_run'])) {
            throw new InvalidArgumentException('Clock moved backwards or prior state is malformed.');
        }
        $lastRun = $previous['last_run'] ?? null;
        // Never normalize missing confirmed-incident history in an existing
        // snapshot: that would erase unresolved incidents and their recoveries.
        // The only valid empty initial state is the entirely empty array.
        if ($previous !== [] && !array_key_exists('issues', $previous)) {
            throw new InvalidArgumentException('Missing incident history; explicit migration required.');
        }
        $old = self::readMap($previous, 'issues');
        foreach ($old as $key => $record) {
            self::validateIssueRecord($key, $record, $at, $lastRun);
        }
        $oldUnknown = self::readMap($previous, 'unknown_history');
        foreach ($oldUnknown as $key => $record) {
            if (!is_string($key) || $key === '' || !is_array($record) ||
                !isset($record['first_seen'], $record['last_seen']) || !array_key_exists('last_notified', $record) ||
                !is_int($record['first_seen']) || !is_int($record['last_seen']) ||
                ($record['last_notified'] !== null && !is_int($record['last_notified'])) ||
                $record['first_seen'] < 0 || $record['first_seen'] > $record['last_seen'] ||
                $record['last_seen'] > $at || ($lastRun !== null && $record['last_seen'] > $lastRun) ||
                ($record['last_notified'] !== null &&
                    ($record['last_notified'] < $record['first_seen'] || $record['last_notified'] > $record['last_seen']))) {
                throw new InvalidArgumentException('Prior unverified history is malformed.');
            }
            if (array_key_exists('last_confirmed_issue', $record)) {
                self::validateIssueRecord($key, $record['last_confirmed_issue'], $at, $lastRun);
                if ($record['last_confirmed_issue']['last_seen'] > $record['first_seen']) {
                    throw new InvalidArgumentException('Suspended confirmed failure occurred after verification was lost.');
                }
            }
        }
        // A target cannot be concurrently confirmed failed and unverified.
        // Earlier snapshots that represented this overlap must be explicitly
        // migrated, not silently accepted or used to fabricate closure events.
        if (array_intersect_key($old, $oldUnknown) !== []) {
            throw new InvalidArgumentException('Contradictory confirmed-failure and unverified history.');
        }
        foreach (['inventory', 'unknown'] as $name) {
            if (array_key_exists($name, $previous)) {
                if (!is_array($previous[$name])) {
                    throw new InvalidArgumentException('Prior ' . $name . ' must be a list.');
                }
                self::validateNames($previous[$name], 'prior ' . $name);
            }
        }
        // The pre-verification legacy format has none of these fields. Once
        // any is present, require the entire current-format history; otherwise
        // a missing unknown_history would silently discard an active gap.
        $verificationFields = ['inventory', 'unknown', 'unknown_history'];
        $presentFields = array_filter($verificationFields, static fn (string $field): bool => array_key_exists($field, $previous));
        if ($presentFields !== [] && (count($presentFields) !== 3 || !array_key_exists('last_run', $previous))) {
            throw new InvalidArgumentException('Incomplete verification history; explicit migration required.');
        }
        // A current-format snapshot must be internally consistent. Historical
        // records cannot name a target that never existed in the last inventory
        // or claim a verification gap that the prior unknown list does not hold.
        if (array_key_exists('inventory', $previous)) {
            $known = array_fill_keys($previous['inventory'], true);
            foreach (array_merge(array_keys($old), array_keys($oldUnknown), $previous['unknown'] ?? []) as $key) {
                if (!isset($known[$key])) {
                    throw new InvalidArgumentException('History references a target outside previous inventory.');
                }
            }
        }
        if (array_key_exists('unknown', $previous) && array_key_exists('unknown_history', $previous)) {
            $recorded = array_keys($oldUnknown);
            $listed = $previous['unknown'];
            sort($recorded, SORT_STRING);
            sort($listed, SORT_STRING);
            if ($recorded !== $listed) {
                throw new InvalidArgumentException('Verification history does not match previous unknown inventory.');
            }
        }
    }

    /** Validate a confirmed or suspended issue record. */
    private static function validateIssueRecord(mixed $key, mixed $record, int $at, ?int $lastRun): void
    {
        if (!is_string($key) || $key === '' || !is_array($record) ||
            !isset($record['code'], $record['detail'], $record['first_seen'], $record['last_seen'], $record['last_notified']) ||
            !is_string($record['code']) || $record['code'] === '' || strlen($record['code']) > 128 ||
            !is_string($record['detail']) || strlen($record['detail']) > 2048 || strlen($key) > 253 ||
            !is_int($record['first_seen']) || !is_int($record['last_seen']) || !is_int($record['last_notified']) ||
            $record['first_seen'] < 0 || $record['last_seen'] < 0 || $record['last_notified'] < 0 ||
            $record['first_seen'] > $record['last_notified'] || $record['last_notified'] > $record['last_seen'] ||
            $record['last_seen'] > $at || ($lastRun !== null && $record['last_seen'] > $lastRun)) {
            throw new InvalidArgumentException('Prior incident record is malformed.');
        }
    }

    /** @param array<string,mixed> $state @return array<string,mixed> */
    private static function readMap(array $state, string $name): array
    {
        if (!array_key_exists($name, $state)) {
            return []; // Legitimate legacy snapshot without this newer field.
        }
        $map = $state[$name];
        if ($map instanceof stdClass && get_object_vars($map) === []) {
            return []; // Old in-memory engine emitted stdClass for empty maps.
        }
        if (!is_array($map) || (array_is_list($map) && $map !== [])) {
            throw new InvalidArgumentException('Prior ' . $name . ' must be an object.');
        }
        return $map;
    }

    /** @param list<string> $names */
    private static function validateNames(array $names, string $label): void
    {
        if (!array_is_list($names)) {
            throw new InvalidArgumentException('Malformed ' . $label . ' list.');
        }
        foreach ($names as $name) {
            if (!is_string($name) || $name === '' || strlen($name) > 253) {
                throw new InvalidArgumentException('Invalid ' . $label . ' name.');
            }
        }
        if (count($names) !== count(array_unique($names))) {
            throw new InvalidArgumentException('Duplicate ' . $label . '.');
        }
    }
}
