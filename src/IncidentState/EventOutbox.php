<?php

declare(strict_types=1);

namespace Portfolio\IncidentState;

use RuntimeException;

/** Bounded at-least-once stdout journal. Delivery IDs survive a crash or replay. */
final class EventOutbox
{
    private const LEASE_SECONDS = 120;
    private const MAX_BACKWARD_SKEW_SECONDS = 300;
    private const MAX_PENDING = 10000;
    private const DELIVERY_BATCH = 128;
    // Leave substantial headroom for monitoring state and the serialized delivery claim.
    private const QUEUE_BUDGET_BYTES = 3_000_000;

    /** @param array<string,mixed> $state
     * @param list<array<string,mixed>> $events
     * @return array{state:array<string,mixed>,events:list<array<string,mixed>>,token:string|null}
     */
    public static function stage(array $state, string $mode, array $events, int $wallClock): array
    {
        $box = self::readBox($state, $mode);
        $pending = $box['pending'];
        $claim = $box['claim'];
        // A small backward clock correction must not void another worker's
        // live lease. Only wildly future-dated claims are treated as corrupt.
        // This gives bounded tolerance, not cross-host monotonic-time guarantees.
        if ($claim !== null && $claim['until'] > $wallClock + self::LEASE_SECONDS + self::MAX_BACKWARD_SKEW_SECONDS) {
            $claim = null;
        }
        if (count($pending) + count($events) > self::MAX_PENDING) {
            throw new OutboxCapacityException('Pending event count limit reached; drain pending alerts before monitoring again.');
        }
        foreach ($events as $event) {
            self::validateEvent($event);
            $pending[] = ['id' => bin2hex(random_bytes(16)), 'event' => $event];
        }
        $token = null;
        $selected = [];
        if ($pending !== [] && ($claim === null || $claim['until'] <= $wallClock)) {
            $batch = array_slice($pending, 0, self::DELIVERY_BATCH);
            $token = bin2hex(random_bytes(16));
            $claim = ['token' => $token, 'until' => $wallClock + self::LEASE_SECONDS, 'ids' => array_column($batch, 'id')];
            foreach ($batch as $entry) {
                // Keep the event schema stable and expose an idempotency key for receivers.
                $selected[] = ['id' => $entry['id']] + $entry['event'];
            }
        }
        $state['outbox'][$mode] = ['pending' => $pending, 'claim' => $claim];
        // Bound admission by serialized size, not count alone. StateStore enforces a
        // separate final 5-MB cap before rename as the last line of defense.
        $size = strlen(json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        if ($events !== [] && $size > self::QUEUE_BUDGET_BYTES) {
            throw new OutboxCapacityException('Outbox storage budget exceeded; drain existing alerts before admission.');
        }
        if ($size + 1 > StateStore::MAX_STATE_BYTES) {
            throw new OutboxCapacityException('State storage limit reached; drain pending alerts.');
        }
        return ['state' => $state, 'events' => $selected, 'token' => $token];
    }

    /** @param array<string,mixed> $state
     * @return array<string,mixed>
     */
    public static function acknowledge(array $state, string $mode, string $token, bool $delivered): array
    {
        $box = self::readBox($state, $mode);
        $claim = $box['claim'];
        if ($claim === null || $claim['token'] !== $token) {
            throw new RuntimeException('Event claim changed before acknowledgment.');
        }
        $claimedIds = array_fill_keys($claim['ids'], true);
        $remaining = $delivered
            ? array_values(array_filter($box['pending'], static fn (array $item): bool => !isset($claimedIds[$item['id']])))
            : $box['pending'];
        $state['outbox'][$mode] = ['pending' => $remaining, 'claim' => null];
        return $state;
    }

    /** @param array<string,mixed> $state
     * @return array{pending:list<array{id:string,event:array<string,mixed>}>,claim:array{token:string,until:int,ids:list<string>}|null}
     */
    private static function readBox(array $state, string $mode): array
    {
        if (!in_array($mode, ['uptime', 'integrity'], true)) {
            throw new RuntimeException('Unknown outbox mode.');
        }
        if (array_key_exists('outbox', $state)) {
            if (!is_array($state['outbox']) ||
                (array_is_list($state['outbox']) && $state['outbox'] !== [])) {
                throw new RuntimeException('Malformed event outbox envelope; state unchanged.');
            }
            foreach ($state['outbox'] as $name => $box) {
                if (!in_array($name, ['uptime', 'integrity'], true)) {
                    throw new RuntimeException('Unexpected outbox mode; state unchanged.');
                }
                self::validateBox($box); // Validate BOTH modes, even when accessing only one.
            }
        }
        return self::validateBox($state['outbox'][$mode] ?? ['pending' => [], 'claim' => null]);
    }

    /** Validate an outgoing outbox mode using the exact admission schema. */
    public static function validateMode(mixed $box): void
    {
        self::validateBox($box);
    }

    /** @param array<string,mixed> $event */
    private static function validateEvent(array $event): void
    {
        try { EventSchema::event($event); }
        catch (\InvalidArgumentException $e) {
            throw new RuntimeException('Malformed event fields; outbox state unchanged.', 0, $e);
        }
    }

    /** @return array{pending:list<array{id:string,event:array<string,mixed>}>,claim:array{token:string,until:int,ids:list<string>}|null} */
    private static function validateBox(mixed $box): array
    {
        if (!is_array($box) || array_is_list($box) || count($box) !== 2 ||
            !array_key_exists('pending', $box) || !array_key_exists('claim', $box)) {
            throw new RuntimeException('Malformed event outbox mode; state unchanged.');
        }
        $pending = $box['pending'];
        $claim = $box['claim'];
        if (!is_array($pending) || !array_is_list($pending) || count($pending) > self::MAX_PENDING ||
            ($claim !== null && (!is_array($claim) || array_is_list($claim) || count($claim) !== 3 ||
                !is_string($claim['token'] ?? null) ||
                preg_match('/\A[a-f0-9]{32}\z/D', $claim['token']) !== 1 ||
                !is_int($claim['until'] ?? null) || $claim['until'] < 0 ||
                !is_array($claim['ids'] ?? null) || !array_is_list($claim['ids'])))) {
            throw new RuntimeException('Malformed event outbox; state unchanged.');
        }
        $seen = [];
        foreach ($pending as $entry) {
            if (!is_array($entry) || !is_string($entry['id'] ?? null) ||
                !preg_match('/\A[a-f0-9]{32}\z/D', $entry['id']) ||
                isset($seen[$entry['id']]) || !is_array($entry['event'] ?? null) ||
                !is_string($entry['event']['type'] ?? null) ||
                !is_string($entry['event']['target'] ?? null)) {
                throw new RuntimeException('Malformed pending event.');
            }
            self::validateEvent($entry['event']);
            $seen[$entry['id']] = true;
        }
        if ($claim !== null) {
            if (count($claim['ids']) > self::DELIVERY_BATCH || $claim['ids'] === [] ||
                count(array_unique($claim['ids'])) !== count($claim['ids'])) {
                throw new RuntimeException('Malformed delivery claim.');
            }
            foreach ($claim['ids'] as $id) {
                if (!is_string($id) || !isset($seen[$id])) {
                    throw new RuntimeException('Delivery claim references a missing event.');
                }
            }
        }
        return ['pending' => $pending, 'claim' => $claim];
    }
}
