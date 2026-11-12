<?php

declare(strict_types=1);

namespace Portfolio\IncidentState;

use InvalidArgumentException;

/** Common admission contract for new observations and queued event payloads. */
final class EventSchema
{
    public static function issue(string $target, array $issue): void
    {
        if ($target === '' || strlen($target) > 253 || count($issue) !== 2 ||
            !is_string($issue['code'] ?? null) || $issue['code'] === '' || strlen($issue['code']) > 128 ||
            !is_string($issue['detail'] ?? null) || strlen($issue['detail']) > 2048) {
            throw new InvalidArgumentException('Incident exceeds the persistent event contract.');
        }
    }

    public static function event(array $event): void
    {
        $types = ['new', 'changed', 'reminder', 'recovered', 'retired',
            'verification_gap', 'verification_gap_reminder', 'verification_restored', 'verification_retired'];
        if (count($event) !== 5 || array_diff(array_keys($event), ['type','target','code','detail','at']) !== [] ||
            !in_array($event['type'] ?? null, $types, true) ||
            !is_string($event['target'] ?? null) || !is_string($event['code'] ?? null) ||
            !is_string($event['detail'] ?? null) || !is_int($event['at'] ?? null) || $event['at'] < 0) {
            throw new InvalidArgumentException('Malformed event envelope.');
        }
        self::issue($event['target'], ['code' => $event['code'], 'detail' => $event['detail']]);
    }
}
