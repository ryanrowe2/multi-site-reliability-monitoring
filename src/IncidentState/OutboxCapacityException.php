<?php

declare(strict_types=1);

namespace Portfolio\IncidentState;

use RuntimeException;

/** Capacity backpressure: do not commit incident transitions until queued alerts are drained. */
final class OutboxCapacityException extends RuntimeException
{
}
