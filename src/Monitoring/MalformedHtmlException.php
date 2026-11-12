<?php

declare(strict_types=1);

namespace Portfolio\Monitoring;

use InvalidArgumentException;

/** A response body whose markup cannot safely establish page health. */
final class MalformedHtmlException extends InvalidArgumentException
{
}
