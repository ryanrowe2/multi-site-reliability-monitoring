<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

// This tool is deliberately not part of the monitoring loop. Only an operator
// who has reviewed the old state and understands possible alert loss may run it.
if (count($argv) !== 4 || $argv[1] !== '--state' ||
    $argv[3] !== '--acknowledge-unrecoverable-historical-alerts') {
    fwrite(STDERR, "Usage: php tools/migrate_legacy_state.php --state FILE --acknowledge-unrecoverable-historical-alerts\n");
    exit(1);
}
try {
    $backup = (new \Portfolio\IncidentState\StateStore($argv[2]))->migrateLegacyWithBackup(true);
    fwrite(STDOUT, "Legacy state migrated to version 2. Backup: " . $backup . "\n");
} catch (Throwable $error) {
    fwrite(STDERR, "Legacy state was not migrated: " . $error->getMessage() . "\n");
    exit(1);
}
