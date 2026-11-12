<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

$measureCoverage = in_array('--coverage', $argv, true);
if ($measureCoverage) {
    if (!function_exists('xdebug_start_code_coverage')) {
        fwrite(STDERR, "Coverage requires Xdebug; no coverage result was generated.\n");
        exit(1);
    }
    xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);
}


use Portfolio\Support\Config;
use Portfolio\Monitoring\Classifier;
use Portfolio\IncidentState\StateEngine;
use Portfolio\IncidentState\StateStore;
use Portfolio\Integrity\DirectoryFingerprint;
use Portfolio\Integrity\IntegrityScanner;

$tests = 0;
$failures = 0;
function check(bool $condition, string $message = 'Assertion failed'): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
function same(mixed $a, mixed $b): void
{
    if ($a !== $b) {
        throw new RuntimeException('Expected ' . var_export($a, true) . ' got ' . var_export($b, true));
    }
}
function raises(callable $fn, string $exception = Throwable::class): void
{
    try {
        $fn();
    } catch (Throwable $e) {
        if ($e instanceof $exception) {
            return;
        }
        throw new RuntimeException('Unexpected exception type: ' . get_class($e), 0, $e);
    }
    throw new RuntimeException('Expected exception was not thrown.');
}
function test(string $name, callable $fn): void
{
    global $tests, $failures;
    $tests++;
    try {
        $fn();
        echo 'PASS ' . $name . "\n";
    } catch (Throwable $e) {
        $failures++;
        fwrite(STDERR, 'FAIL ' . $name . ': ' . $e->getMessage() . "\n");
    }
}
function tmp(): string
{
    $p = sys_get_temp_dir() . '/portfolio-monitor-' . bin2hex(random_bytes(8));
    mkdir($p, 0700, true);
    return $p;
}
function deleteTree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            deleteTree($path . '/' . $entry);
        }
    }
    rmdir($path);
}
function cloneTree(string $from, string $to): void
{
    mkdir($to, 0700, true);
    foreach (scandir($from) ?: [] as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        if (is_dir($from . '/' . $item)) {
            cloneTree($from . '/' . $item, $to . '/' . $item);
        } else {
            copy($from . '/' . $item, $to . '/' . $item);
        }
    }
}
function fixtures(): array
{
    $root = dirname(__DIR__);
    $temp = tmp();
    cloneTree($root . '/examples/fixtures/sites', $temp . '/sites');
    $cfg = Config::load($root . '/config/demo.json')['integrity'];
    $cfg['root'] = $temp . '/sites';
    return [$temp, $cfg];
}
function events(array $previous, array $current, int $now, int $reminder = 21600): array
{
    return StateEngine::transition($previous, $current, $now, $reminder);
}
function demoAlert(string $target, string $type = 'new', string $detail = 'Synthetic incident'): array
{
    return ['type' => $type, 'target' => $target, 'code' => 'synthetic_problem', 'detail' => $detail, 'at' => 100];
}
function issue(string $code = 'http_error', string $detail = 'HTTP 500'): array
{
    return ['site-a.example.com' => ['code' => $code, 'detail' => $detail]];
}
function cli(array $args): array
{
    $command = array_merge([PHP_BINARY, dirname(__DIR__) . '/bin/monitor.php'], $args);
    $proc = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Cannot run CLI.');
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $out, $err];
}

foreach ([200] as $status) {
    test("HTTP {$status} default success contract", static function () use ($status): void {
        $observation = ['status_code' => $status];
        if ($status === 200) { $observation['body'] = 'Meaningful content'; }
        same(true, Classifier::classify('site-a.example.com', $observation)['healthy']);
    });
}
foreach ([201, 202, 204, 205, 207, 299] as $status) {
    test("HTTP {$status} without explicit contract is unverified", static function () use ($status): void {
        same('unverified_http_status', Classifier::classify('site-a.example.com', ['status_code'=>$status])['code']);
    });
}
foreach (['connection', 'tls', 'timeout'] as $kind) {
    test("transport {$kind}", static function () use ($kind): void {
        same('transport_' . $kind, Classifier::classify('site-a.example.com', ['transport_error' => $kind])['code']);
    });
}
foreach ([404, 500, 503, 100] as $status) {
    test("HTTP {$status} flagged", static function () use ($status): void {
        same('http_error', Classifier::classify('site-a.example.com', ['status_code' => $status])['code']);
    });
}
test('HTTP 200 critical WordPress error', static function (): void {
    same('application_wp_critical_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => 'THERE HAS BEEN A CRITICAL ERROR ON THIS WEBSITE'])['code']);
});
test('HTTP 200 database failure', static function (): void {
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => 'Error establishing a database connection'])['code']);
});
test('redirect outside expected host', static function (): void {
    same('unexpected_redirect', Classifier::classify('site-a.example.com', ['status_code' => 302, 'redirect_location' => 'https://other.example.org/'])['code']);
});
test('same-host redirect is not falsely healthy', static function (): void {
    same('unverified_redirect', Classifier::classify('site-a.example.com', ['status_code' => 301, 'redirect_location' => 'https://www.site-a.example.com/x'])['code']);
});
test('HTTP redirect without Location', static function (): void {
    same('unresolved_redirect', Classifier::classify('site-a.example.com', ['status_code' => 302])['code']);
});
foreach (['http://site-a.example.com', sprintf('%s://%s@%s', 'https', 'user:pass', 'site-a.example.com'), 'https://site-a.example.com:8080/'] as $url) {
    test('unsafe redirect rejected ' . $url, static function () use ($url): void {
        same('unsafe_redirect', Classifier::classify('site-a.example.com', ['status_code' => 302, 'redirect_location' => $url])['code']);
    });
}
test('unexpected HTTP response data rejected', static function (): void {
    raises(static fn () => Classifier::classify('site-a.example.com', ['transport_error' => 'timeout', 'status_code' => 200]), InvalidArgumentException::class);
});
test('invalid status rejected', static function (): void {
    raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 999]), InvalidArgumentException::class);
});
test('unsupported observation key rejected', static function (): void {
    raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 200, str_rot13('frperg') => 'x']), InvalidArgumentException::class);
});
test('body cap enforced', static function (): void {
    raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => str_repeat('X', 131073)]), InvalidArgumentException::class);
});
test('first incident', static function (): void {
    $r = events([], issue(), 100);
    same('new', $r['events'][0]['type']);
    same(100, $r['mode_state']['issues']['site-a.example.com']['first_seen']);
});
test('unchanged incident suppressed', static function (): void {
    $r = events([], issue(), 100);
    $r2 = events($r['mode_state'], issue(), 200);
    same([], $r2['events']);
    same(100, $r2['mode_state']['issues']['site-a.example.com']['last_notified']);
});
test('changed incident', static function (): void {
    $r = events([], issue(), 100);
    $r2 = events($r['mode_state'], issue('transport_tls', 'Transport tls'), 200);
    same('changed', $r2['events'][0]['type']);
    same(200, $r2['mode_state']['issues']['site-a.example.com']['first_seen']);
});
test('recovery', static function (): void {
    $r = events([], issue(), 100);
    $r2 = events($r['mode_state'], [], 200);
    same('recovered', $r2['events'][0]['type']);
    same([], (array) $r2['mode_state']['issues']);
});
test('six-hour reminder boundary', static function (): void {
    $r = events([], issue(), 100);
    same([], events($r['mode_state'], issue(), 100 + 21600 - 1)['events']);
    same('reminder', events($r['mode_state'], issue(), 100 + 21600)['events'][0]['type']);
});
test('integrity reminder interval honored', static function (): void {
    $r = events([], issue('integrity_problem', 'bad plugin'), 100, 86400);
    same([], events($r['mode_state'], issue('integrity_problem', 'bad plugin'), 100 + 86399, 86400)['events']);
    same('reminder', events($r['mode_state'], issue('integrity_problem', 'bad plugin'), 100 + 86400, 86400)['events'][0]['type']);
});
test('reminders are per-target', static function (): void {
    $first = events([], issue(), 100);
    $more = issue() + ['site-b.example.org' => ['code' => 'http_error', 'detail' => 'HTTP 503']];
    $second = events($first['mode_state'], $more, 200);
    $third = events($second['mode_state'], $more, 100 + 21600);
    same(1, count($third['events']));
    same('site-a.example.com', $third['events'][0]['target']);
});
test('clock rollback rejected', static function (): void {
    $first = events([], issue(), 200);
    raises(static fn () => events($first['mode_state'], issue(), 199), InvalidArgumentException::class);
});
test('malformed previous incident rejected', static function (): void {
    raises(static fn () => events(['issues' => ['site-a.example.com' => ['code' => 'x']]], issue(), 100), InvalidArgumentException::class);
});
test('persist and reload', static function (): void {
    $d = tmp();
    try {
        $store = new StateStore($d . '/state.json');
        $store->transaction(static function (array $state): array {
            $state['modes']['uptime'] = events([], issue(), 100)['mode_state'];
            return ['state' => $state, 'result' => true];
        });
        $events = $store->transaction(static function (array $state): array {
            $result = events($state['modes']['uptime'], issue(), 110);
            $state['modes']['uptime'] = $result['mode_state'];
            return ['state' => $state, 'result' => $result['events']];
        });
        same([], $events);
        same(2, json_decode((string) file_get_contents($d . '/state.json'), true)['schema_version']);
    } finally { deleteTree($d); }
});
test('invalid state JSON preserved', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/state.json', '{broken');
        raises(static fn () => (new StateStore($d . '/state.json'))->transaction(static fn ($state) => ['state' => $state, 'result' => null]), RuntimeException::class);
        same('{broken', file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('failed write/invalid directory propagates', static function (): void {
    raises(static fn () => (new StateStore('/nonexistent-monitor-dir-01/state.json'))->transaction(static fn ($state) => ['state' => $state, 'result' => true]), RuntimeException::class);
});
test('transaction exception leaves state unchanged', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/state.json', '{"schema_version":1,"modes":{}}');
        raises(static fn () => (new StateStore($d . '/state.json'))->transaction(static function ($state): array { throw new RuntimeException('test'); }), RuntimeException::class);
        same('{"schema_version":1,"modes":{}}', file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('demo configuration accepted', static function (): void {
    $cfg = Config::load(dirname(__DIR__) . '/config/demo.json');
    same(2, count($cfg['hosts']));
});
foreach (['127.0.0.1', 'localhost', 'site-a.example.com.evil.com', 'https://site-a.example.com', 'SITE-A.EXAMPLE.COM', 'site-a.example.com/path'] as $bad) {
    test('non-demo host rejected ' . $bad, static function () use ($bad): void {
        raises(static fn () => Config::hosts([$bad]), InvalidArgumentException::class);
    });
}
test('duplicate host rejected', static function (): void {
    raises(static fn () => Config::hosts(['site-a.example.com', 'site-a.example.com']), InvalidArgumentException::class);
});
test('invalid config JSON rejected', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/config.json', '{bad');
        raises(static fn () => Config::load($d . '/config.json'));
    } finally { deleteTree($d); }
});
test('identical fingerprint across sites', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $r = IntegrityScanner::scan($cfg);
        same([], $r['issues']);
        same(1, count(array_unique($r['fingerprints'])));
    } finally { deleteTree($d); }
});
test('directory fingerprint independent of file creation order', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/a'); mkdir($d . '/b');
        file_put_contents($d . '/a/z.txt', 'Z'); file_put_contents($d . '/a/a.txt', 'A');
        file_put_contents($d . '/b/a.txt', 'A'); file_put_contents($d . '/b/z.txt', 'Z');
        same(DirectoryFingerprint::hash($d . '/a'), DirectoryFingerprint::hash($d . '/b'));
    } finally { deleteTree($d); }
});
test('directory digest changes with content', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/a'); file_put_contents($d . '/a/x', 'X');
        $before = DirectoryFingerprint::hash($d . '/a');
        file_put_contents($d . '/a/x', 'Y');
        check($before !== DirectoryFingerprint::hash($d . '/a'));
    } finally { deleteTree($d); }
});
test('directory digest includes relative filename', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/a'); file_put_contents($d . '/a/x', 'X');
        $before = DirectoryFingerprint::hash($d . '/a');
        rename($d . '/a/x', $d . '/a/y');
        check($before !== DirectoryFingerprint::hash($d . '/a'));
    } finally { deleteTree($d); }
});
test('symlink in fingerprint input rejected', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/a'); file_put_contents($d . '/outside', 'secret');
        symlink($d . '/outside', $d . '/a/link');
        raises(static fn () => DirectoryFingerprint::hash($d . '/a'), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('missing Elementor core', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        unlink($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor/elementor.php');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'missing_elementor_core'));
    } finally { deleteTree($d); }
});
test('wrong Elementor core version', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        file_put_contents($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor/elementor.php', '<?php /* Version: 8.0-demo */');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'core_version_mismatch'));
    } finally { deleteTree($d); }
});
test('missing Pro installation', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        unlink($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'invalid_pro_installation_count'));
    } finally { deleteTree($d); }
});
test('duplicate Pro installation', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $base = $cfg['root'] . '/site-a.example.com/wp-content/plugins';
        mkdir($base . '/elementor-pro-backup');
        copy($base . '/elementor-pro/elementor-pro.php', $base . '/elementor-pro-backup/elementor-pro.php');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'invalid_pro_installation_count'));
    } finally { deleteTree($d); }
});
test('incorrect Pro header and runtime versions', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        file_put_contents($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php', '<?php /* Version: 1.0 */ define("ELEMENTOR_PRO_VERSION", "1.0");');
        $detail = IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'];
        check(str_contains($detail, 'pro_header_version_mismatch') && str_contains($detail, 'pro_runtime_version_mismatch'));
    } finally { deleteTree($d); }
});
test('missing update lock', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        unlink($cfg['root'] . '/site-a.example.com/wp-content/mu-plugins/site-update-lock.php');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'missing_update_lock'));
    } finally { deleteTree($d); }
});
test('divergent Pro directories', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        file_put_contents($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt', 'modified');
        $r = IntegrityScanner::scan($cfg);
        same(1, count($r['issues']));
        check(str_contains($r['issues']['site-a.example.com']['detail'], 'fleet_pro_fingerprint_divergence'));
        check(!isset($r['issues']['site-b.example.org']));
    } finally { deleteTree($d); }
});
test('Pro fixture symlink rejected', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt';
        unlink($p); symlink('/etc/passwd', $p);
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'scan_error'));
    } finally { deleteTree($d); }
});
test('CLI help', static function (): void {
    [$status, $out] = cli(['--help']);
    same(0, $status);
    check(str_contains($out, 'offline demonstration'));
});
test('CLI end-to-end new/suppressed/changed/recovered', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        $run = static fn (string $file, string $at): array => cli(['uptime', '--config', $root . '/config/demo.json', '--responses', $root . '/examples/responses/' . $file, '--state', $state, '--at', $at]);
        [$status, $out] = $run('failure.json', '2026-01-01T00:00:00Z'); same(0, $status);
        same('new', json_decode($out, true)['events'][0]['type']);
        [$status, $out] = $run('failure.json', '2026-01-01T00:30:00Z'); same(0, $status); same([], json_decode($out, true)['events']);
        [$status, $out] = $run('changed.json', '2026-01-01T01:00:00Z'); same(0, $status); same('changed', json_decode($out, true)['events'][0]['type']);
        [$status, $out] = $run('healthy.json', '2026-01-01T01:30:00Z'); same(0, $status); same('recovered', json_decode($out, true)['events'][0]['type']);
    } finally { deleteTree($d); }
});
test('CLI persistent reminder and no duplicate', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $options = ['uptime', '--responses', $root . '/examples/responses/failure.json', '--state', $d . '/state.json'];
        cli(array_merge($options, ['--at', '2026-01-01T00:00:00Z']));
        [$status, $out] = cli(array_merge($options, ['--at', '2026-01-01T06:00:00Z']));
        same(0, $status); same('reminder', json_decode($out, true)['events'][0]['type']);
        [$status, $out] = cli(array_merge($options, ['--at', '2026-01-01T06:30:00Z']));
        same(0, $status); same([], json_decode($out, true)['events']);
    } finally { deleteTree($d); }
});
test('CLI invalid JSON does not rewrite state', static function (): void {
    $d = tmp();
    try {
        $state = $d . '/state.json'; file_put_contents($state, 'bad-state');
        [$status] = cli(['uptime', '--responses', dirname(__DIR__) . '/examples/responses/healthy.json', '--state', $state]);
        same(1, $status); same('bad-state', file_get_contents($state));
    } finally { deleteTree($d); }
});
test('CLI refuses incomplete observations', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/bad.json', json_encode(['site-a.example.com' => ['status_code' => 200]]));
        [$status] = cli(['uptime', '--responses', $d . '/bad.json', '--state', $d . '/state.json']);
        same(1, $status); check(!file_exists($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('CLI refuses symlink state', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/target.json', '{}'); symlink($d . '/target.json', $d . '/state.json');
        [$status] = cli(['uptime', '--responses', dirname(__DIR__) . '/examples/responses/healthy.json', '--state', $d . '/state.json']);
        same(1, $status);
    } finally { deleteTree($d); }
});
test('CLI invalid date fails', static function (): void {
    [$status] = cli(['uptime', '--responses', dirname(__DIR__) . '/examples/responses/healthy.json', '--at', '2026-02-30T00:00:00Z']);
    same(1, $status);
});
test('CLI integrity smoke', static function (): void {
    $d = tmp();
    try {
        [$status, $out] = cli(['integrity', '--state', $d . '/state.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $status); same([], json_decode($out, true)['events']);
        same(2, count(json_decode($out, true)['fingerprints']));
    } finally { deleteTree($d); }
});


test('intermediate fixture symlink rejected', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $site = $cfg['root'] . '/site-a.example.com';
        rename($site . '/wp-content/plugins', $site . '/wp-content/plugins-original');
        symlink($site . '/wp-content/plugins-original', $site . '/wp-content/plugins');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'scan_error'));
    } finally { deleteTree($d); }
});
test('missing fixture site reported as issues', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        deleteTree($cfg['root'] . '/site-a.example.com');
        $details = IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'];
        check(str_contains($details, 'missing_elementor_core'));
        check(str_contains($details, 'missing_update_lock'));
    } finally { deleteTree($d); }
});
test('malformed Pro runtime constant reported', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        file_put_contents($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php', '<?php /* Version: 9.2.0-demo */');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'pro_runtime_version_mismatch'));
    } finally { deleteTree($d); }
});
test('empty folder affects fingerprint', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/x');
        $before = DirectoryFingerprint::hash($d . '/x');
        mkdir($d . '/x/empty');
        check($before !== DirectoryFingerprint::hash($d . '/x'));
    } finally { deleteTree($d); }
});
test('reject symlink state with direct StateStore use', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/real.json', '{}'); symlink($d . '/real.json', $d . '/state.json');
        raises(static fn () => (new StateStore($d . '/state.json'))->transaction(static fn (array $state): array => ['state' => $state, 'result' => true]), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('reject invalid state schema', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/state.json', '{"schema_version":99,"modes":{}}');
        raises(static fn () => (new StateStore($d . '/state.json'))->transaction(static fn (array $state): array => ['state' => $state, 'result' => true]), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('reject out-of-order persisted timestamps', static function (): void {
    $first = events([], issue(), 200);
    $malformed = $first['mode_state'];
    $malformed['issues']['site-a.example.com']['last_notified'] = 201;
    raises(static fn () => events($malformed, issue(), 202), InvalidArgumentException::class);
});
test('CLI old timestamp does not overwrite', static function (): void {
    $d = tmp();
    try {
        $state = $d . '/state.json';
        $responses = dirname(__DIR__) . '/examples/responses/failure.json';
        cli(['uptime', '--responses', $responses, '--state', $state, '--at', '2026-01-02T00:00:00Z']);
        $before = file_get_contents($state);
        [$code] = cli(['uptime', '--responses', $responses, '--state', $state, '--at', '2026-01-01T00:00:00Z']);
        same(1, $code); same($before, file_get_contents($state));
    } finally { deleteTree($d); }
});
test('CLI simultaneous processes serialize one new incident', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $command = [PHP_BINARY, $root . '/bin/monitor.php', 'uptime', '--responses', $root . '/examples/responses/failure.json', '--state', $d . '/state.json', '--at', '2026-01-01T00:00:00Z'];
        $pipesA = $pipesB = [];
        $procA = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipesA);
        $procB = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipesB);
        if (!is_resource($procA) || !is_resource($procB)) { throw new RuntimeException('Cannot start two processes'); }
        foreach ([$pipesA, $pipesB] as $pipes) { fclose($pipes[0]); }
        $outA = stream_get_contents($pipesA[1]); $outB = stream_get_contents($pipesB[1]);
        fclose($pipesA[1]); fclose($pipesB[1]);
        fclose($pipesA[2]); fclose($pipesB[2]);
        same(0, proc_close($procA)); same(0, proc_close($procB));
        $types = array_merge(array_column(json_decode($outA, true)['events'], 'type'), array_column(json_decode($outB, true)['events'], 'type'));
        same(['new'], $types);
        check(is_array(json_decode((string) file_get_contents($d . '/state.json'), true)));
    } finally { deleteTree($d); }
});

// Independent adversarial regression tests for the publication-blocking re-audit.
test('CMM-01 failed stdout preserves pending event and replays on next run', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $stateFile = $d . '/state.json';
        $command = [PHP_BINARY, $root . '/bin/monitor.php', 'uptime', '--state', $stateFile,
            '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z'];
        $pipes = [];
        $proc = proc_open($command, [0 => ['pipe', 'r'], 1 => ['file', '/dev/full', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc));
        fclose($pipes[0]); stream_get_contents($pipes[2]); fclose($pipes[2]);
        same(1, proc_close($proc));
        $state = json_decode((string) file_get_contents($stateFile), true);
        same(1, count($state['outbox']['uptime']['pending']));
        same(null, $state['outbox']['uptime']['claim']);
        [$exit, $json] = cli(['uptime', '--state', $stateFile, '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:30:00Z']);
        same(0, $exit);
        same('new', json_decode($json, true)['events'][0]['type']);
        $after = json_decode((string) file_get_contents($stateFile), true);
        same([], $after['outbox']['uptime']['pending']);
    } finally { deleteTree($d); }
});
test('CMM-01 outbox preserves newly appended events during existing claim', static function (): void {
    $state = ['schema_version' => 1, 'modes' => []];
    $a = \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [demoAlert('a')], 100);
    check($a['token'] !== null);
    $b = \Portfolio\IncidentState\EventOutbox::stage($a['state'], 'uptime', [demoAlert('b')], 101);
    same(null, $b['token']);
    $acked = \Portfolio\IncidentState\EventOutbox::acknowledge($b['state'], 'uptime', $a['token'], true);
    same(1, count($acked['outbox']['uptime']['pending']));
    same('b', $acked['outbox']['uptime']['pending'][0]['event']['target']);
    $next = \Portfolio\IncidentState\EventOutbox::stage($acked, 'uptime', [], 102);
    same('b', $next['events'][0]['target']);
});
test('CMM-01 abandoned delivery lease expires and replays pending event', static function (): void {
    $s = \Portfolio\IncidentState\EventOutbox::stage(['schema_version' => 1, 'modes' => []], 'uptime', [demoAlert('a')], 100);
    same(null, \Portfolio\IncidentState\EventOutbox::stage($s['state'], 'uptime', [], 101)['token']);
    same('new', \Portfolio\IncidentState\EventOutbox::stage($s['state'], 'uptime', [], 221)['events'][0]['type']);
});
test('CMM-02 removed unhealthy site generates retirement not recovery', static function (): void {
    $a = StateEngine::transition([], issue(), 100, 21600, ['site-a.example.com', 'site-b.example.org']);
    $b = StateEngine::transition($a['mode_state'], [], 200, 21600, ['site-b.example.org']);
    same('retired', $b['events'][0]['type']);
    same('site-a.example.com', $b['events'][0]['target']);
});
test('CMM-02 verified healthy in current inventory recovers as usual', static function (): void {
    $a = StateEngine::transition([], issue(), 100, 21600, ['site-a.example.com']);
    $b = StateEngine::transition($a['mode_state'], [], 200, 21600, ['site-a.example.com']);
    same('recovered', $b['events'][0]['type']);
});
foreach (['README.md', 'docs/validation.md', 'diagrams/architecture.svg', '.github/workflows/ci.yml', 'tests/run.php', 'tools/extra.php', 'ATTRIBUTION.md'] as $filename) {
    test('CMM-03 release scan sees marker in ' . $filename, static function () use ($filename): void {
        $d = tmp();
        try {
            $path = $d . '/' . $filename;
            if (!is_dir(dirname($path))) { mkdir(dirname($path), 0700, true); }
            file_put_contents($path, '-----BEGIN ' . 'PRIVATE KEY-----');
            $command = [PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', $d];
            $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($process));
            fclose($pipes[0]);
            stream_get_contents($pipes[1]);
            stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            same(1, proc_close($process));
        } finally { deleteTree($d); }
    });
}
test('CMM-03 release scan rejects symlinks', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/ordinary.txt', 'Safe');
        symlink($d . '/ordinary.txt', $d . '/unsafe-link');
        $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', $d], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($p));
        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        same(1, proc_close($p));
    } finally { deleteTree($d); }
});
test('CMM-04 renamed decoy pro directory is invalid', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $dir = $cfg['root'] . '/site-a.example.com/wp-content/plugins';
        rename($dir . '/elementor-pro', $dir . '/elementor-pro-fake');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'invalid_pro_installation_count'));
    } finally { deleteTree($d); }
});
test('CMM-05 commented out runtime version cannot pass', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php';
        file_put_contents($p, "<?php /* Version: 9.2.0-demo */ // define('ELEMENTOR_PRO_VERSION', '9.2.0-demo');\n");
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'pro_runtime_version_mismatch'));
    } finally { deleteTree($d); }
});
test('CMM-05 duplicate runtime version declarations fail', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php';
        file_put_contents($p, "<?php /* Version: 9.2.0-demo */ define('ELEMENTOR_PRO_VERSION','9.2.0-demo'); define('ELEMENTOR_PRO_VERSION','9.2.0-demo');");
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'pro_runtime_version_mismatch'));
    } finally { deleteTree($d); }
});
test('CMM-06 uptime ignores broken unrelated integrity settings', static function (): void {
    $d = tmp();
    try {
        $cfg = ['hosts' => ['site-a.example.com','site-b.example.org'], 'reminder_seconds' => ['uptime' => 21600], 'integrity' => ['root' => 'not-found']];
        file_put_contents($d . '/config.json', json_encode($cfg));
        [$exit, $out] = cli(['uptime', '--config', $d . '/config.json', '--state', $d . '/state.json',
            '--responses', dirname(__DIR__) . '/examples/responses/healthy.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit); same([], json_decode($out, true)['events']);
    } finally { deleteTree($d); }
});
test('CMM-07 HTTP 201 Location is not an invalid redirect', static function (): void {
    $x = Classifier::classify('site-a.example.com', ['status_code' => 201, 'redirect_location' => 'https://site-a.example.com/new']);
    same('unverified_http_status', $x['code']);
});
test('CMM-08 safe relative redirect is unverified not a confirmed outage', static function (): void {
    $x = Classifier::classify('site-a.example.com', ['status_code' => 302, 'redirect_location' => '/login']);
    same(null, $x['healthy']); same('unverified_redirect', $x['code']);
});
test('CMM-08 unverified current observation cannot close an incident', static function (): void {
    $first = StateEngine::transition([], issue(), 100, 21600, ['site-a.example.com']);
    $second = StateEngine::transition($first['mode_state'], [], 200, 21600, ['site-a.example.com'], ['site-a.example.com']);
    same([], $second['events']);
    same([], $second['mode_state']['issues']);
    same('http_error', $second['mode_state']['unknown_history']['site-a.example.com']['last_confirmed_issue']['code']);
});
test('CMM-09 a symlink at one site produces isolated scan_error', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt';
        unlink($p); symlink('/etc/passwd', $p);
        $r = IntegrityScanner::scan($cfg);
        check(str_contains($r['issues']['site-a.example.com']['detail'], 'scan_error'));
        check(!isset($r['issues']['site-b.example.org']));
        same(1, count($r['fingerprints']));
    } finally { deleteTree($d); }
});
test('CMM-10 tutorial discussing database errors remains healthy', static function (): void {
    $x = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => 'This tutorial explains how to fix Error establishing a database connection in WordPress']);
    same(true, $x['healthy']);
});
test('CMM-11 configured minimum rejects empty or whitespace body', static function (): void {
    foreach (['', " \n  "] as $body) {
        $x = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $body], ['min_body_bytes' => 1]);
        same('content_assertion_failed', $x['code']);
    }
    same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => 204], ['min_body_bytes' => 1])['code']);
});
test('CMM-11 sentinel rejects truncated pages', static function (): void {
    same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => 'OK'], ['contains' => 'EXPECTED PAGE FOOTER'])['code']);
});
test('CMM-12 zero-byte update locks fail content integrity check', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/mu-plugins/site-update-lock.php';
        file_put_contents($p, '');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'empty_update_lock'));
    } finally { deleteTree($d); }
});
test('CMM-12 modified update lock differs from approved SHA256', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/mu-plugins/site-update-lock.php';
        file_put_contents($p, '<?php // different');
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'], 'update_lock_fingerprint_mismatch'));
    } finally { deleteTree($d); }
});
test('CMM-13 negative timestamp rejected', static function (): void {
    $r = events([], issue(), 100);
    $r['mode_state']['issues']['site-a.example.com']['last_notified'] = -1;
    raises(static fn () => events($r['mode_state'], issue(), 200), InvalidArgumentException::class);
});
test('CMM-13 prior incident later than last completed run is invalid', static function (): void {
    $r = events([], issue(), 100);
    $r['mode_state']['last_run'] = 99;
    raises(static fn () => events($r['mode_state'], issue(), 200), InvalidArgumentException::class);
});
test('L01 matching modified plugin copies fail approved baseline fingerprint', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        foreach ($cfg['sites'] as $site) {
            file_put_contents($cfg['root'] . '/' . $site . '/wp-content/plugins/elementor-pro/synthetic-asset.txt', 'same malicious change');
        }
        $r = IntegrityScanner::scan($cfg);
        same(1, count(array_unique(array_values($r['fingerprints']))));
        same(2, count($r['issues']));
        check(str_contains($r['issues']['site-a.example.com']['detail'], 'pro_baseline_fingerprint_mismatch'));
    } finally { deleteTree($d); }
});
test('L05 a fixture root outside approved directories is refused', static function (): void {
    $d = tmp();
    try {
        mkdir($d . '/cfg'); mkdir($d . '/outside');
        $data = ['hosts' => ['site-a.example.com'], 'reminder_seconds' => ['uptime' => 21600, 'integrity' => 86400],
            'integrity' => ['root' => '../outside', 'sites' => ['site-a.example.com'], 'core_version' => '1', 'pro_header_version' => '1', 'pro_runtime_version' => '1', 'update_lock' => 'lock.php']];
        file_put_contents($d . '/cfg/config.json', json_encode($data));
        raises(static fn () => Config::load($d . '/cfg/config.json'), InvalidArgumentException::class);
    } finally { deleteTree($d); }
});
test('L06 monitoring gap is observable after a missed interval', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $opts = ['uptime', '--state', $d . '/state.json', '--responses', $root . '/examples/responses/healthy.json'];
        cli(array_merge($opts, ['--at', '2026-01-01T00:00:00Z']));
        [$code, $out] = cli(array_merge($opts, ['--at', '2026-01-01T04:00:00Z']));
        same(0, $code);
        same(14400, json_decode($out, true)['gap_since_previous_run_seconds']);
        same(true, json_decode($out, true)['monitoring_gap_exceeded']);
    } finally { deleteTree($d); }
});

test('CLI removing failing target emits retired and never recovered', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $original = json_decode((string) file_get_contents($root . '/config/demo.json'), true);
        $first = $d . '/a.json'; $second = $d . '/b.json';
        file_put_contents($first, json_encode($original));
        $original['hosts'] = ['site-b.example.org'];
        unset($original['content_policies']['site-a.example.com']);
        file_put_contents($second, json_encode($original));
        $initial = ['uptime','--config',$first,'--responses',$root.'/examples/responses/failure.json','--state',$d.'/state.json','--at','2026-01-01T00:00:00Z'];
        [$code] = cli($initial);
        same(0,$code);
        $response = ['site-b.example.org'=>['status_code'=>200,'body'=>'Healthy']];
        file_put_contents($d.'/only.json',json_encode($response));
        [$code,$out] = cli(['uptime','--config',$second,'--responses',$d.'/only.json','--state',$d.'/state.json','--at','2026-01-01T00:30:00Z']);
        same(0,$code);
        $types = array_column(json_decode($out,true)['events'],'type');
        same(['retired'],$types);
    } finally { deleteTree($d); }
});
test('CLI unverified redirect preserves an open failure', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $opts = ['uptime','--state',$d.'/state.json'];
        [$code] = cli(array_merge($opts,['--responses',$root.'/examples/responses/failure.json','--at','2026-01-01T00:00:00Z']));
        same(0,$code);
        $rows = json_decode((string)file_get_contents($root.'/examples/responses/healthy.json'),true);
        $rows['site-a.example.com'] = ['status_code'=>302,'redirect_location'=>'/login'];
        file_put_contents($d.'/unknown.json',json_encode($rows));
        [$code,$out] = cli(array_merge($opts,['--responses',$d.'/unknown.json','--at','2026-01-01T00:30:00Z']));
        same(0,$code);
        $result = json_decode($out,true);
        same([], $result['events']);
        same(['site-a.example.com'], $result['unverified_targets']);
        $state=json_decode((string)file_get_contents($d.'/state.json'),true);
        same('http_error', $state['modes']['uptime']['unknown_history']['site-a.example.com']['last_confirmed_issue']['code']);
        same([], $state['modes']['uptime']['issues']);
    } finally { deleteTree($d); }
});
test('publication scan excludes only known generated dependency folders', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d.'/README.md','Safe content');
        foreach (['vendor', 'var/phpstan-cache','.git'] as $path) {
            if (!is_dir($d.'/'.$path)) { mkdir($d.'/'.$path,0700,true); }
            file_put_contents($d.'/'.$path.'/unpublished.bin', "\0not for publication");
        }
        file_put_contents($d.'/composer.lock', "\0generated lock file");
        $p=proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php',$d],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        check(is_resource($p));
        fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(0,proc_close($p));
    } finally { deleteTree($d); }
});
test('publication scan rejects binary release payload', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d.'/README.md', "\0wrong binary");
        $p=proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php',$d],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        check(is_resource($p));fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);same(1,proc_close($p));
    } finally { deleteTree($d); }
});
test('outbox rejects corrupt pending journal', static function (): void {
    raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage(['outbox'=>['uptime'=>['pending'=>[['id'=>'x']], 'claim'=>null]]], 'uptime', [], 100), RuntimeException::class);
});
test('commented and quoted PHP define statements cannot impersonate runtime metadata', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p=$cfg['root'].'/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php';
        file_put_contents($p,"<?php /* Version: 9.2.0-demo */ \$x = \"define('ELEMENTOR_PRO_VERSION', '9.2.0-demo')\";");
        check(str_contains(IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'],'pro_runtime_version_mismatch'));
    } finally { deleteTree($d); }
});

test('201 Created with Location must honor any explicitly configured body policy', static function (): void {
    same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => 201, 'redirect_location' => '/created'], ['min_body_bytes' => 1])['code']);
});

// Third-generation independent audit regressions (synthetic, no network requests).
test('NEW-02 unverified 3xx codes can never report healthy', static function (): void {
    foreach ([300, 304, 305, 306, 310, 399] as $status) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => $status]);
        same(null, $r['healthy']);
        same('unverified_http_status', $r['code']);
    }
});
test('NEW-02 a 304 response never recovers a previous 500 incident', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        [$code] = cli(['uptime', '--state', $state, '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $code);
        $rows = json_decode((string) file_get_contents($root . '/examples/responses/healthy.json'), true);
        $rows['site-a.example.com'] = ['status_code' => 304];
        file_put_contents($d . '/304.json', json_encode($rows));
        [$exit, $output] = cli(['uptime', '--state', $state, '--responses', $d . '/304.json', '--at', '2026-01-01T00:30:00Z']);
        same(0, $exit);
        same([], json_decode($output, true)['events']);
        same(['site-a.example.com'], json_decode($output, true)['unverified_targets']);
        same('http_error', json_decode((string) file_get_contents($state), true)['modes']['uptime']['unknown_history']['site-a.example.com']['last_confirmed_issue']['code']);
    } finally { deleteTree($d); }
});
test('NEW-03 realistic WP error page is detected with an HTML title and navigation', static function (): void {
    $html = '<html><head><title>WordPress › Error</title></head><body><nav>Home</nav><main><p>There has been a critical error on this website.</p></main></body></html>';
    same('application_wp_critical_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('NEW-03 realistic PHP fatal error after HTML title is detected', static function (): void {
    $html = '<html><head><title>Server error</title></head><body><main><pre>PHP Fatal error: Uncaught RuntimeException in file.php</pre></main></body></html>';
    same('application_php_fatal_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('NEW-05 head/style/script-only responses fail min-visible-content requirements', static function (): void {
    foreach (['<html><head><title>Valid</title></head><body></body></html>',
        '<html><body><script>console.log("working")</script></body></html>',
        '<html><body><style>body {display:block}</style></body></html>',
        '<html><head><title>Title</title></head></html>'] as $html) {
        $result = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html], ['min_body_bytes' => 1]);
        same(str_contains($html, '<style>') ? 'unverified_html' : 'content_assertion_failed', $result['code']);
    }
});
test('NEW-06 troubleshooting articles are not outage pages', static function (): void {
    foreach (['<h1>Service Unavailable: how to troubleshoot HTTP 503</h1><p>Here is a useful article.</p>',
        '<h1>Fatal error: how to debug PHP</h1><p>Tutorial.</p>',
        'Fatal error: how to debug safely',
        '<h1>How to fix There has been a critical error on this website</h1>'] as $html) {
        same(true, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['healthy']);
    }
});
test('NEW-07 quoted Version metadata without a leading plugin header cannot pass', static function (): void {
    [$dir, $cfg] = fixtures();
    try {
        $file = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor/elementor.php';
        file_put_contents($file, "<?php\n\$fake = <<<'FAKE'\nVersion: 9.1.0-demo\nFAKE;\n");
        $scan = IntegrityScanner::scan($cfg);
        check(str_contains($scan['issues']['site-a.example.com']['detail'], 'core_version_mismatch'));
    } finally { deleteTree($dir); }
});
test('NEW-07 later comments cannot impersonate the leading plugin header', static function (): void {
    [$dir, $cfg] = fixtures();
    try {
        $file = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor/elementor.php';
        file_put_contents($file, "<?php\n\$foo = true;\n/* Version: 9.1.0-demo */\n");
        $scan = IntegrityScanner::scan($cfg);
        check(str_contains($scan['issues']['site-a.example.com']['detail'], 'core_version_mismatch'));
    } finally { deleteTree($dir); }
});
test('NEW-08 event id is delivered and retained across replay', static function (): void {
    $state = ['schema_version' => 1, 'modes' => []];
    $first = \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [demoAlert('site-a.example.com')], 100);
    $id = $first['events'][0]['id'];
    check((bool) preg_match('/\A[a-f0-9]{32}\z/', $id));
    $second = \Portfolio\IncidentState\EventOutbox::acknowledge($first['state'], 'uptime', $first['token'], false);
    $third = \Portfolio\IncidentState\EventOutbox::stage($second, 'uptime', [], 101);
    same($id, $third['events'][0]['id']);
    same('new', $third['events'][0]['type']);
});
test('NEW-04 outbox bounds each delivery claim and retains the rest', static function (): void {
    $events = [];
    for ($i = 0; $i < 400; ++$i) {
        $events[] = demoAlert('site-' . $i . '.example.com');
    }
    $stage = \Portfolio\IncidentState\EventOutbox::stage(['schema_version' => 1, 'modes' => []], 'uptime', $events, 100);
    same(128, count($stage['events']));
    $acked = \Portfolio\IncidentState\EventOutbox::acknowledge($stage['state'], 'uptime', $stage['token'], true);
    same(272, count($acked['outbox']['uptime']['pending']));
});
test('NEW-01 oversized valid state is rejected before touching previous readable state', static function (): void {
    $d = tmp();
    try {
        $path = $d . '/state.json';
        $store = new StateStore($path);
        $store->transaction(static fn (array $state): array => ['state' => $state, 'result' => null]);
        $before = file_get_contents($path);
        raises(static fn () => $store->transaction(static function (array $state): array {
            $entries = [];
            // Every event individually satisfies EventSchema; total payload
            // exceeds StateStore's 5-MB readable-file limit.
            for ($i = 0; $i < 2600; ++$i) {
                $entries[] = [
                    'id' => sprintf('%032x', $i),
                    'event' => demoAlert('site-' . $i . '.example.com', 'new', str_repeat('X', 1950)),
                ];
            }
            $state['outbox']['uptime'] = ['pending' => $entries, 'claim' => null];
            return ['state' => $state, 'result' => null];
        }), RuntimeException::class);
        same($before, file_get_contents($path));
        same(2, $store->transaction(static fn (array $state): array => ['state' => $state, 'result' => $state['schema_version']]));
    } finally { deleteTree($d); }
});
test('NEW-01 event admission enforces a serialized state budget', static function (): void {
    $entries = [];
    for ($i = 0; $i < 1700; ++$i) {
        $entries[] = ['id' => sprintf('%032x', $i), 'event' => demoAlert('a.example.com', 'new', str_repeat('X', 1900))];
    }
    $state = ['schema_version' => 1, 'modes' => [], 'outbox' => ['uptime' => ['pending' => $entries, 'claim' => null]]];
    raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [demoAlert('b.example.com')], 100), \Portfolio\IncidentState\OutboxCapacityException::class);
    $flush = \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [], 100);
    same(128, count($flush['events']));
});
test('NEW-04 saturated outbox drains during new incident evaluation without committing incident changes', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $store = new StateStore($d . '/state.json');
        $pending = [];
        for ($i = 0; $i < 10000; ++$i) {
            $pending[] = ['id' => sprintf('%032x', $i), 'event' => demoAlert('synthetic-' . $i . '.example.com')];
        }
        $store->transaction(static function (array $state) use ($pending): array {
            $state['outbox']['uptime'] = ['pending' => $pending, 'claim' => null];
            return ['state' => $state, 'result' => null];
        });
        [$status, $json] = cli(['uptime', '--state', $d . '/state.json', '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']);
        same(2, $status);
        $data = json_decode($json, true);
        same(true, $data['monitoring_deferred']);
        same(128, count($data['events']));
        $state = json_decode((string) file_get_contents($d . '/state.json'), true);
        same([], $state['modes']); // No new incident transition was silently committed.
        same(9872, count($state['outbox']['uptime']['pending']));
    } finally { deleteTree($d); }
});
test('NEW-11 offline flush can replay pending events with an unavailable response file', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        $cmd = [PHP_BINARY, $root . '/bin/monitor.php', 'uptime', '--state', $state,
            '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z'];
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['file', '/dev/full', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[2]); fclose($pipes[2]);
        same(1, proc_close($proc));
        $pending = json_decode((string) file_get_contents($state), true)['outbox']['uptime']['pending'];
        same(1, count($pending));
        [$status, $out] = cli(['flush', '--mode', 'uptime', '--state', $state]);
        same(0, $status);
        $data = json_decode($out, true);
        same('outbox_replay', $data['type']);
        same($pending[0]['id'], $data['events'][0]['id']);
        same([], json_decode((string) file_get_contents($state), true)['outbox']['uptime']['pending']);
    } finally { deleteTree($d); }
});
test('NEW-09 release scanner rejects encrypted private keys and unquoted synthetic secrets', static function (): void {
    $root = dirname(__DIR__);
    foreach (['-----BEGIN ' . 'ENCRYPTED PRIVATE KEY-----', sprintf('%s=%s', 'API_KEY', 'EXAMPLE01234567890123456789012345')] as $bad) {
        $d = tmp();
        try {
            file_put_contents($d . '/README.md', 'Safe');
            file_put_contents($d . '/notice.txt', $bad);
            $proc = proc_open([PHP_BINARY, $root . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($proc));
            fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            same(1, proc_close($proc));
        } finally { deleteTree($d); }
    }
});
test('NEW-10 strict release mode scans any packaged composer lock file', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/README.md', 'Safe');
        file_put_contents($d . '/composer.lock', sprintf('%s=%s', 'API_KEY', 'EXAMPLE01234567890123456789012345'));
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc));
        fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(1, proc_close($proc));
    } finally { deleteTree($d); }
});
test('NEW-12 scan failure exposes a bounded category, not host filesystem paths', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $p = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt';
        unlink($p);
        symlink('/etc/passwd', $p);
        $result = IntegrityScanner::scan($cfg);
        $detail = $result['issues']['site-a.example.com']['detail'];
        check(str_contains($detail, 'scan_error_unsafe_path'));
        check(!str_contains($detail, '/etc/passwd'));
    } finally { deleteTree($d); }
});

// Fourth-generation audit fixes: independent reproduction cases from v3 review.
test('V3-01 late WordPress critical error after eight navigation blocks', static function (): void {
    $html = '<body>' . str_repeat('<nav>Menu navigation</nav>', 8) . '<h1>There has been a critical error on this website.</h1></body>';
    same('application_wp_critical_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('V3-01 no hidden eight-kilobyte cutoff for structured application errors', static function (): void {
    $html = '<body><nav>' . str_repeat('Navigation ', 1000) . '</nav><main><pre>PHP Fatal error: Uncaught RuntimeException in file.php</pre></main></body>';
    same('application_php_fatal_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('V3-02 database outage heading in a support article is not an outage', static function (): void {
    $html = '<article><h1>Error establishing a database connection</h1><p>In this guide, we explain how to troubleshoot this WordPress issue.</p></article>';
    same(true, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['healthy']);
});
test('V3-03 content assertions only examine visitor-visible text', static function (): void {
    $html = '<body><p>Site maintenance is active</p><script>const value="WELCOME BACK";</script></body>';
    same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html], ['min_body_bytes' => 1, 'contains' => 'WELCOME BACK'])['code']);
    same(true, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => '<p>WELCOME BACK</p>'], ['contains' => 'WELCOME BACK'])['healthy']);
});
test('V3-04 all 2xx statuses honor explicit page content policy', static function (): void {
    foreach ([200, 201, 202, 204, 205, 207, 299] as $status) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => $status, 'body' => 'OK'],
            ['min_body_bytes' => 100, 'contains' => 'APP_EXPECTED'])['code']);
    }
    same(null, Classifier::classify('site-a.example.com', ['status_code' => 204])['healthy']);
    same('unverified_partial_response', Classifier::classify('site-a.example.com', ['status_code' => 206, 'body' => 'OK'])['code']);
});
test('V3-05 inactive define cannot pass fixture metadata verification', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $file = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/elementor-pro.php';
        file_put_contents($file, "<?php /* Version: 9.2.0-demo */ if (false) { define('ELEMENTOR_PRO_VERSION', '9.2.0-demo'); }");
        $detail = IntegrityScanner::scan($cfg)['issues']['site-a.example.com']['detail'];
        check(str_contains($detail, 'pro_runtime_version_mismatch'));
        check(str_contains($detail, 'pro_baseline_fingerprint_mismatch'));
        unset($cfg['baseline_sha256']);
        raises(static fn () => IntegrityScanner::scan($cfg), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('V3-06 reject typo keys at every configuration boundary', static function (): void {
    $base = json_decode((string) file_get_contents(dirname(__DIR__) . '/config/demo.json'), true);
    $changes = [
        ['top', static function (array &$c): void { $c['hostz'] = []; }],
        ['baseline', static function (array &$c): void { $c['integrity']['baseline_sh256'] = $c['integrity']['baseline_sha256']; unset($c['integrity']['baseline_sha256']); }],
        ['interval', static function (array &$c): void { $c['expected_interval_seconds']['uptiem'] = 1800; unset($c['expected_interval_seconds']['uptime']); }],
        ['reminder', static function (array &$c): void { $c['reminder_seconds']['uptiem'] = 1800; }],
        ['policy', static function (array &$c): void { $c['content_policies']['site-a.example.com']['containz'] = 'hello'; }],
    ];
    foreach ($changes as [$label, $mutate]) {
        $d = tmp();
        try {
            $cfg = $base; $mutate($cfg);
            file_put_contents($d . '/config.json', json_encode($cfg));
            raises(static fn () => Config::load($d . '/config.json', $label === 'baseline' ? 'integrity' : 'uptime'), InvalidArgumentException::class);
        } finally { deleteTree($d); }
    }
});
test('V3-07 malformed outbox values are rejected without changing state', static function (): void {
    foreach ([123, null, ['pending' => [], 'claim' => null, 'surplus' => 1], ['pending' => false, 'claim' => null]] as $bad) {
        $d = tmp();
        try {
            $file = $d . '/state.json';
            $json = json_encode(['schema_version' => 1, 'modes' => (object) [], 'outbox' => ['uptime' => $bad]]);
            file_put_contents($file, $json);
            [$exit] = cli(['flush', '--mode', 'uptime', '--state', $file]);
            same(1, $exit);
            same($json, file_get_contents($file));
        } finally { deleteTree($d); }
    }
});
test('V3-08 oversized response input is rejected under constrained memory', static function (): void {
    $d = tmp();
    try {
        $big = $d . '/big.json';
        file_put_contents($big, str_repeat('x', 20_000_000));
        $command = [PHP_BINARY, '-d', 'memory_limit=16M', dirname(__DIR__) . '/bin/monitor.php', 'uptime',
            '--config', dirname(__DIR__) . '/config/demo.json', '--responses', $big, '--state', $d . '/state.json'];
        $proc = proc_open($command, [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]); $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
        same(1, proc_close($proc));
        check(str_contains($err, 'exceeds maximum permitted size'));
        check(!str_contains($err, 'Allowed memory size'));
    } finally { deleteTree($d); }
});
test('V3-09 scanner recognizes AWS secret access key assignments', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/notice.txt', 'AWS_' . 'SECRET_ACCESS_KEY=' . str_repeat('A1', 25));
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($proc));
    } finally { deleteTree($d); }
});
test('V3-10 non-NUL binary must fail strict release scan', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/hidden.txt', str_repeat("\xff\xfe\xfd\xf1\xa0", 20));
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($proc));
    } finally { deleteTree($d); }
});
test('V3-11 no historical private-source fingerprint is included in provenance', static function (): void {
    $doc = (string) file_get_contents(dirname(__DIR__) . '/docs/provenance-and-limitations.md');
    check(!str_contains($doc, '6cbc52dea864807083e5d30ce8f7e5167568de0c97fb54a03eb1198d7778afd2'));
    check(str_contains($doc, 'byte-identical'));
});
test('V3-12 manifest verification is enforced by CI', static function (): void {
    $ci = (string) file_get_contents(dirname(__DIR__) . '/.github/workflows/ci.yml');
    check(str_contains($ci, 'sha256sum -c MANIFEST.sha256'));
    check(str_contains($ci, 'tools/verify_manifest.php'));
});

test('V3-12 manifest rejects drift, extra files, and missing files', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/a.txt', 'OK');
        file_put_contents($d . '/MANIFEST.sha256', hash('sha256', 'OK') . '  a.txt' . "\n");
        $verify = static function (string $dir): int {
            $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/verify_manifest.php', $dir],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); return proc_close($proc);
        };
        same(0, $verify($d));
        file_put_contents($d . '/a.txt', 'CHANGED');
        same(1, $verify($d));
        file_put_contents($d . '/a.txt', 'OK');
        file_put_contents($d . '/unexpected.txt', 'UNLISTED');
        same(1, $verify($d));
        unlink($d . '/unexpected.txt');
        unlink($d . '/a.txt');
        same(1, $verify($d));
    } finally { deleteTree($d); }
});
test('V3-08 oversized configuration and persisted state reject without OOM', static function (): void {
    $d = tmp();
    try {
        $config = $d . '/oversize.json';
        file_put_contents($config, str_repeat('x', 2_000_000));
        raises(static fn () => Config::load($config, 'uptime'), InvalidArgumentException::class);
        $state = $d . '/state.json';
        $original = str_repeat('x', 5_500_000);
        file_put_contents($state, $original);
        [$exit, $out, $err] = cli(['flush', '--mode', 'uptime', '--state', $state]);
        same(1, $exit);
        check(str_contains($err, 'cannot be read safely'));
        same(strlen($original), filesize($state));
    } finally { deleteTree($d); }
});
test('V3-05 absent approved lock fingerprint is rejected', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        unset($cfg['update_lock_sha256']);
        raises(static fn () => IntegrityScanner::scan($cfg), RuntimeException::class);
    } finally { deleteTree($d); }
});

// Fifth-generation independent regressions — all 13 V4 audit findings.
test('V4-01 critical WordPress page with unrelated help footer never recovers', static function (): void {
    $host = 'site-a.example.com';
    $old = StateEngine::transition([], [$host => ['code' => 'http_error', 'detail' => 'HTTP 500']], 1000, 21600, [$host]);
    $html = '<html><body><h1>There has been a critical error on this website.</h1>' .
        '<footer><a href="/docs">How to fix WordPress problems</a></footer></body></html>';
    $result = Classifier::classify($host, ['status_code' => 200, 'body' => $html]);
    same('application_wp_critical_error', $result['code']);
    $next = StateEngine::transition($old['mode_state'], [$host => ['code' => $result['code'], 'detail' => $result['detail']]], 2000, 21600, [$host]);
    same('changed', $next['events'][0]['type']);
    check(!in_array('recovered', array_column($next['events'], 'type'), true));
});
test('V4-01 unrelated support link does not hide database outage', static function (): void {
    $html = '<main><h1>Error establishing a database connection</h1></main>' .
        '<footer><a href="/help">Read more about troubleshooting</a></footer>';
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('V4-02 Core directory digest detects executable code mutation without changed version', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        $core = $cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor/elementor.php';
        file_put_contents($core, "\n/* synthetic malicious mutation */ echo 'NOT THE SAME';\n", FILE_APPEND);
        $scan = IntegrityScanner::scan($cfg);
        check(str_contains($scan['issues']['site-a.example.com']['detail'], 'core_baseline_fingerprint_mismatch'));
        check(!isset($scan['issues']['site-b.example.org']));
        same(2, count($scan['core_fingerprints']));
    } finally { deleteTree($d); }
});
test('V4-02 Core SHA-256 baseline is mandatory', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        unset($cfg['core_baseline_sha256']);
        raises(static fn () => IntegrityScanner::scan($cfg), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('V4-03 hidden, aria-hidden and inline invisible text fail content marker assertion', static function (): void {
    $bodies = [
        '<div hidden>HEALTH_OK</div><p>maintenance</p>',
        '<span style="display:none">HEALTH_OK</span><p>maintenance</p>',
        '<section style="visibility: hidden"><p>HEALTH_OK</p></section>',
        '<div aria-hidden="true"><b>HEALTH_OK</b></div>',
        '<p><span hidden>HEALTH_OK</span>maintenance</p>',
        '<script>document.write("HEALTH_OK")</script><p>maintenance</p>',
    ];
    foreach ($bodies as $body) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $body], ['min_body_bytes' => 1, 'contains' => 'HEALTH_OK'])['code']);
    }
    same(true, Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => '<div hidden>no</div><p>HEALTH_OK</p>'], ['contains' => 'HEALTH_OK'])['healthy']);
});
test('V4-04 successful response other than 200 still detects critical application error', static function (): void {
    foreach ([201, 202, 207, 299] as $status) {
        same('application_wp_critical_error', Classifier::classify('site-a.example.com',
            ['status_code' => $status, 'body' => '<main><p>There has been a critical error on this website.</p></main>'])['code']);
    }
});
test('Body-bearing 204/205 responses still recognize an injected error page', static function (): void {
    foreach ([204, 205] as $status) {
        $result = Classifier::classify('site-a.example.com', ['status_code' => $status,
            'body' => '<p>There has been a critical error on this website.</p>']);
        same('application_wp_critical_error', $result['code']);
    }
});
test('V4-05 HTTP 206 remains unknown and cannot close a prior outage', static function (): void {
    $host = 'site-a.example.com';
    $r = Classifier::classify($host, ['status_code' => 206, 'body' => 'HEALTH_OK'], ['contains' => 'HEALTH_OK']);
    same(null, $r['healthy']); same('unverified_partial_response', $r['code']);
    $old = StateEngine::transition([], [$host => ['code' => 'http_error', 'detail' => 'HTTP 500']], 1000, 21600, [$host]);
    $later = StateEngine::transition($old['mode_state'], [], 2000, 21600, [$host], [$host]);
    same([], $later['events']);
    same('http_error', $later['mode_state']['unknown_history'][$host]['last_confirmed_issue']['code']);
});
test('V4-06 divergence event belongs only to out-of-baseline sites', static function (): void {
    [$d, $cfg] = fixtures();
    try {
        file_put_contents($cfg['root'] . '/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt', 'changed');
        $result = IntegrityScanner::scan($cfg);
        same(['site-a.example.com'], array_keys($result['issues']));
        check(str_contains($result['issues']['site-a.example.com']['detail'], 'pro_baseline_fingerprint_mismatch'));
    } finally { deleteTree($d); }
});
test('V4-07 null prior incident history cannot be treated as empty', static function (): void {
    raises(static fn () => StateEngine::transition(['issues' => null, 'last_run' => 10], issue(), 100, 21600), InvalidArgumentException::class);
});
test('V4-08 malformed outbox entry in unrelated mode blocks transaction', static function (): void {
    $bad = ['outbox' => [
        'uptime' => ['pending' => [], 'claim' => null],
        'integrity' => ['pending' => [['oops' => 'missing event fields']], 'claim' => null],
    ]];
    raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage($bad, 'uptime', [], time()), RuntimeException::class);
    $d = tmp();
    try {
        $file = $d . '/state.json';
        $state = ['schema_version' => 1, 'modes' => new stdClass()] + $bad;
        file_put_contents($file, json_encode($state));
        [$status] = cli(['flush', '--mode', 'uptime', '--state', $file]);
        same(1, $status);
        same(json_encode($state), file_get_contents($file));
    } finally { deleteTree($d); }
});
test('V4-09 impossible far-future claim is safely reclaimed', static function (): void {
    $id = str_repeat('a', 32);
    $state = ['outbox' => ['uptime' => ['pending' => [
        ['id' => $id, 'event' => demoAlert('site-a.example.com')]],
        'claim' => ['token' => str_repeat('b', 32), 'until' => PHP_INT_MAX, 'ids' => [$id]],
    ]]];
    $result = \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [], 1000);
    same($id, $result['events'][0]['id']);
    check($result['token'] !== null && $result['token'] !== str_repeat('b', 32));
    $state['outbox']['uptime']['claim'][str_rot13('gbxra')] = 'invalid-token';
    raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage($state, 'uptime', [], 1000), RuntimeException::class);
});
test('V4-10 empty in-memory incident history round-trips through engine', static function (): void {
    $first = StateEngine::transition([], [], 1000, 3600, ['site-a.example.com']);
    check(is_array($first['mode_state']['issues']));
    $second = StateEngine::transition($first['mode_state'], [], 2000, 3600, ['site-a.example.com']);
    same([], $second['events']);
    same([], $second['mode_state']['issues']);
});
test('V4-11 prolonged verification gap escalates and reminds without false recovery', static function (): void {
    $host = 'site-a.example.com';
    $first = StateEngine::transition([], [], 1000, 21600, [$host], [$host], 3600, 7200);
    same([], $first['events']);
    $before = StateEngine::transition($first['mode_state'], [], 4599, 21600, [$host], [$host], 3600, 7200);
    same([], $before['events']);
    $escalated = StateEngine::transition($before['mode_state'], [], 4600, 21600, [$host], [$host], 3600, 7200);
    same('verification_gap', $escalated['events'][0]['type']);
    $quiet = StateEngine::transition($escalated['mode_state'], [], 11799, 21600, [$host], [$host], 3600, 7200);
    same([], $quiet['events']);
    $reminded = StateEngine::transition($quiet['mode_state'], [], 11800, 21600, [$host], [$host], 3600, 7200);
    same('verification_gap_reminder', $reminded['events'][0]['type']);
    $verified = StateEngine::transition($reminded['mode_state'], [], 11900, 21600, [$host], [], 3600, 7200);
    same('verification_restored', $verified['events'][0]['type']);
    same([], $verified['mode_state']['unknown_history']);
});
test('V4-11 CLI emits a verification_gap after configured threshold', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        $response = $d . '/unknown.json';
        file_put_contents($response, json_encode([
            'site-a.example.com' => ['status_code' => 301, 'redirect_location' => 'https://site-a.example.com/next'],
            'site-b.example.org' => ['status_code' => 200, 'body' => 'Healthy'],
        ]));
        $run = static fn (string $at): array => cli(['uptime', '--config', $root . '/config/demo.json',
            '--responses', $response, '--state', $state, '--at', $at]);
        [$exit] = $run('2026-01-01T00:00:00Z'); same(0, $exit);
        [$exit, $output] = $run('2026-01-01T01:00:00Z'); same(0, $exit);
        same('verification_gap', json_decode($output, true)['events'][0]['type']);
    } finally { deleteTree($d); }
});
test('V4-12 scanner recognizes fake GitHub, Slack and npm credential patterns', static function (): void {
    foreach ([
        'GITHUB_TOKEN=' . 'ghs_' . str_repeat('A', 40),
        'SLACK_BOT_TOKEN=' . 'xoxb-' . str_repeat('B', 40),
        '_authToken=' . str_repeat('C', 48),
    ] as $bad) {
        $d = tmp();
        try {
            file_put_contents($d . '/leak.md', $bad . "\n");
            $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($proc));
        } finally { deleteTree($d); }
    }
});
test('V4-13 malformed prior inventory and unknown lists are rejected', static function (): void {
    raises(static fn () => StateEngine::transition(['inventory' => 'blah'], [], 1000, 3600, []), InvalidArgumentException::class);
    raises(static fn () => StateEngine::transition(['unknown' => null], [], 1000, 3600, []), InvalidArgumentException::class);
    raises(static fn () => StateEngine::transition(['inventory' => ['one.example.com','one.example.com']], [], 1000, 3600, []), InvalidArgumentException::class);
    // Old valid snapshots without inventory remain supported.
    same([], StateEngine::transition(['issues' => []], [], 1000, 3600, [])['events']);
});

test('V4-02 supplied integrity shell demo remains executable with mandatory Core baseline', static function (): void {
    if (PHP_OS_FAMILY === 'Windows') {
        return;
    }
    $script = dirname(__DIR__) . '/examples/run-integrity-demo.sh';
    $proc = proc_open(['bash', $script], [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    check(is_resource($proc)); fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    same(0, proc_close($proc));
    check(str_contains($out, 'Fingerprint divergence') && str_contains($out, 'Restored matching fingerprints'));
    check(!str_contains($err, 'ERROR:'));
});
test('Release lifecycle shell demo works from a clean state', static function (): void {
    if (PHP_OS_FAMILY === 'Windows') {
        return;
    }
    $script = dirname(__DIR__) . '/examples/run-lifecycle.sh';
    $proc = proc_open(['bash', $script], [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    check(is_resource($proc)); fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    same(0, proc_close($proc));
    check(str_contains($out, 'Six-hour reminder') && str_contains($out, 'Recovered'));
    check(!str_contains($err, 'ERROR:'));
});


// Fifth independent audit (V5) regressions; all data and endpoints are synthetic.
test('V5-01 separate real database error is never masked by tutorial context', static function (): void {
    $html = '<article><h1>Error establishing a database connection</h1><p>In this guide we explain database troubleshooting.</p></article>' .
        '<main><h2>Error establishing a database connection</h2><p>Database still down.</p></main>';
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    $old = StateEngine::transition([], issue(), 1000, 21600, ['site-a.example.com']);
    $classification = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html]);
    $now = StateEngine::transition($old['mode_state'], ['site-a.example.com' => ['code' => $classification['code'], 'detail' => $classification['detail']]], 2000, 21600, ['site-a.example.com']);
    same('changed', $now['events'][0]['type']);
    check(isset($now['mode_state']['issues']['site-a.example.com']));
});
test('V5-02 publication scanner detects WordPress constants and bearer tokens', static function (): void {
    // Split strings to keep synthetic credential fixtures out of release source.
    foreach ([
        '<?php ' . 'define(' . "'DB_" . "PASSWORD', '" . str_repeat('X', 28) . "');",
        '<?php ' . 'define(' . "'AUTH_" . "KEY', '" . str_repeat('X', 28) . "');",
        'Authorization: Bearer ' . str_repeat('A', 35),
        'GITHUB_' . 'TOKEN=' . str_repeat('Z', 35),
    ] as $content) {
        $d = tmp();
        try {
            file_put_contents($d . '/synthetic.php', $content);
            $run = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($run)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($run));
        } finally { deleteTree($d); }
    }
    $d = tmp();
    try {
        file_put_contents($d . '/wp-' . 'config.php', '<?php // synthetic placeholder');
        $run = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($run)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($run));
    } finally { deleteTree($d); }
});
test('V5-03 corrupt queued event rejected before delivery or rewrite', static function (): void {
    $d = tmp();
    try {
        $f = $d . '/state.json';
        $bad = ['schema_version' => 1, 'modes' => new stdClass(), 'outbox' => ['uptime' => [
            'pending' => [['id' => str_repeat('a', 32), 'event' => ['type' => 'new', 'target' => 'site-a.example.com']]],
            'claim' => null,
        ]]];
        $raw = json_encode($bad);
        file_put_contents($f, $raw);
        [$exit, $out] = cli(['flush', '--mode', 'uptime', '--state', $f]);
        same(1, $exit); same('', $out); same($raw, file_get_contents($f));
        raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage(['outbox' => ['integrity' => $bad['outbox']['uptime']]], 'uptime', [], 100), RuntimeException::class);
        raises(static fn () => \Portfolio\IncidentState\EventOutbox::stage(['schema_version' => 1], 'uptime', [['type' => 'new', 'target' => 'x']], 100), RuntimeException::class);
    } finally { deleteTree($d); }
});
test('V5-04 invalid other-mode incident state rejects normal scan and flush', static function (): void {
    $d = tmp();
    try {
        $f = $d . '/state.json';
        $bad = json_encode(['schema_version' => 1, 'modes' => ['integrity' => ['issues' => null, 'last_run' => 'invalid']]]);
        file_put_contents($f, $bad);
        $root = dirname(__DIR__);
        [$exit] = cli(['uptime', '--config', $root . '/config/demo.json', '--responses', $root . '/examples/responses/healthy.json', '--state', $f, '--at', '2026-01-01T00:00:00Z']);
        same(1, $exit); same($bad, file_get_contents($f));
        [$exit] = cli(['flush', '--state', $f, '--mode', 'uptime']);
        same(1, $exit); same($bad, file_get_contents($f));
    } finally { deleteTree($d); }
});
test('V5-05 hidden styles and title never satisfy visible-content sentinel', static function (): void {
    foreach ([
        '<div style=display:none>READY</div><main>Missing</main>',
        '<div style="opacity:0">READY</div><main>Missing</main>',
        '<title>READY</title><body>Missing</body>',
        '<section style="color:red; opacity: 0 !important"><span>READY</span></section><main>Missing</main>',
        '<section style="visibility:collapse">READY</section><main>Missing</main>',
    ] as $html) {
        $result = Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$html], ['contains'=>'READY']);
        same(str_contains($html, 'color:red') ? 'unverified_html' : 'content_assertion_failed', $result['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'<p>READY</p>'], ['contains'=>'READY'])['code']);
});
test('V5-06 unicode blank-only pages never pass meaningful content minimum', static function (): void {
    foreach (['<body>&nbsp;&nbsp;&nbsp;</body>', '<body>' . "\u{200B}\u{200C}\u{FEFF}" . '</body>', '<p>' . "\u{202F}\u{2009}" . '</p>'] as $html) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$html], ['min_body_bytes'=>1])['code']);
    }
});
test('V5-07 footer links and educational code examples do not create outages', static function (): void {
    foreach ([
        '<main><h1>Service operational</h1></main><footer><a>Error establishing a database connection</a></footer>',
        '<article><h1>How to debug PHP</h1><p>In this guide we explain PHP errors.</p><pre>PHP Fatal error: Uncaught RuntimeException</pre></article>',
        '<nav><a>There has been a critical error on this website.</a></nav><main>Service operational</main>',
    ] as $html) {
        same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$html])['code']);
    }
    same('application_php_fatal_error', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'<main><pre>PHP Fatal error: Uncaught RuntimeException</pre></main>'])['code']);
});
test('V5-08 verification gaps close on restored verification and retirement', static function (): void {
    $host = 'site-a.example.com';
    $first = StateEngine::transition([], [], 1000, 21600, [$host], [$host], 10, 3600);
    $gap = StateEngine::transition($first['mode_state'], [], 1010, 21600, [$host], [$host], 10, 3600);
    same('verification_gap', $gap['events'][0]['type']);
    $healthy = StateEngine::transition($gap['mode_state'], [], 1020, 21600, [$host], [], 10, 3600);
    same('verification_restored', $healthy['events'][0]['type']);
    same([], $healthy['mode_state']['unknown_history']);
    $failed = StateEngine::transition($gap['mode_state'], issue(), 1020, 21600, [$host], [], 10, 3600);
    same(['new', 'verification_restored'], array_column($failed['events'], 'type'));
    $retired = StateEngine::transition($gap['mode_state'], [], 1020, 21600, [], [], 10, 3600);
    same('verification_retired', $retired['events'][0]['type']);
});
test('V5-09 trailing-dot DNS equivalent is a safe unverified redirect', static function (): void {
    same('unverified_redirect', Classifier::classify('site-a.example.com', ['status_code'=>301,'redirect_location'=>'https://SITE-A.EXAMPLE.COM./'])['code']);
    same('unexpected_redirect', Classifier::classify('site-a.example.com', ['status_code'=>301,'redirect_location'=>'https://site-a.example.com.evil./'])['code']);
});
test('V5-10 fresh flush serializes top-level modes as JSON object', static function (): void {
    $d = tmp();
    try {
        $f = $d . '/new-state.json';
        [$exit] = cli(['flush','--state',$f,'--mode','uptime']);
        same(0, $exit);
        $json = (string) file_get_contents($f);
        check(str_contains($json, '"modes": {}'));
        check(!str_contains($json, '"modes": []'));
    } finally { deleteTree($d); }
});


test('V5-01 CLI never emits false recovery for a mixed tutorial and active database error', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        $mixed = '<article><h1>Error establishing a database connection</h1><p>In this guide we explain debugging.</p></article>' .
            '<main><h2>Error establishing a database connection</h2><p>Still down</p></main>';
        $rows = ['site-a.example.com' => ['status_code' => 500], 'site-b.example.org' => ['status_code' => 200, 'body' => 'Healthy']];
        file_put_contents($d . '/responses.json', json_encode($rows));
        $args = ['uptime', '--state', $state, '--responses', $d . '/responses.json'];
        [$exit, $out] = cli(array_merge($args, ['--at', '2026-01-01T00:00:00Z']));
        same(0, $exit); same('new', json_decode($out, true)['events'][0]['type']);
        $rows['site-a.example.com'] = ['status_code' => 200, 'body' => $mixed];
        file_put_contents($d . '/responses.json', json_encode($rows));
        [$exit, $out] = cli(array_merge($args, ['--at', '2026-01-01T00:30:00Z']));
        same(0, $exit);
        same('changed', json_decode($out, true)['events'][0]['type']);
        same('application_database_error', json_decode((string) file_get_contents($state), true)['modes']['uptime']['issues']['site-a.example.com']['code']);
    } finally { deleteTree($d); }
});
test('V5-08 CLI emits verification restoration event after prolonged unknown', static function (): void {
    $d = tmp();
    try {
        $state = $d . '/state.json';
        $rows = ['site-a.example.com' => ['status_code' => 301, 'redirect_location' => '/login'],
            'site-b.example.org' => ['status_code' => 200, 'body' => 'Healthy']];
        $file = $d . '/responses.json';
        $run = static fn (string $time): array => cli(['uptime', '--state', $state, '--responses', $file, '--at', $time]);
        file_put_contents($file, json_encode($rows));
        [$exit] = $run('2026-01-01T00:00:00Z'); same(0, $exit);
        [$exit, $out] = $run('2026-01-01T01:00:00Z'); same(0, $exit);
        same('verification_gap', json_decode($out, true)['events'][0]['type']);
        $rows['site-a.example.com'] = ['status_code' => 200, 'body' => 'Healthy'];
        file_put_contents($file, json_encode($rows));
        [$exit, $out] = $run('2026-01-01T01:30:00Z'); same(0, $exit);
        same('verification_restored', json_decode($out, true)['events'][0]['type']);
    } finally { deleteTree($d); }
});

// V6 independent audit regressions. These probe distinct error categories with
// controlled inputs, never live websites or proprietary infrastructure.
test('V6-01 database/critical errors normalize HTML NBSP and inline breaks', static function (): void {
    foreach ([
        '<h1>Error&nbsp;establishing a database connection</h1>' => 'application_database_error',
        '<h1>Error establishing a<br>database connection</h1>' => 'application_database_error',
        '<h1>There has been a critical&nbsp;error on this website.</h1>' => 'application_wp_critical_error',
        '<h1>There has been a critical<br>error on this website.</h1>' => 'application_wp_critical_error',
        '<h1>There has been a critical&#160;error on this website.</h1>' => 'application_wp_critical_error',
    ] as $html => $expected) {
        same($expected, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    }
});
test('V6-02 closed details and dialog cannot satisfy required visible content', static function (): void {
    foreach ([
        '<details><p>READY_MARKER</p></details>',
        '<details><summary>More information</summary><p>READY_MARKER</p></details>',
        '<dialog>READY_MARKER</dialog>',
        '<dialog><p>READY_MARKER</p></dialog>',
    ] as $html) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => '<main>Welcome</main>' . $html], ['contains' => 'READY_MARKER'])['code']);
    }
    // An open container and the first direct summary of closed details remain visible.
    foreach ([
        '<dialog open>READY_MARKER</dialog>',
        '<details open><p>READY_MARKER</p></details>',
        '<details><summary>READY_MARKER</summary><p>Private text</p></details>',
    ] as $html) {
        same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html],
            ['contains' => 'READY_MARKER'])['code']);
    }
});
test('V6-02 CLI does not falsely recover on invisible dialog sentinel', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $config = json_decode((string) file_get_contents($root . '/config/demo.json'), true);
        $config['content_policies']['site-a.example.com'] = ['min_body_bytes' => 1, 'contains' => 'READY_MARKER'];
        $configPath = $d . '/config.json'; file_put_contents($configPath, json_encode($config));
        $responsePath = $d . '/responses.json'; $statePath = $d . '/state.json';
        $responses = ['site-a.example.com' => ['status_code' => 500, 'body' => 'Broken'],
            'site-b.example.org' => ['status_code' => 200, 'body' => 'OK']];
        file_put_contents($responsePath, json_encode($responses));
        $args = ['uptime', '--config', $configPath, '--responses', $responsePath, '--state', $statePath];
        [$exit] = cli(array_merge($args, ['--at', '2026-01-01T00:00:00Z'])); same(0, $exit);
        $responses['site-a.example.com'] = ['status_code' => 200, 'body' => '<h1>Maintenance</h1><dialog>READY_MARKER</dialog>'];
        file_put_contents($responsePath, json_encode($responses));
        [$exit, $out] = cli(array_merge($args, ['--at', '2026-01-01T00:30:00Z'])); same(0, $exit);
        $types = array_column(json_decode($out, true)['events'], 'type');
        check(!in_array('recovered', $types, true));
        check(in_array('changed', $types, true));
    } finally { deleteTree($d); }
});
test('V6-04/05 examples and help-link titles do not cause false incidents', static function (): void {
    foreach ([
        '<main><h1>Help</h1><pre>Error establishing a database connection</pre><p>Everything works.</p></main>',
        '<main><h1>Help</h1><a href="/docs">Error establishing a database connection</a><p>Everything works.</p></main>',
        '<main><h1>Help</h1><code>There has been a critical error on this website.</code></main>',
    ] as $html) {
        same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    }
});
test('V6-06 instructional heading outside article is not an outage', static function (): void {
    $html = '<main><h1>Error establishing a database connection</h1><p>In this guide we show solutions</p></main>';
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    // An unrelated, later error must remain detectable despite a guide earlier.
    $html .= '<section><h2>There has been a critical error on this website.</h2></section>';
    same('application_wp_critical_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
});
test('V6-07 HTTP 200 service-temporarily-unavailable error template is detected', static function (): void {
    foreach (['<h1>503 Service Temporarily Unavailable</h1>', '<h1>Service Temporarily Unavailable</h1>'] as $html) {
        same('application_service_unavailable', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<h1>Guide to 503 Service Temporarily Unavailable errors</h1>'])['code']);
});
test('V6-08 inconsistent previous verification inventory is rejected in engine', static function (): void {
    $previous = ['last_run' => 100, 'issues' => [], 'inventory' => ['site-a.example.com'], 'unknown' => [],
        'unknown_history' => ['site-b.example.org' => ['first_seen' => 90, 'last_seen' => 100, 'last_notified' => 100]]];
    raises(static fn () => StateEngine::transition($previous, [], 150, 3600, ['site-a.example.com']), InvalidArgumentException::class);
});
test('V6-08 invalid history is rejected without rewriting persisted state', static function (): void {
    $d = tmp();
    try {
        $state = ['schema_version' => 1, 'modes' => ['uptime' => ['last_run' => 100, 'issues' => new stdClass(),
            'inventory' => ['site-a.example.com'], 'unknown' => [],
            'unknown_history' => ['site-b.example.org' => ['first_seen' => 90, 'last_seen' => 100, 'last_notified' => 100]]]]];
        $path = $d . '/bad.json'; $raw = json_encode($state); file_put_contents($path, $raw);
        [$exit] = cli(['flush', '--mode', 'uptime', '--state', $path]);
        same(1, $exit); same($raw, file_get_contents($path));
    } finally { deleteTree($d); }
});
test('V6-08 incomplete current-format verification state does not reset incidents', static function (): void {
    raises(static fn () => StateEngine::validateHistory(['last_run' => 100, 'issues' => [], 'inventory' => ['site-a.example.com'], 'unknown' => ['site-a.example.com']]), InvalidArgumentException::class);
    raises(static fn () => StateEngine::validateHistory(['last_run' => 100, 'issues' => [], 'unknown_history' => []]), InvalidArgumentException::class);
    // Complete pre-verification legacy state remains accepted.
    StateEngine::validateHistory(['last_run' => 100, 'issues' => []]);
});
test('V6-09 JSON list and object envelopes are not conflated', static function (): void {
    foreach (['{"schema_version":1,"modes":[]}', '{"schema_version":1,"modes":{},"outbox":[]}',
        '{"schema_version":1,"modes":{"uptime":{"issues":[]}}}',
        '{"schema_version":1,"modes":{},"outbox":{"uptime":{"pending":{},"claim":null}}}'] as $raw) {
        $d = tmp();
        try {
            $path = $d . '/state.json'; file_put_contents($path, $raw);
            [$exit] = cli(['flush', '--mode', 'uptime', '--state', $path]);
            same(1, $exit); same($raw, file_get_contents($path));
        } finally { deleteTree($d); }
    }
});
test('V6-03 strict release scan detects PHP putenv and constant secrets', static function (): void {
    $d = tmp();
    try {
        file_put_contents($d . '/config.php', '<?php' . "\n" .
            'putenv("AWS_SECRET' . '_ACCESS_KEY=notarealsecretvalue1234567890");' . "\n" .
            'const GITHUB_' . 'TOKEN = "notarealtokenvalue123456789012";' . "\n");
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]); $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(1, proc_close($proc)); check(str_contains($stderr, 'PHP') || str_contains($stderr, 'credential'));
        check(!str_contains($stdout, 'indicators clear'));
    } finally { deleteTree($d); }
});

// Version 8 independent-audit regressions. All fixtures and credentials are synthetic.
test('V7-01 greater-than within quoted HTML attribute does not expose hidden sentinel', static function (): void {
    foreach ([
        '<p>Welcome</p><div title="x > y" hidden>EXPECTED</div>',
        '<p>Welcome</p><div title="x > y" style="display:none">EXPECTED</div>',
        '<p>Welcome</p><div title="x > y" aria-hidden="true">EXPECTED</div>',
        "<p>Welcome</p><div title='x > y' style='visibility:hidden'>EXPECTED</div>",
    ] as $body) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $body], ['contains' => 'EXPECTED'])['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => '<p title="x > y">EXPECTED</p>'], ['contains' => 'EXPECTED'])['code']);
    same('unverified_html', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => '<div title="unclosed > something'], ['contains' => 'EXPECTED'])['code']);
});
test('V7-01 hidden sentinel never closes a real incident in CLI', static function (): void {
    $d = tmp();
    try {
        $r = dirname(__DIR__);
        $state = $d . '/state.json';
        $config = json_decode((string) file_get_contents($r . '/config/demo.json'), true);
        $config['content_policies']['site-a.example.com'] = ['contains' => 'EXPECTED'];
        file_put_contents($d . '/cfg.json', json_encode($config));
        [$exit] = cli(['uptime', '--config', $d . '/cfg.json', '--responses', $r . '/examples/responses/failure.json',
            '--state', $state, '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $rows = json_decode((string) file_get_contents($r . '/examples/responses/healthy.json'), true);
        $rows['site-a.example.com'] = ['status_code' => 200, 'body' => '<p>Welcome</p><div title="x > y" hidden>EXPECTED</div>'];
        file_put_contents($d . '/hidden.json', json_encode($rows));
        [$exit, $out] = cli(['uptime', '--config', $d . '/cfg.json', '--responses', $d . '/hidden.json',
            '--state', $state, '--at', '2026-01-01T00:30:00Z']);
        same(0, $exit);
        same(['changed'], array_column(json_decode($out, true)['events'], 'type'));
        same('content_assertion_failed', json_decode($out, true)['active_issues']['site-a.example.com']['code']);
    } finally { deleteTree($d); }
});
test('V7-03 instructional headings tolerate nested wrappers without masking later outages', static function (): void {
    $doc = '<h2>Error establishing a database connection</h2><div><p>In this guide we explain fixes.</p></div><p>Healthy.</p>';
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $doc])['code']);
    $mixed = $doc . '<main><h1>Error establishing a database connection</h1></main>';
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $mixed])['code']);
});
test('V7-04 instructional PHP pre examples outside articles remain healthy', static function (): void {
    $doc = '<h1>Understanding a PHP fatal error</h1><pre>PHP Fatal error: Uncaught Exception</pre><p>This is example documentation.</p>';
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $doc])['code']);
    same('application_php_fatal_error', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => $doc . '<main><pre>PHP Fatal error: Uncaught RuntimeException</pre></main>'])['code']);
});
test('V7-05 normalize required-content Unicode whitespace', static function (): void {
    foreach (['<p>Ready&nbsp;for service</p>', '<p>Ready' . "\u{2009}" . 'for service</p>',
        '<p>Ready' . "\u{202F}" . 'for service</p>'] as $body) {
        same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $body],
            ['contains' => 'Ready for service'])['code']);
    }
    same('content_assertion_failed', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => 'Ready for servicing'], ['contains' => 'Ready for service'])['code']);
});
test('V7-06 bad gateway templates fail while educational references stay healthy', static function (): void {
    foreach (['502 Bad Gateway' => 'application_bad_gateway', '504 Gateway Timeout' => 'application_gateway_timeout'] as $label => $code) {
        same($code, Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => '<h1>' . $label . '</h1><p>Proxy problem</p>'])['code']);
        same('healthy', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => '<h1>Debugging proxy failures</h1><p>How to fix ' . $label . '</p>'])['code']);
    }
});
test('V7-07 reject contradictory historical failures and unknowns', static function (): void {
    $host = 'site-a.example.com';
    $bad = ['last_run' => 100, 'inventory' => [$host], 'unknown' => [$host],
        'issues' => [$host => ['code' => 'http_error', 'detail' => 'HTTP 500', 'first_seen' => 10, 'last_seen' => 100, 'last_notified' => 10]],
        'unknown_history' => [$host => ['first_seen' => 10, 'last_seen' => 100, 'last_notified' => 30]]];
    raises(static fn () => StateEngine::validateHistory($bad), InvalidArgumentException::class);
    $d = tmp();
    try {
        file_put_contents($d . '/state.json', json_encode(['schema_version' => 1, 'modes' => ['uptime' => $bad]]));
        $original = (string) file_get_contents($d . '/state.json');
        [$exit] = cli(['flush', '--mode', 'uptime', '--state', $d . '/state.json']);
        check($exit !== 0);
        same($original, file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('V7-07 suspended failure survives unknown cycles and recovers once', static function (): void {
    $host = 'site-a.example.com';
    $bad = [$host => ['code' => 'http_error', 'detail' => 'HTTP 500']];
    $first = StateEngine::transition([], $bad, 100, 3600, [$host]);
    $lost = StateEngine::transition($first['mode_state'], [], 200, 3600, [$host], [$host]);
    same([], $lost['events']);
    same([], $lost['mode_state']['issues']);
    same('http_error', $lost['mode_state']['unknown_history'][$host]['last_confirmed_issue']['code']);
    StateEngine::validateHistory($lost['mode_state']);
    $again = StateEngine::transition($lost['mode_state'], [], 300, 3600, [$host], [$host]);
    same([], $again['events']);
    $recover = StateEngine::transition($again['mode_state'], [], 400, 3600, [$host]);
    same(['recovered'], array_column($recover['events'], 'type'));
    same([], StateEngine::transition($recover['mode_state'], [], 500, 3600, [$host])['events']);
    $repeat = StateEngine::transition($lost['mode_state'], $bad, 400, 3600, [$host]);
    same([], $repeat['events']);
    $changed = StateEngine::transition($lost['mode_state'], [$host => ['code'=>'transport_tls', 'detail'=>'Transport tls']], 400, 3600, [$host]);
    same(['changed'], array_column($changed['events'], 'type'));
    $retired = StateEngine::transition($lost['mode_state'], [], 400, 3600, []);
    same(['retired'], array_column($retired['events'], 'type'));
});
test('V7-02 synthetic PHP credential variables are rejected by release scan', static function (): void {
    $d = tmp();
    try {
        $variable = '$db_' . 'password'; // No credential-shaped assignment literal in the released source.
        file_put_contents($d . '/synthetic.php', '<?php ' . $variable . ' = "EXAMPLE_SYNTHETIC_DUMMY_VALUE_ABCDEF1234567890";');
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        check(proc_close($proc) !== 0);
        file_put_contents($d . '/synthetic.php', '<?php $value = getenv("EXAMPLE_ENV");');
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(0, proc_close($proc));
    } finally { deleteTree($d); }
});

// Version 8 independent-audit regressions: keep these in the permanent suite.
test('V8-01 raw-text and RCDATA HTML do not interrupt healthy observations', static function (): void {
    $cases = [
        '<script>if (a < b) { work(); }</script><main>Welcome</main>',
        '<style>main::after { content: "<span"; }</style><main>Welcome</main>',
        '<textarea>if (a < b) { data(); }</textarea><main>Welcome</main>',
        '<textarea><strong without a greater-than</textarea><main>Welcome</main>',
        '<script>const x = "<b"; const y = "</not-a-tag>";</script><main>Welcome</main>',
        '<main>3 < 5 and Welcome</main>',
    ];
    foreach ($cases as $body) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $body], ['contains' => 'Welcome']);
        same(str_contains($body, '<style>') ? 'unverified_html' : 'healthy', $r['code']);
    }
});
test('V8-01 raw script cannot abort sibling incident in CLI', static function (): void {
    $d = tmp();
    try {
        $fixture = json_decode(file_get_contents(dirname(__DIR__) . '/examples/responses/healthy.json'), true);
        $fixture['site-a.example.com'] = ['status_code' => 200,
            'body' => '<script>if (a < b) { work(); }</script><main>Welcome</main>'];
        $fixture['site-b.example.org'] = ['status_code' => 503, 'body' => 'Service unavailable'];
        file_put_contents($d . '/fixtures.json', json_encode($fixture));
        [$exit, $out] = cli(['uptime', '--state', $d . '/state.json', '--responses', $d . '/fixtures.json',
            '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $result = json_decode($out, true);
        same('healthy', $result['observations']['site-a.example.com']['code']);
        same('http_error', $result['observations']['site-b.example.org']['code']);
        same(['new'], array_column($result['events'], 'type'));
    } finally { deleteTree($d); }
});
test('V8-02 nginx 504 Time-out is not a healthy HTTP 200', static function (): void {
    foreach (['504 Gateway Time-out', 'Gateway Timeout', '504 Gateway Timeout', 'Gateway Time out'] as $title) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<h1>' . $title . '</h1><hr><center>nginx</center>']);
        same('application_gateway_timeout', $r['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<h1>Understanding a 504 Gateway Time-out</h1><p>This tutorial explains common proxy problems.</p>'])['code']);
});
test('V8-02 nginx 504 cannot falsely recover a prior outage via CLI', static function (): void {
    $d = tmp();
    try {
        $fixture = json_decode(file_get_contents(dirname(__DIR__) . '/examples/responses/healthy.json'), true);
        $fixture['site-a.example.com'] = ['status_code' => 500, 'body' => 'Server error'];
        file_put_contents($d . '/responses.json', json_encode($fixture));
        [$exit, $first] = cli(['uptime', '--state', $d . '/state.json', '--responses', $d . '/responses.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        same('new', json_decode($first, true)['events'][0]['type']);
        $fixture['site-a.example.com'] = ['status_code' => 200,
            'body' => '<html><h1>504 Gateway Time-out</h1><hr><center>nginx</center></html>'];
        file_put_contents($d . '/responses.json', json_encode($fixture));
        [$exit, $second] = cli(['uptime', '--state', $d . '/state.json', '--responses', $d . '/responses.json', '--at', '2026-01-01T00:30:00Z']);
        same(0, $exit);
        same('application_gateway_timeout', json_decode($second, true)['observations']['site-a.example.com']['code']);
        same(['changed'], array_column(json_decode($second, true)['events'], 'type'));
    } finally { deleteTree($d); }
});
test('V8-03 bounded backward clock change retains a live outbox claim', static function (): void {
    $event = demoAlert('site-a.example.com');
    $first = \Portfolio\IncidentState\EventOutbox::stage([], 'uptime', [$event], 1000);
    $pendingId = $first['events'][0]['id'];
    foreach ([999, 995, 901] as $clock) {
        $result = \Portfolio\IncidentState\EventOutbox::stage($first['state'], 'uptime', [], $clock);
        same(null, $result['token']);
        same([], $result['events']);
        same($pendingId, $result['state']['outbox']['uptime']['pending'][0]['id']);
    }
    $expired = \Portfolio\IncidentState\EventOutbox::stage($first['state'], 'uptime', [], 1120);
    check(is_string($expired['token']));
    same($pendingId, $expired['events'][0]['id']);
});
test('V8-04 strict scanner rejects indexed, associative, property and short PHP secrets', static function (): void {
    $d = tmp();
    try {
        $name = 'db_' . 'password';
        $dummy = 'SYNTHETIC_' . 'CHANGE_ME_1234567890';
        $sources = [
            '<?php $settings = [\'' . $name . '\' => \'' . $dummy . '\'];',
            '<?php $settings[\'' . $name . '\'] = \'' . $dummy . '\';',
            '<?php $server->password = \'' . $dummy . '\';',
            '<?php $server?->password = \'' . $dummy . '\';',
            '<?php $' . $name . ' = \'' . 'testpass1' . '\';',
        ];
        foreach ($sources as $source) {
            file_put_contents($d . '/sample.php', $source);
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            same(1, proc_close($p));
        }
        file_put_contents($d . '/sample.php', '<?php $safe = getenv("EXAMPLE_ENV");');
        $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($p)); fclose($pipes[0]);
        stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(0, proc_close($p));
    } finally { deleteTree($d); }
});
test('V8-05 inline display cascade and priority preserve visible markers', static function (): void {
    foreach ([
        'display:none;display:block',
        'display:none!important;display:block!important',
        'display:none;display:block!important',
        'display:block!important;display:none',
        'opacity:0;opacity:1',
        'visibility:hidden;visibility:visible',
    ] as $style) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<main style="' . $style . '">Welcome</main>'], ['contains' => 'Welcome']);
        same(true, $r['healthy']);
    }
    foreach (['display:block;display:none', 'display:none!important;display:block',
        'opacity:1;opacity:0', 'visibility:visible;visibility:hidden'] as $style) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<main style="' . $style . '">Welcome</main>'], ['contains' => 'Welcome']);
        same('content_assertion_failed', $r['code']);
    }
});
test('V8-06 invalid historical issue length is rejected before a transition', static function (): void {
    $old = StateEngine::transition([], issue(), 100, 3600, ['site-a.example.com']);
    $bad = $old['mode_state'];
    foreach (['code' => str_repeat('x', 129), 'detail' => str_repeat('y', 2049)] as $field => $value) {
        $one = $bad;
        $one['issues']['site-a.example.com'][$field] = $value;
        raises(static fn () => StateEngine::validateHistory($one), InvalidArgumentException::class);
    }
});
test('V8-06 corrupt persisted incidents are rejected without rewriting state', static function (): void {
    $d = tmp();
    try {
        $fixture = json_decode(file_get_contents(dirname(__DIR__) . '/examples/responses/healthy.json'), true);
        $fixture['site-a.example.com'] = ['status_code' => 500, 'body' => 'Server error'];
        file_put_contents($d . '/responses.json', json_encode($fixture));
        [$exit] = cli(['uptime', '--state', $d . '/state.json', '--responses', $d . '/responses.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $original = file_get_contents($d . '/state.json');
        $serialized = preg_replace('/"code"\s*:\s*"http_error"/', '"code": "' . str_repeat('z', 129) . '"', $original, 1);
        check(is_string($serialized) && $serialized !== $original);
        file_put_contents($d . '/state.json', $serialized);
        file_put_contents($d . '/responses.json', file_get_contents(dirname(__DIR__) . '/examples/responses/healthy.json'));
        [$exit, $out, $err] = cli(['uptime', '--state', $d . '/state.json', '--responses', $d . '/responses.json', '--at', '2026-01-01T00:30:00Z']);
        check($exit !== 0);
        check(str_contains($err, 'Corrupt incident history'));
        same($serialized, file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});

// Version 9 independent review: permanent, isolated negative regressions.
test('V9-01 incomplete saved issue history rejects flush and retains bytes', static function (): void {
    $d = tmp();
    try {
        [$exit] = cli(['uptime', '--responses', dirname(__DIR__) . '/examples/responses/failure.json',
            '--state', $d . '/state.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $state = json_decode((string) file_get_contents($d . '/state.json'), true);
        unset($state['modes']['uptime']['issues']);
        $state['modes']['uptime']['unknown_history'] = (object) $state['modes']['uptime']['unknown_history'];
        $bad = json_encode($state, JSON_UNESCAPED_SLASHES);
        file_put_contents($d . '/state.json', $bad);
        [$flush, , $error] = cli(['flush', '--mode', 'uptime', '--state', $d . '/state.json']);
        same(1, $flush);
        check(str_contains($error, 'Corrupt incident history'));
        same($bad, file_get_contents($d . '/state.json'));
        [$normal] = cli(['uptime', '--responses', dirname(__DIR__) . '/examples/responses/healthy.json',
            '--state', $d . '/state.json', '--at', '2026-01-01T00:10:00Z']);
        same(1, $normal);
        same($bad, file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('V9-01 initial state remains valid and current snapshot must contain issues', static function (): void {
    StateEngine::validateHistory([]);
    StateEngine::validateHistory(['issues' => [], 'last_run' => 100]);
    raises(static fn () => StateEngine::validateHistory(['inventory' => [], 'unknown' => [],
        'unknown_history' => [], 'last_run' => 100]), InvalidArgumentException::class);
});
test('V9-02 duplicate JSON member names and Unicode aliases reject without rewriting', static function (): void {
    $d = tmp();
    try {
        foreach (['{"schema_version":1,"modes":{},"modes":{}}',
            '{"schema_version":1,"modes":{"uptime":{"issues":{},"issues":{}}}}',
            '{"schema_version":1,"modes":{"uptime":{"issues":{},"i\\u0073sues":{}}}}'] as $bad) {
            $file = $d . '/state.json';
            file_put_contents($file, $bad);
            [$exit] = cli(['flush', '--mode', 'uptime', '--state', $file]);
            same(1, $exit);
            same($bad, file_get_contents($file));
        }
        \Portfolio\Support\UniqueJsonKeys::assertUnique('{"schema_version":1,"modes":{"uptime":{"issues":{}}}}');
    } finally { deleteTree($d); }
});
test('V9-03 strict scanner catches nested and compact JSON credentials', static function (): void {
    $d = tmp();
    try {
        $key = 'AWS_' . 'SECRET_ACCESS_KEY';
        $sample = 'synthetic_example_value_12345';
        foreach ([$key, 'db_' . 'password', 'secret_' . 'key', 'auth_' . 'token'] as $secret) {
            file_put_contents($d . '/payload.json', json_encode(['ok' => ['nested' => [$secret => $sample]]]));
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            same(1, proc_close($p));
        }
        file_put_contents($d . '/payload.json', '{"safe":{"healthy":true,"body":"demo"}}');
        $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        check(is_resource($p)); fclose($pipes[0]);
        stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        same(0, proc_close($p));
    } finally { deleteTree($d); }
});
test('V9-04 CSS comments conceal markers, including split declarations', static function (): void {
    foreach (['display:none /* comment */', '/* x */ display:none', 'dis/* x */play:none',
        'visibility: /* abc */ hidden', 'opacity:/* abc */0'] as $style) {
        $out = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<div style="' . $style . '">READY</div>'], ['contains' => 'READY']);
        same('content_assertion_failed', $out['code']);
    }
    same(true, Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<div style="display:none /* abc */;display:block">READY</div>'], ['contains' => 'READY'])['healthy']);
});
test('V9-04 hidden CSS cannot recover failed host in CLI', static function (): void {
    $d = tmp();
    try {
        $config = json_decode((string) file_get_contents(dirname(__DIR__) . '/config/demo.json'), true);
        $config['content_policies']['site-a.example.com'] = ['contains' => 'READY'];
        file_put_contents($d . '/config.json', json_encode($config));
        $fixture = json_decode((string) file_get_contents(dirname(__DIR__) . '/examples/responses/healthy.json'), true);
        $fixture['site-a.example.com'] = ['status_code' => 200, 'body' => '<div style="display:none /* comment */">READY</div>'];
        file_put_contents($d . '/hidden.json', json_encode($fixture));
        [$first] = cli(['uptime', '--config', $d . '/config.json', '--state', $d . '/state.json',
            '--responses', dirname(__DIR__) . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $first);
        [$second, $output] = cli(['uptime', '--config', $d . '/config.json', '--state', $d . '/state.json',
            '--responses', $d . '/hidden.json', '--at', '2026-01-01T00:10:00Z']);
        same(0, $second);
        $parsed = json_decode($output, true);
        foreach ($parsed['events'] as $event) {
            check(!($event['target'] === 'site-a.example.com' && $event['type'] === 'recovered'));
        }
        same('content_assertion_failed', $parsed['active_issues']['site-a.example.com']['code']);
    } finally { deleteTree($d); }
});
test('V9-05 oversized unverified targets are rejected at state load', static function (): void {
    $name = str_repeat('x', 300);
    $history = ['issues' => [], 'last_run' => 100, 'inventory' => [$name], 'unknown' => [$name],
        'unknown_history' => [$name => ['first_seen' => 0, 'last_seen' => 100, 'last_notified' => 100]]];
    raises(static fn () => StateEngine::validateHistory($history), InvalidArgumentException::class);
    $d = tmp();
    try {
        $raw = json_encode(['schema_version' => 1, 'modes' => ['uptime' => $history], 'outbox' => (object) []]);
        file_put_contents($d . '/state.json', $raw);
        [$exit] = cli(['flush', '--mode', 'uptime', '--state', $d . '/state.json']);
        same(1, $exit);
        same($raw, file_get_contents($d . '/state.json'));
    } finally { deleteTree($d); }
});
test('V9-06 unrelated invalid config section does not stop selected mode', static function (): void {
    $d = tmp();
    try {
        $base = json_decode((string) file_get_contents(dirname(__DIR__) . '/config/demo.json'), true);
        $u = $base; $u['integrity'] = 'BROKEN';
        file_put_contents($d . '/uptime.json', json_encode($u));
        [$exit] = cli(['uptime', '--config', $d . '/uptime.json', '--state', $d . '/state.json',
            '--responses', dirname(__DIR__) . '/examples/responses/healthy.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $i = $base; $i['content_policies'] = 'BROKEN';
        // Copy config to packaged directory because relative fixture root is confined.
        $local = dirname(__DIR__) . '/config/.v9-isolation-' . bin2hex(random_bytes(8)) . '.json';
        try {
            file_put_contents($local, json_encode($i));
            [$exit, , $err] = cli(['integrity', '--config', $local, '--state', $d . '/integrity.json', '--at', '2026-01-01T00:00:00Z']);
            same(0, $exit);
        } finally { @unlink($local); }
    } finally { deleteTree($d); }
});
test('V9-07 textarea example remains healthy, real error still detected', static function (): void {
    $example = '<html><body><h2>Paste error here</h2><textarea>Error establishing a database connection</textarea></body></html>';
    same(true, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $example])['healthy']);
    $real = $example . '<h1>Error establishing a database connection</h1>';
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $real])['code']);
});
test('V9-08 active SVG is rejected; static SVG is permitted', static function (): void {
    $d = tmp();
    try {
        $file = $d . '/diagram.svg';
        $run = static function () use ($d): int {
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($p);
        };
        file_put_contents($file, '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>');
        same(1, $run());
        foreach (['<svg><script>bad</script></svg>', '<svg><a href="javascript:alert(1)">x</a></svg>',
            '<svg><image href="https://example.com/image.svg" /></svg>', '<!DOCTYPE svg><svg/>'] as $payload) {
            file_put_contents($file, $payload);
            same(1, $run());
        }
        file_put_contents($file, '<svg xmlns="http://www.w3.org/2000/svg"><text>Safe schematic</text></svg>');
        same(0, $run());
    } finally { deleteTree($d); }
});

test('V9-02 duplicate configuration members rejected as well as persisted state', static function (): void {
    $d = tmp();
    try {
        $config = (string) file_get_contents(dirname(__DIR__) . '/config/demo.json');
        $config = preg_replace('/\A\s*\{/', '{"hosts":[],', $config, 1);
        check(is_string($config));
        $file = $d . '/config.json';
        file_put_contents($file, $config);
        raises(static fn () => Config::load($file, 'uptime'), InvalidArgumentException::class);
    } finally { deleteTree($d); }
});

// Version 10 independent audit regressions and additional same-boundary hardening.
test('V10-01 duplicate response host and nested properties reject without mutating state', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        [$exit] = cli(['uptime', '--config', $root . '/config/demo.json', '--state', $state,
            '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $saved = file_get_contents($state);
        $host = 'site-a.example.com';
        $other = 'site-b.example.org';
        $badInputs = [
            '{"' . $host . '":{"status_code":500},"' . $host . '":{"status_code":200},"' . $other . '":{"status_code":200}}',
            '{"' . $host . '":{"status_code":500,"status_code":200},"' . $other . '":{"status_code":200}}',
            '{"' . $host . '":{"status_code":500,"status_\\u0063ode":200},"' . $other . '":{"status_code":200}}',
        ];
        foreach ($badInputs as $i => $raw) {
            file_put_contents($d . '/bad.json', $raw);
            [$exit, $stdout] = cli(['uptime', '--config', $root . '/config/demo.json', '--state', $state,
                '--responses', $d . '/bad.json', '--at', '2026-01-01T00:30:00Z']);
            same(1, $exit);
            same('', $stdout);
            same($saved, file_get_contents($state));
        }
    } finally { deleteTree($d); }
});
test('V10-02 inline help on a real error remains an incident', static function (): void {
    foreach ([
        '<main><p>Error establishing a database connection <small>Please try later</small></p></main>' => 'application_database_error',
        '<main><h1>There has been a critical error on this website. <small>Please contact support</small></h1></main>' => 'application_wp_critical_error',
        '<main><p>Error establishing a database connection <span>Try again later</span></p></main>' => 'application_database_error',
    ] as $html => $expected) {
        same($expected, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['code']);
    }
});
test('V10-02 tutorial and support examples do not become incidents', static function (): void {
    foreach ([
        '<h1>Error establishing a database connection</h1><p>In this guide we explain why the error appears.</p>',
        '<article><h1>There has been a critical error on this website</h1><p>This tutorial describes the issue.</p></article>',
        '<p>This guide explains what error establishing a database connection means.</p>',
    ] as $html) {
        same(true, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html])['healthy']);
    }
});
test('V10-02 failed host does not falsely recover on application error with inline help', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        [$exit] = cli(['uptime', '--config', $root . '/config/demo.json', '--state', $state,
            '--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $rows = json_decode((string) file_get_contents($root . '/examples/responses/healthy.json'), true);
        $rows['site-a.example.com'] = ['status_code' => 200,
            'body' => '<main><p>Error establishing a database connection <small>Please try later</small></p></main>'];
        file_put_contents($d . '/responses.json', json_encode($rows));
        [$exit, $stdout] = cli(['uptime', '--config', $root . '/config/demo.json', '--state', $state,
            '--responses', $d . '/responses.json', '--at', '2026-01-01T00:30:00Z']);
        same(0, $exit);
        $data = json_decode($stdout, true);
        same('application_database_error', $data['active_issues']['site-a.example.com']['code']);
        foreach ($data['events'] as $event) {
            check(!($event['target'] === 'site-a.example.com' && $event['type'] === 'recovered'));
        }
    } finally { deleteTree($d); }
});
test('V10-03 invalid HTML returns unknown, never a healthy result', static function (): void {
    foreach (['<p title="unterminated>Welcome</p>', '<!-- unterminated', '<div title="a < b">READY</div><p title="broken>'] as $html) {
        $result = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html], ['contains' => 'READY']);
        same(null, $result['healthy']);
        same('unverified_html', $result['code']);
    }
    $result = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => "\xff"]);
    same('unverified_html', $result['code']);
});
test('V10-03 malformed HTML on one host does not abort sibling outage checks', static function (): void {
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $state = $d . '/state.json';
        $rows = ['site-a.example.com' => ['status_code' => 200, 'body' => '<p title="unterminated>Welcome</p>'],
            'site-b.example.org' => ['status_code' => 500, 'body' => 'outage']];
        file_put_contents($d . '/rows.json', json_encode($rows));
        [$exit, $out] = cli(['uptime', '--config', $root . '/config/demo.json', '--responses', $d . '/rows.json',
            '--state', $state, '--at', '2026-01-01T00:00:00Z']);
        same(0, $exit);
        $data = json_decode($out, true);
        same('http_error', $data['active_issues']['site-b.example.org']['code']);
        check(in_array('site-a.example.com', $data['unverified_targets'], true));
        same('unverified_html', $data['observations']['site-a.example.com']['code']);
    } finally { deleteTree($d); }
});
test('V10-04 HTML attributes are compared by exact name, not suffix', static function (): void {
    foreach (['data-style="display:none"', 'data-aria-hidden="true"', 'data-hidden', 'data-open', 'xstyle=display:none',
        'some-aria-hidden=true', 'data-type=hidden'] as $attributes) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<main ' . $attributes . '>Welcome</main>'], ['contains' => 'Welcome']);
        same(true, $r['healthy']);
    }
    foreach (['style="display:none"', 'style=display:none', 'aria-hidden="true"', 'hidden', 'hidden="false"'] as $attributes) {
        $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
            'body' => '<main ' . $attributes . '>Welcome</main>'], ['contains' => 'Welcome']);
        same('content_assertion_failed', $r['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<main data-style="display:none" style="display:block">Welcome</main>'], ['contains' => 'Welcome'])['code']);
});
test('V10-05 release scan rejects camelCase JSON credentials without false positives', static function (): void {
    $d = tmp();
    try {
        $namePairs = [['db','Password'], ['access','Token'], ['refresh','Token'], ['jwt','Secret'],
            ['api','Key'], ['client','Secret'], ['AWS','SecretAccessKey']];
        foreach ($namePairs as $parts) {
            $key = implode('', $parts);
            file_put_contents($d . '/fixture.json', json_encode(['example' => [$key => 'synthetic_' . 'value_123456789012']]));
            $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
            check(is_resource($proc)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
            same(1, proc_close($proc));
        }
        file_put_contents($d . '/fixture.json', '{"example":{"refreshInterval":3600,"enabled":true}}');
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]);
        stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
        same(0, proc_close($proc));
    } finally { deleteTree($d); }
});
test('V10-05 structured secret scanner rejects numeric values and duplicate keys', static function (): void {
    $d = tmp();
    try {
        $scan = static function () use ($d): int {
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); return proc_close($p);
        };
        $key = 'db' . 'Password';
        file_put_contents($d . '/fixture.json', json_encode([$key => 123456]));
        same(1, $scan());
        // Reject ambiguous objects even when the last duplicate is harmless.
        file_put_contents($d . '/fixture.json', '{"fixture":1,"fixture":2}');
        same(1, $scan());
    } finally { deleteTree($d); }
});
test('V10-06 SVG external CSS imports rejected while plain static SVG passes', static function (): void {
    $d = tmp();
    try {
        $run = static function () use ($d): int {
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($p);
        };
        $external = '@' . 'import' . ' "https://example.org/demo.css";';
        file_put_contents($d . '/diagram.svg', '<svg xmlns="http://www.w3.org/2000/svg"><style>' . $external . '</style></svg>');
        same(1, $run());
        file_put_contents($d . '/diagram.svg', '<svg xmlns="http://www.w3.org/2000/svg"><style>text{fill:black}</style></svg>');
        same(1, $run());
        file_put_contents($d . '/diagram.svg', '<svg xmlns="http://www.w3.org/2000/svg"><text>Static diagram</text></svg>');
        same(0, $run());
    } finally { deleteTree($d); }
});
test('V10 CI workflow explicitly restricts GitHub token', static function (): void {
    $workflow = (string) file_get_contents(dirname(__DIR__) . '/.github/workflows/ci.yml');
    check(str_contains($workflow, "permissions:\n  contents: read\n"));
});


// Independent Version 11 audit remediations. Synthetic inputs only; no network.
test('V11-01 prefixed database error never closes a confirmed incident', static function (): void {
    $body = '<div><strong>Database Error:</strong> Error establishing a database connection</div>';
    same('application_database_error', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$body])['code']);
    $d = tmp();
    try {
        $root = dirname(__DIR__);
        $responses = json_decode((string)file_get_contents($root . '/examples/responses/healthy.json'), true);
        $responses['site-a.example.com'] = ['status_code'=>500,'body'=>'failed'];
        file_put_contents($d.'/r.json', json_encode($responses));
        [$exit] = cli(['uptime','--config',$root.'/config/demo.json','--responses',$d.'/r.json','--state',$d.'/state.json','--at','2026-01-01T00:00:00Z']);
        same(0,$exit);
        $responses['site-a.example.com'] = ['status_code'=>200,'body'=>$body];
        file_put_contents($d.'/r.json', json_encode($responses));
        [$exit,$out] = cli(['uptime','--config',$root.'/config/demo.json','--responses',$d.'/r.json','--state',$d.'/state.json','--at','2026-01-01T00:30:00Z']);
        same(0,$exit);
        $report = json_decode($out, true);
        check(!in_array('recovered', array_column($report['events'],'type'),true));
        same('application_database_error',$report['active_issues']['site-a.example.com']['code']);
    } finally { deleteTree($d); }
});
test('V11-02 instructional elements cannot create false incidents', static function (): void {
    foreach ([
        '<main><h1>Fixing WordPress issues</h1><p>In this tutorial, we explain common messages.</p><div><p>Error establishing a database connection</p></div></main>',
        '<article><h1>Error establishing a database connection</h1><p>In this guide, we explain troubleshooting.</p></article>',
        '<h2>Understanding PHP errors</h2><pre>PHP Fatal error: Uncaught RuntimeException</pre><p>This is example documentation.</p>',
        '<main><p>Service OK</p><a href="/help">There has been a critical error on this website.</a></main>',
    ] as $body) {
        same('healthy',Classifier::classify('site-a.example.com',['status_code'=>200,'body'=>$body])['code']);
    }
    $mixed = '<article><h1>Error establishing a database connection</h1><p>In this guide we explain it.</p></article>'.
        '<main><h2>Error establishing a database connection</h2><p>Database still down.</p></main>';
    same('application_database_error',Classifier::classify('site-a.example.com',['status_code'=>200,'body'=>$mixed])['code']);
});
test('V11-03 inherited visibility can be overridden by a displayed descendant', static function (): void {
    $host = 'site-a.example.com';
    $result = Classifier::classify($host, ['status_code'=>200,
        'body'=>'<div style="visibility:hidden"><span style="visibility:visible">Dashboard Ready</span></div>'],
        ['contains'=>'Dashboard Ready']);
    same('healthy',$result['code']);
    foreach (['display:none','opacity:0'] as $style) {
        same('content_assertion_failed',Classifier::classify($host,['status_code'=>200,
            'body'=>'<div style="'.$style.'"><span style="visibility:visible">Dashboard Ready</span></div>'],
            ['contains'=>'Dashboard Ready'])['code']);
    }
});
test('V11-04 YAML nested access tokens, short passwords and connection URLs fail release scan', static function (): void {
    $d = tmp();
    try {
        $scan = static function () use ($d): int {
            $proc = proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php', '--release', $d],
                [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($proc);
        };
        foreach ([
            "auth:\n  access".'Token: "fake-token-1234567890123456"' . "\n",
            'DB_'.'PASSWORD: "shortpw9"' . "\n",
            'database_'.'url: "' . sprintf('%s://%s', 'postgresql', 'demo:fakeword@localhost:5432/app') . '"' . "\n",
            'secrets: {client'.'Secret: 23456789}' . "\n",
        ] as $yaml) {
            file_put_contents($d.'/fixture.yml',$yaml);
            same(1,$scan());
        }
        file_put_contents($d.'/fixture.yml',"service:\n  port: 8080\n  timeout: 30\n");
        same(0,$scan());
    } finally { deleteTree($d); }
});
test('V11-05 generic PHP define() secrets fail release scan', static function (): void {
    $d=tmp();
    try {
        $scan = static function () use($d): int {
            $proc=proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php','--release',$d],
                [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($proc);
        };
        file_put_contents($d.'/fixture.php', '<?php define("APP_' . 'PASSWORD", "fake-password-123456789");');
        same(1,$scan());
        file_put_contents($d.'/fixture.php','<?php define("APP_TIMEOUT", 3600);');
        same(0,$scan());
    } finally { deleteTree($d); }
});
test('V11-06 XML-entity encoded SVG links are rejected; native diagrams pass', static function (): void {
    $d=tmp();
    try {
        $scan = static function () use($d): int {
            $proc=proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php','--release',$d],
                [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($proc);
        };
        $unsafe='<svg xmlns="http://www.w3.org/2000/svg"><a href="&#' . '106;avascript:alert(1)">Example</a></svg>';
        file_put_contents($d.'/fixture.svg',$unsafe);
        same(1,$scan());
        file_put_contents($d.'/fixture.svg','<svg xmlns="http://www.w3.org/2000/svg"><text>Static</text></svg>');
        same(0,$scan());
    } finally { deleteTree($d); }
});

test('V12 structural error regions ignore zero-opacity bodies and honor visible summaries', static function (): void {
    $h = 'site-a.example.com';
    foreach (['opacity:0.000', 'opacity:0.0'] as $style) {
        $html = '<main><h1>Welcome</h1><p style="' . $style . '">Error establishing a database connection</p></main>';
        same('healthy', Classifier::classify($h,['status_code'=>200,'body'=>$html])['code']);
    }
    same('application_database_error', Classifier::classify($h,['status_code'=>200,
        'body'=>'<details><summary>Error establishing a database connection</summary><p>Not expanded.</p></details>'])['code']);
    same('healthy', Classifier::classify($h,['status_code'=>200,
        'body'=>'<details><summary>Summary</summary><p>Error establishing a database connection</p></details>'])['code']);
});
test('V12 malformed CSS comments cannot prove healthy content', static function (): void {
    same('unverified_html', Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<p>Visible</p><span style="visibility:visible;/*unterminated">READY</span>'],
        ['contains'=>'READY'])['code']);
});


// Version 12 independent audit: all cases below failed against the published
// v12 ZIP before remediation. These tests are offline and use synthetic inputs.
foreach ([
    'DOCTYPE with empty body' => '<!DOCTYPE html><html><body></body></html>',
    'XML processing instruction with empty body' => '<?xml version="1.0"?><html><body></body></html>',
    'DOCTYPE with quoted bracket' => '<!DOCTYPE html [ <!ENTITY x "[synthetic]"> ]><html><body></body></html>',
] as $name => $page) {
    test('V12-01 declarations are never visible text: ' . $name, static function () use ($page): void {
        same('content_assertion_failed', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $page], ['min_body_bytes' => 1])['code']);
    });
}
test('V12-01 normal body content after a DOCTYPE remains visible', static function (): void {
    same('healthy', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => '<!DOCTYPE html><html><body>READY</body></html>'],
        ['contains' => 'READY', 'min_body_bytes' => 1])['code']);
});
foreach (['hidden', 'style="display:none"', 'aria-hidden="true"', 'style="opacity:0"'] as $attribute) {
    test('V12-02 explicit concealment never reveals a details summary: ' . $attribute,
        static function () use ($attribute): void {
            $page = '<details ' . $attribute . '><summary>READY</summary></details>';
            same('content_assertion_failed', Classifier::classify('site-a.example.com',
                ['status_code' => 200, 'body' => $page], ['contains' => 'READY'])['code']);
            same('content_assertion_failed', Classifier::classify('site-a.example.com',
                ['status_code' => 200, 'body' => '<details ' . $attribute . '><summary>Error establishing a database connection</summary></details>'])['code']);
        });
}
test('V12-02 unhidden closed details first summary is visible', static function (): void {
    same('healthy', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => '<details><summary>READY</summary><p>Concealed</p></details>'],
        ['contains' => 'READY'])['code']);
});
foreach ([
    '500 Internal Server Error' => 'application_internal_server_error',
    'HTTP Error 503. The service is unavailable.' => 'application_service_unavailable',
] as $banner => $expected) {
    test('V12-03 HTTP 200 server error is an incident: ' . $banner, static function () use ($banner, $expected): void {
        $page = '<main><h1>' . $banner . '</h1><p>Server</p></main>';
        same($expected, Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $page])['code']);
        $tutorial = '<main><h1>Guide to diagnosing websites</h1><p>In this tutorial we explain an error.</p><h2>' . $banner . '</h2></main>';
        same('unverified_html', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $tutorial])['code']);
    });
}
foreach (['track', 'param', 'col'] as $void) {
    test('V12-04 void ' . $void . ' cannot conceal following siblings', static function () use ($void): void {
        $page = '<main><' . $void . ' hidden><h1>Error establishing a database connection</h1></main>';
        same('application_database_error', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $page])['code']);
        same('healthy', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => '<' . $void . ' hidden><span>READY</span>'],
            ['contains' => 'READY'])['code']);
        check(Classifier::isVoidTag($void));
    });
}
test('V12-05 Authorization headers and credential-bearing URLs are blocked in release scanner', static function (): void {
    $d = tmp();
    try {
        $scan = static function () use ($d): int {
            $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($proc));
            fclose($pipes[0]);
            stream_get_contents($pipes[1]);
            stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($proc);
        };
        $bearer = 'Bearer ' . 'SyntheticOnlyAbcdefghijklmnop012345';
        foreach ([
            ['fixture.json', json_encode(['authorization' => $bearer], JSON_THROW_ON_ERROR)],
            ['fixture.yml', 'authorization: "' . $bearer . '"' . "\n"],
            ['fixture.json', json_encode(['dsn' => sprintf('%s://%s', 'mysql', 'demo:synthetic_pass@example.com/db')], JSON_THROW_ON_ERROR)],
            ['fixture.yml', 'service:\n  dsn: "' . sprintf('%s://%s', 'mysql', 'demo:synthetic_pass@example.com/db') . '"' . "\n"],
        ] as [$file, $content]) {
            foreach (['fixture.json', 'fixture.yml'] as $name) { @unlink($d . '/' . $name); }
            file_put_contents($d . '/' . $file, $content);
            same(1, $scan());
        }
        @unlink($d . '/fixture.json'); @unlink($d . '/fixture.yml');
        file_put_contents($d . '/fixture.json', json_encode(['url' => 'https://example.com/public', 'port' => 443], JSON_THROW_ON_ERROR));
        same(0, $scan());
    } finally { deleteTree($d); }
});
test('V12 false recovery cannot follow an empty document, hidden details or a server error banner', static function (): void {
    $root = dirname(__DIR__); $base = json_decode(file_get_contents($root . '/config/demo.json'), true);
    check(is_array($base));
    $cases = [
        ['<!DOCTYPE html><html><body></body></html>', ['min_body_bytes' => 1]],
        ['<?xml version="1.0"?><html><body></body></html>', ['min_body_bytes' => 1]],
        ['<details hidden><summary>READY</summary></details>', ['contains' => 'READY']],
        ['<details aria-hidden="true"><summary>READY</summary></details>', ['contains' => 'READY']],
        ['<details style="display:none"><summary>READY</summary></details>', ['contains' => 'READY']],
        ['<h1>500 Internal Server Error</h1>', ['min_body_bytes' => 1]],
        ['<h1>HTTP Error 503. The service is unavailable.</h1>', ['min_body_bytes' => 1]],
        ['<track hidden><h1>Error establishing a database connection</h1><p>READY</p>', ['contains' => 'READY']],
    ];
    $d = tmp();
    try {
        foreach ($cases as $i => [$body, $policy]) {
            $state = $d . '/state-' . $i . '.json';
            $base['content_policies'] = ['site-a.example.com' => $policy, 'site-b.example.org' => ['min_body_bytes' => 1]];
            $config = $d . '/config.json';
            file_put_contents($config, json_encode($base, JSON_THROW_ON_ERROR));
            $file = $d . '/responses.json';
            file_put_contents($file, json_encode(['site-a.example.com' => ['status_code' => 500, 'body' => 'Failure'],
                'site-b.example.org' => ['status_code' => 200, 'body' => 'Healthy']], JSON_THROW_ON_ERROR));
            [$start] = cli(['uptime', '--config', $config, '--state', $state, '--responses', $file, '--at', '2026-01-01T00:00:00Z']);
            same(0, $start);
            file_put_contents($file, json_encode(['site-a.example.com' => ['status_code' => 200, 'body' => $body],
                'site-b.example.org' => ['status_code' => 200, 'body' => 'Healthy']], JSON_THROW_ON_ERROR));
            [$exit, $output] = cli(['uptime', '--config', $config, '--state', $state, '--responses', $file, '--at', '2026-01-01T00:10:00Z']);
            same(0, $exit);
            $decoded = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
            check(!in_array('recovered', array_column($decoded['events'], 'type'), true), 'Unexpected recovery in case ' . $i);
        }
    } finally { deleteTree($d); }
});

// Version 13 independent audit remediation: paired positive/negative evidence.
// External hosts, configuration and sensitive values are strictly synthetic.
foreach (['<div popover="auto">READY</div>', '<div popover="manual">READY</div>',
    '<datalist><option>READY</option></datalist>', '<iframe src="https://example.com"><p>READY</p></iframe>',
    '<canvas>READY</canvas>', '<object>READY</object>', '<audio>READY</audio>', '<video>READY</video>'] as $html) {
    test('C13-01 inactive and fallback content never establishes site health: ' . substr($html, 0, 30),
        static function () use ($html): void {
            same('content_assertion_failed', Classifier::classify('site-a.example.com',
                ['status_code' => 200, 'body' => $html], ['contains' => 'READY'])['code']);
            $fault = str_replace('READY', 'Error establishing a database connection', $html);
            same('healthy', Classifier::classify('site-a.example.com',
                ['status_code' => 200, 'body' => '<p>Working</p>' . $fault])['code']);
        });
}
test('C13-01 visible sibling remains usable after non-rendered subtree', static function (): void {
    same('healthy', Classifier::classify('site-a.example.com', [
        'status_code' => 200, 'body' => '<datalist><option>NOT READY</option></datalist><p>READY</p>'],
        ['contains' => 'READY'])['code']);
});
test('C13-02 real error banners survive nearby references to troubleshooting', static function (): void {
    foreach (['<h1>500 Internal Server Error</h1><p>See our troubleshooting guide for more information.</p>',
        '<h1>There has been a critical error on this website.</h1><p>This guide is temporarily unavailable.</p>',
    ] as $html) {
        check(str_starts_with(Classifier::classify('site-a.example.com', [
            'status_code' => 200, 'body' => '<main>' . $html . '</main>'])['code'], 'application_'));
    }
});
test('C13-03 instructional prefixed headings do not become incidents', static function (): void {
    foreach (['<article><h1>Database Error: Error establishing a database connection</h1><p>This guide explains how to resolve it.</p></article>',
        '<main><h1>WordPress Error: There has been a critical error on this website</h1><p>In this article we demonstrate a solution.</p></main>'] as $html) {
        same('healthy', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $html])['code']);
    }
});
test('C13-04 self-closing nonvoid HTML cannot prove a recovery', static function (): void {
    same('unverified_html', Classifier::classify('site-a.example.com', [
        'status_code' => 200, 'body' => '<div hidden/><p>READY</p>'], ['contains' => 'READY'])['code']);
    same('healthy', Classifier::classify('site-a.example.com', [
        'status_code' => 200, 'body' => '<br/><p>READY</p>'], ['contains' => 'READY'])['code']);
});
test('C13-05 CSS escapes never prove visibility without CSS rendering', static function (): void {
    foreach (['display:n\\6fne', 'di\\73play:none', 'visibility:vi\\73ible'] as $style) {
        same('unverified_html', Classifier::classify('site-a.example.com', [
            'status_code' => 200, 'body' => '<div style="' . $style . '">READY</div>'],
            ['contains' => 'READY'])['code']);
    }
});
test('C13-01/02/04/05 active outage cannot be closed by non-evidence', static function (): void {
    $root = dirname(__DIR__); $config = json_decode((string)file_get_contents($root . '/config/demo.json'), true, 512, JSON_THROW_ON_ERROR);
    $config['content_policies']['site-a.example.com'] = ['contains' => 'READY', 'min_body_bytes' => 1];
    $cases = ['<div popover="auto">READY</div>', '<datalist>READY</datalist>',
        '<iframe><p>READY</p></iframe>', '<canvas>READY</canvas>',
        '<div hidden/><p>READY</p>', '<div style="display:n\\6fne">READY</div>',
        '<h1>500 Internal Server Error</h1><p>See our troubleshooting guide.</p><p>READY</p>'];
    $temp = tmp();
    try {
        file_put_contents($temp . '/config.json', json_encode($config, JSON_THROW_ON_ERROR));
        $response = $temp . '/responses.json';
        foreach ($cases as $i => $html) {
            $state = $temp . '/state-' . $i . '.json';
            file_put_contents($response, json_encode(['site-a.example.com' => ['status_code' => 500, 'body' => 'Broken'],
                'site-b.example.org' => ['status_code' => 200, 'body' => 'Working']], JSON_THROW_ON_ERROR));
            [$code] = cli(['uptime', '--config', $temp . '/config.json', '--state', $state, '--responses', $response,
                '--at', '2026-01-01T00:00:00Z']); same(0, $code);
            file_put_contents($response, json_encode(['site-a.example.com' => ['status_code' => 200, 'body' => $html],
                'site-b.example.org' => ['status_code' => 200, 'body' => 'Working']], JSON_THROW_ON_ERROR));
            [$code, $out] = cli(['uptime', '--config', $temp . '/config.json', '--state', $state,
                '--responses', $response, '--at', '2026-01-01T00:05:00Z']); same(0, $code);
            $parsed = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
            check(!in_array('recovered', array_column($parsed['events'], 'type'), true), 'False recovery ' . $i);
        }
    } finally { deleteTree($temp); }
});
test('C13-06/07 security scanner rejects all discovered YAML and JSON secret formats', static function (): void {
    $dir = tmp();
    try {
        $scan = static function () use ($dir): int {
            $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $dir],
                [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
            check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); return proc_close($proc);
        };
        $key = 'DB_' . 'PASSWORD'; $value = 'demo' . '1234';
        $samples = [
            ['fixture.yml', "env:\n - name: " . $key . "\n   value: " . $value . "\n"],
            ['fixture.yml', "environment:\n - " . $key . '=' . $value . "\n"],
            ['fixture.yml', 'environment: [' . $key . '=' . $value . "]\n"],
            ['fixture.yml', "env: [{name: " . $key . ', value: ' . $value . "}]\n"],
            ['fixture.json', json_encode(['database' . 'Credentials' => $value], JSON_THROW_ON_ERROR)],
            ['fixture.json', json_encode(['database' => ['credentials' => $value]], JSON_THROW_ON_ERROR)],
        ];
        foreach ($samples as [$filename, $content]) {
            foreach (['fixture.yml', 'fixture.json'] as $name) { @unlink($dir . '/' . $name); }
            file_put_contents($dir . '/' . $filename, $content);
            check($scan() === 1, 'Scanner missed ' . $filename . ' case ' . sha1($content));
        }
        @unlink($dir . '/fixture.yml'); @unlink($dir . '/fixture.json');
        file_put_contents($dir . '/fixture.yml', "service:\n  port: 8080\n");
        same(0, $scan());
    } finally { deleteTree($dir); }
});
test('C13-08 invalid XML is rejected while static diagrams validate', static function (): void {
    $validator = \Portfolio\Support\StaticSvgValidator::class;
    check($validator::isWellFormed('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'));
    foreach (['<svg><rect></svg>', '<svg><rect/></svg><svg/>', '<svg><rect x=10 /></svg>',
        '<svg><rect x="1" x="2" /></svg>', '<svg><text>broken</svg>'] as $invalid) {
        same(false, $validator::isWellFormed($invalid));
    }
    $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/validate_svg.php'],
        [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); same(0, proc_close($proc));
    $dir = tmp();
    try {
        file_put_contents($dir . '/broken.svg', '<svg><rect></svg>');
        $proc = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/validate_svg.php', $dir],
            [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        check(is_resource($proc)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); same(1, proc_close($proc));
    } finally { deleteTree($dir); }
});


// V14 independent audit — durable, synthetic negative and positive controls.
foreach ([
    'unrelated heading' => '<main><h2>How to check server status</h2><h1>500 Internal Server Error</h1><p>READY</p></main>',
    'unrelated article introduction' => '<article><p>In this guide we explain server status.</p><h1>500 Internal Server Error</h1><p>READY</p></article>',
] as $name => $html) {
    test('V14-01 instructional introduction cannot confirm recovery: ' . $name,
        static function () use ($html): void {
            $result = Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => $html], ['contains' => 'READY']);
            same(null, $result['healthy']);
            same('unverified_html', $result['code']);
        });
}
test('V14-02 unselected option is never a visible success marker', static function (): void {
    $html = '<p>Loading</p><select><option selected>Loading</option><option>READY</option></select>';
    same('content_assertion_failed', Classifier::classify('site-a.example.com',
        ['status_code' => 200, 'body' => $html], ['contains' => 'READY'])['code']);
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<p>READY</p><select><option>Loading</option></select>'], ['contains'=>'READY'])['code']);
});
test('V14-03 meta refresh is never evidence of completed destination health', static function (): void {
    foreach (['<meta http-equiv="refresh" content="0;url=https://example.org/path">',
        '<META HTTP-EQUIV=REFRESH CONTENT="10; url=/next">',
        '<meta content="0;url=https://example.org/next" http-equiv="refresh">'] as $tag) {
        $r = Classifier::classify('site-a.example.com', ['status_code'=>200,
            'body'=>'<html><head>'.$tag.'</head><body>READY</body></html>'], ['contains'=>'READY']);
        same(null, $r['healthy']); same('unverified_redirect', $r['code']);
    }
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<html><head><meta name="description" content="refresh tips"></head><body>READY</body></html>'],
        ['contains'=>'READY'])['code']);
});
test('V14-04 strict scanner recognizes abbreviated credential names across formats', static function (): void {
    $dir = tmp();
    try {
        $scan = static function () use ($dir): int {
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $dir],
                [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes);
            check(is_resource($p)); fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]); return proc_close($p);
        };
        $longValue = 'synthetic-demo-passphrase-123';
        $samples = [
            ['config.yaml', 'db'.'_pass: "'.$longValue.'"'],
            ['config.yaml', 'mysql'.'_pwd: "'.$longValue.'"'],
            ['config.yaml', 'services:' . "\n" . '  service:' . "\n" . '    environment:' . "\n" . '      - DB'.'_PASS='.$longValue],
            ['config.json', json_encode(['db'.'Pass'=>$longValue])],
            ['config.json', json_encode(['mysql'.'Pwd'=>$longValue])],
            ['config.php', '<?php $db'.'_pwd = "short12";'],
        ];
        foreach ($samples as [$filename, $text]) {
            @unlink($dir.'/config.yaml'); @unlink($dir.'/config.json'); @unlink($dir.'/config.php');
            file_put_contents($dir.'/'.$filename, $text);
            same(1, $scan());
        }
        @unlink($dir.'/config.yaml'); @unlink($dir.'/config.json'); @unlink($dir.'/config.php');
        file_put_contents($dir.'/config.json', '{"maintenancePeriod":1800,"services":2}');
        same(0, $scan());
    } finally { deleteTree($dir); }
});
test('V14-05 default HTTP 200 cannot prove recovery without meaningful text', static function (): void {
    foreach (['', '<!DOCTYPE html>', '<head><title>Welcome</title></head>','<script>READY</script>'] as $body) {
        same('content_assertion_failed', Classifier::classify('site-a.example.com',
            ['status_code'=>200,'body'=>$body])['code']);
    }
    same('unverified_http_status', Classifier::classify('site-a.example.com', ['status_code'=>204])['code']);
    same('unverified_http_status', Classifier::classify('site-a.example.com', ['status_code'=>201])['code']);
});
test('V14-06 heading preserves inline anchor text while excluding link-only evidence', static function (): void {
    $page = '<main><h1>Error establishing a <a href="/help">database</a> connection</h1><p>READY</p></main>';
    same('application_database_error', Classifier::classify('site-a.example.com',
        ['status_code'=>200,'body'=>$page])['code']);
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<main><h1>Help center</h1><a href="/help">Error establishing a database connection</a></main>'])['code']);
});
test('V14-07 recognized server-error separator variants', static function (): void {
    foreach (['500 - Internal Server Error', '500: Internal Server Error', '500 Internal Server Error'] as $text) {
        same('application_internal_server_error', Classifier::classify('site-a.example.com',
            ['status_code'=>200,'body'=>'<h1>'.$text.'</h1><p>READY</p>'])['code']);
    }
});
test('V14-08 preformatted database examples do not generate confirmed false incidents', static function (): void {
    $r = Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<pre>Error establishing a database connection</pre>']);
    same(null, $r['healthy']); same('unverified_html', $r['code']);
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<main><h1>Help</h1><pre>Error establishing a database connection</pre><p>Service OK</p></main>'])['code']);
});
test('V14-09 inline SVG style CSS is denied before escaped URL interpretation', static function (): void {
    $dir = tmp();
    try {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:'.'\\75rl(https://example.net/icon.png)" width="1" height="1"/></svg>';
        file_put_contents($dir.'/graphic.svg', $svg);
        same(false, \Portfolio\Support\StaticSvgValidator::isWellFormed($svg));
        $p = proc_open([PHP_BINARY, dirname(__DIR__).'/tools/publication_scan.php','--release',$dir],
            [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        check(is_resource($p));fclose($pipes[0]);stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);
        fclose($pipes[1]);fclose($pipes[2]);same(1,proc_close($p));
    } finally { deleteTree($dir); }
});
test('V14-10 uptime-only verification thresholds do not invalidate integrity mode', static function (): void {
    $d=tmp();
    try {
        cloneTree(dirname(__DIR__).'/examples/fixtures/sites',$d.'/sites');
        $cfg=json_decode((string)file_get_contents(dirname(__DIR__).'/config/demo.json'),true,512,JSON_THROW_ON_ERROR);
        $cfg['integrity']['root']='sites';
        $cfg['unverified_threshold_seconds']='invalid';
        file_put_contents($d.'/c.json',json_encode($cfg,JSON_THROW_ON_ERROR));
        [$exit] = cli(['integrity','--config',$d.'/c.json','--state',$d.'/s.json','--at','2026-01-01T00:00:00Z']);
        same(0,$exit);
        [$exit] = cli(['uptime','--config',$d.'/c.json','--state',$d.'/u.json',
            '--responses',dirname(__DIR__).'/examples/responses/healthy.json','--at','2026-01-01T00:00:00Z']);
        same(1,$exit);
    } finally { deleteTree($d); }
});
test('V14-11 canonical equivalent Unicode content matches in both directions', static function (): void {
    $decomposed='Cafe'."\u{0301}";
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$decomposed],
        ['contains'=>'Café'])['code']);
    same('healthy', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'Café'],
        ['contains'=>$decomposed])['code']);
});
// Reproduce all six safety-critical CLI lifecycles against persisted state.
foreach ([
    'heading_intro'=>'<main><h2>How to check server status</h2><h1>500 Internal Server Error</h1><p>READY</p></main>',
    'article_intro'=>'<article><p>In this guide we explain server status.</p><h1>500 Internal Server Error</h1><p>READY</p></article>',
    'unselected_option'=>'<p>Loading</p><select><option selected>Loading</option><option>READY</option></select>',
    'meta_refresh'=>'<html><head><meta http-equiv="refresh" content="0;url=/somewhere"></head><body>READY</body></html>',
    'inline_link_error'=>'<main><h1>Error establishing a <a href="/help">database</a> connection</h1><p>READY</p></main>',
    'alternate_500'=>'<h1>500 - Internal Server Error</h1><p>READY</p>',
] as $name=>$body) {
    test('V14 no false recovery on active outage through CLI: '.$name, static function () use ($body): void {
        $d=tmp();
        try {
            $cfg=json_decode((string)file_get_contents(dirname(__DIR__).'/config/demo.json'),true,512,JSON_THROW_ON_ERROR);
            $cfg['content_policies']['site-a.example.com']=['min_body_bytes'=>1,'contains'=>'READY'];
            file_put_contents($d.'/c.json',json_encode($cfg,JSON_THROW_ON_ERROR));
            $responses=['site-a.example.com'=>['status_code'=>500,'body'=>'HTTP 500'],
                'site-b.example.org'=>['status_code'=>200,'body'=>'READY']];
            file_put_contents($d.'/r.json',json_encode($responses,JSON_THROW_ON_ERROR));
            $base=['uptime','--config',$d.'/c.json','--state',$d.'/s.json','--responses',$d.'/r.json'];
            [$exit]=cli(array_merge($base,['--at','2026-01-01T00:00:00Z']));same(0,$exit);
            $responses['site-a.example.com']=['status_code'=>200,'body'=>$body];
            file_put_contents($d.'/r.json',json_encode($responses,JSON_THROW_ON_ERROR));
            [$exit,$output]=cli(array_merge($base,['--at','2026-01-01T00:30:00Z']));same(0,$exit);
            $result=json_decode($output,true,512,JSON_THROW_ON_ERROR);
            check(!in_array('recovered',array_column($result['events'],'type'),true));
            check($result['observations']['site-a.example.com']['healthy']!==true);
        } finally {deleteTree($d);}
    });
}

require __DIR__ . '/v16_regressions.php';
require __DIR__ . '/cmm17_regressions.php';

printf("\n%d tests; %d failures\n", $tests, $failures);

if ($measureCoverage) {
    $data = xdebug_get_code_coverage();
    xdebug_stop_code_coverage();
    $src = realpath(dirname(__DIR__) . '/src') . DIRECTORY_SEPARATOR;
    $executed = 0;
    $executable = 0;
    foreach ($data as $filename => $lines) {
        $path = realpath($filename);
        // CLI subprocesses execute in separate processes and are not included.
        // This is strictly in-process unit coverage, not overall coverage.
        if ($path === false || !str_starts_with($path, $src)) {
            continue;
        }
        foreach ($lines as $hits) {
            if ($hits >= 0 || $hits === -1) { // -1: executable but uncovered; -2: dead code.
                $executable++;
                if ($hits > 0) {
                    $executed++;
                }
            }
        }
    }
    if ($executable === 0) {
        fwrite(STDERR, "No source lines instrumented; coverage invalid.\n");
        exit(1);
    }
    printf("In-process source line coverage: %d/%d (%.1f%%); CLI subprocesses excluded\n", $executed, $executable, 100 * $executed / $executable);
}
exit($failures === 0 ? 0 : 1);
