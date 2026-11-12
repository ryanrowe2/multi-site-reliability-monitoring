<?php

declare(strict_types=1);

use Portfolio\Monitoring\Classifier;
use Portfolio\IncidentState\StateStore;

// These regressions are included by run.php after the shared test harness.
// Every test uses offline synthetic inputs and leaves source artifacts unchanged.

foreach ([
    'opacity:0%' => 'content_assertion_failed',
    'opacity:0e0' => 'content_assertion_failed',
    'opacity:0.0%' => 'content_assertion_failed',
    'opacity:calc(0)' => 'unverified_html',
    'content-visibility:hidden' => 'content_assertion_failed',
    'display:var(--hide);--hide:none' => 'unverified_html',
    'filter:opacity(0%)' => 'unverified_html',
    'transform:scale(0)' => 'unverified_html',
    'clip-path:inset(50%)' => 'unverified_html',
    'font-size:0' => 'unverified_html',
    'color:transparent' => 'unverified_html',
] as $css => $expected) {
    test('V16 hidden or unsupported CSS never confirms health: ' . $css, static function () use ($css, $expected): void {
        $r = Classifier::classify('site-a.example.com', [
            'status_code' => 200, 'body' => '<main><span style="' . $css . '">READY</span><p>Waiting</p></main>'
        ], ['contains' => 'READY']);
        same($expected, $r['code']);
        check($r['healthy'] !== true);
    });
}

test('V16 ambiguous CSS cannot create a false incident from concealed text', static function (): void {
    $r = Classifier::classify('site-a.example.com', [
        'status_code' => 200,
        'body' => '<h1 style="filter:opacity(0%)">500 Internal Server Error</h1><p>READY</p>',
    ]);
    same('unverified_html', $r['code']);
});

test('V16 decoded active HTML meta refresh cannot confirm recovery', static function (): void {
    $r = Classifier::classify('site-a.example.com', [
        'status_code' => 200, 'body' => '<meta http-equiv="re&#x66;resh" content="0;url=https://example.org"><p>READY</p>'
    ], ['contains' => 'READY']);
    same('unverified_redirect', $r['code']);
});

test('V16 inert or malformed HTML refresh does not trigger false navigation', static function (): void {
    foreach (['<template><meta http-equiv="refresh" content="0;url=/elsewhere"></template><p>READY</p>',
        '<meta http-equiv="refresh" content="this is not a directive"><p>READY</p>'] as $html) {
        same('healthy', Classifier::classify('site-a.example.com',
            ['status_code' => 200, 'body' => $html], ['contains' => 'READY'])['code']);
    }
});

foreach ([201,202,204,205,207,299] as $status) {
    test('V16 default recovery requires page-status proof, not empty HTTP ' . $status, static function () use ($status): void {
        same('unverified_http_status', Classifier::classify('site-a.example.com', ['status_code' => $status])['code']);
    });
}

test('CMM-17 zero-evidence bodyless success policy is rejected', static function (): void {
    raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 204], ['min_body_bytes' => 0]), \InvalidArgumentException::class);
});

test('V16 genuine database error with trailing text remains failure', static function (): void {
    $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<h1>Error establishing a database connection — The site is down</h1>']);
    same('application_database_error', $r['code']);
});

test('V16 real later error overrides earlier ambiguous instructional example', static function (): void {
    $r = Classifier::classify('site-a.example.com', ['status_code' => 200,
        'body' => '<section><pre>Error establishing a database connection</pre></section><section><h1>500 Internal Server Error</h1></section>']);
    same('application_internal_server_error', $r['code']);
});

test('V16 writer rejects unreadable state before committing it', static function (): void {
    $dir = tmp();
    try {
        $file = $dir . '/state.json';
        $store = new StateStore($file);
        $store->transaction(static fn (array $state): array => ['state' => $state, 'result' => null]);
        $before = file_get_contents($file);
        foreach ([
            ['outbox' => null],
            ['modes' => ['uptime' => ['issues' => 'bad']]],
            ['outbox' => ['uptime' => ['pending' => [['id' => 'bad', 'event' => []]], 'claim' => null]]],
        ] as $fragment) {
            raises(static fn () => $store->transaction(static fn (array $state): array =>
                ['state' => array_replace($state, $fragment), 'result' => null]), RuntimeException::class);
            same($before, file_get_contents($file));
        }
    } finally { deleteTree($dir); }
});

test('V16 strict scanner recognizes credential formats from complete audit', static function (): void {
    $dir = tmp();
    try {
        $scan = static function () use ($dir): int {
            $r = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $dir],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            check(is_resource($r)); fclose($pipes[0]);
            stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            return proc_close($r);
        };
        $secret = str_repeat('example', 4);
        $url = sprintf('%s://%s', 'postgresql', 'demo:' . $secret . '@localhost/database');
        $cases = [
            'json' => [
                json_encode(['DBPASS' => $secret], JSON_THROW_ON_ERROR),
                json_encode(['PGPASSWORD' => $secret], JSON_THROW_ON_ERROR),
                json_encode(['SERVICE_AUTH' => $secret], JSON_THROW_ON_ERROR),
                json_encode(['databaseCredentials' => ['password' => $secret]], JSON_THROW_ON_ERROR),
            ],
            'yml' => [
                'DBPASS: ' . $secret,
                'db_uri: ' . $secret,
                'environment:' . "\n" . '  - DBPASS=' . $secret,
                'environment: [DBPASS=' . $secret . ']',
                'env:' . "\n" . '  - name: DBPASS' . "\n" . '    value: ' . $secret,
                'uri: ' . $url,
            ],
            'php' => [
                '<?php $url = ' . var_export($url, true) . ';',
                '<?php $url = ' . var_export('postgresql://demo:', true) . ' . ' . var_export($secret . '@localhost/database', true) . ';',
                '<?php define(' . var_export('DBPASS', true) . ', ' . var_export($secret, true) . ');',
                '<?php $password = <<<' . "'END'\n" . $secret . "\nEND;\n",
            ],
            'svg' => [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect fill="u' . '\\' . '72l(https://example.org/resource)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect foo:bar="x"/></svg>',
            ],
        ];
        foreach ($cases as $ext => $samples) {
            foreach ($samples as $case) {
                $file = $dir . '/fixture.' . $ext;
                file_put_contents($file, $case);
                same(1, $scan());
                unlink($file);
            }
        }
        file_put_contents($dir . '/good.json', '{"kind":"synthetic","value":"READY"}');
        same(0, $scan());
    } finally { deleteTree($dir); }
});

test('V16 no false recovery after unsupported HTML or bodyless status', static function (): void {
    $dir = tmp();
    try {
        $root = dirname(__DIR__);
        $config = json_decode((string) file_get_contents($root . '/config/demo.json'), true, 512, JSON_THROW_ON_ERROR);
        $config['content_policies']['site-a.example.com']['contains'] = 'READY';
        file_put_contents($dir . '/config.json', json_encode($config, JSON_THROW_ON_ERROR));
        $base = ['uptime', '--config', $dir . '/config.json', '--state', $dir . '/state.json'];
        [$exit] = cli(array_merge($base, ['--responses', $root . '/examples/responses/failure.json', '--at', '2026-01-01T00:00:00Z']));
        same(0, $exit);
        foreach ([
            ['status_code' => 200, 'body' => '<span style="opacity:0%">READY</span><p>Waiting</p>'],
            ['status_code' => 200, 'body' => '<meta http-equiv="re&#x66;resh" content="0;url=/next"><p>READY</p>'],
            ['status_code' => 202],
            ['status_code' => 204],
        ] as $i => $observation) {
            $response = ['site-a.example.com' => $observation, 'site-b.example.org' => ['status_code'=>200,'body'=>'READY']];
            $fixture = $dir . '/response.json';
            file_put_contents($fixture, json_encode($response, JSON_THROW_ON_ERROR));
            [$exit, $output] = cli(array_merge($base, ['--responses', $fixture,
                '--at', sprintf('2026-01-01T%02d:00:00Z', $i + 1)]));
            same(0, $exit);
            $result = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
            check(!in_array('recovered', array_column($result['events'], 'type'), true));
            check($result['observations']['site-a.example.com']['healthy'] !== true);
        }
    } finally { deleteTree($dir); }
});
