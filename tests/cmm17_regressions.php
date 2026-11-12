<?php

declare(strict_types=1);

use Portfolio\Monitoring\Classifier;
use Portfolio\IncidentState\StateStore;
use Portfolio\IncidentState\StateEngine;
use Portfolio\Support\Config;
use Portfolio\Support\PortableNfc;

/** Isolated synthetic release scan. Nothing is published or executed remotely. */
function cmm17Scan(string $ext, string $body): int
{
    $d = tmp();
    try {
        file_put_contents($d . '/synthetic.' . $ext, $body);
        $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/tools/publication_scan.php', '--release', $d],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($p)) { throw new RuntimeException('Scanner failed to launch'); }
        fclose($pipes[0]); stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        return proc_close($p);
    } finally { deleteTree($d); }
}

test('CMM17-01 empty and zero-evidence policies cannot prove recovery', static function (): void {
    foreach ([[], ['min_body_bytes' => 0], ['min_body_bytes' => 0, 'contains' => null]] as $policy) {
        if ($policy === []) { continue; } // [] is the default contract, never a configured override
        raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => ''], $policy), InvalidArgumentException::class);
        raises(static fn () => Classifier::classify('site-a.example.com', ['status_code' => 201, 'body' => ''], $policy), InvalidArgumentException::class);
    }
    same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code' => 200, 'body' => ''])['code']);
    same('unverified_http_status', Classifier::classify('site-a.example.com', ['status_code' => 201, 'body' => ''])['code']);
    $d=tmp();
    try {
        $root=dirname(__DIR__);
        $config=json_decode((string)file_get_contents($root.'/config/demo.json'),true,512,JSON_THROW_ON_ERROR);
        foreach ([[], ['min_body_bytes'=>0], ['contains'=>null,'min_body_bytes'=>0]] as $policy) {
            $config['content_policies']['site-a.example.com']=$policy;
            file_put_contents($d.'/config.json',json_encode($config,JSON_THROW_ON_ERROR));
            raises(static fn()=> Config::load($d.'/config.json','uptime'), InvalidArgumentException::class);
        }
    } finally {deleteTree($d);}
});

test('CMM17-02 C0 C1 and DEL controls never count as meaningful content', static function (): void {
    foreach ([0x00, 0x01, 0x07, 0x1b, 0x7f, 0x80, 0x9f] as $code) {
        $char=$code<=0x7f?chr($code):($code===0x80?"\u{0080}":"\u{009F}");
        if ($code === 0x00) { // Embedded NUL is an observation datum, not meaningful text.
            same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$char])['code']);
            continue;
        }
        same('content_assertion_failed', Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$char])['code']);
    }
});

test('CMM17-03 real server and WordPress errors with trailing details remain failures', static function (): void {
    foreach ([
      '<h1>500 Internal Server Error Please retry later</h1>' => 'application_internal_server_error',
      '<h1>There has been a critical error on this website. ' . str_repeat('Contact the administrator. ',15) . '</h1>' => 'application_wp_critical_error',
      '<h1>Error establishing a database connection ' . str_repeat('Retry this request. ', 30) . '</h1>' => 'application_database_error',
      '<h1>HTTP Error 503. The service is unavailable.</h1>' => 'application_service_unavailable',
    ] as $page=>$expected) {
        same($expected, Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$page])['code']);
    }
});

test('CMM17-04 guide after a real failure cannot confirm recovery', static function (): void {
    foreach ([
      '<h1>Error establishing a database connection</h1><p>This guide explains how to fix the issue.</p>',
      '<h1>There has been a critical error on this website.</h1><p>This guide explains how to fix it.</p>',
      '<h1>500 Internal Server Error</h1><p>How to check server status.</p>',
    ] as $body) {
        $r=Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>$body]);
        check($r['healthy']!==true);
    }
});

test('CMM17-05 missing outbox in modern state cannot discard undelivered alerts', static function (): void {
    $d=tmp();
    try {
        $f=$d.'/s.json';
        $store=new StateStore($f);
        $store->transaction(static fn(array $state):array=>['state'=>$state,'result'=>null]);
        $original=json_decode((string)file_get_contents($f),true,512,JSON_THROW_ON_ERROR);
        same(2,$original['schema_version']);
        unset($original['outbox']);
        file_put_contents($f,json_encode($original,JSON_THROW_ON_ERROR));
        $before=file_get_contents($f);
        raises(static fn()=> $store->transaction(static fn(array $state):array=>['state'=>$state,'result'=>null]), RuntimeException::class);
        same($before,file_get_contents($f));
    } finally {deleteTree($d);}
});

test('CMM17-05 legacy migration requires explicit acknowledgment and preserves backup', static function (): void {
    $d=tmp();
    try {
        $f=$d.'/s.json';
        $legacy=['schema_version'=>1,'modes'=>['uptime'=>['issues'=>new stdClass(),'last_run'=>100]]];
        $raw=json_encode($legacy,JSON_THROW_ON_ERROR);
        file_put_contents($f,$raw);
        $store=new StateStore($f);
        raises(static fn()=> $store->transaction(static fn(array $state):array=>['state'=>$state,'result'=>null]),RuntimeException::class);
        raises(static fn()=> $store->migrateLegacyWithBackup(false),RuntimeException::class);
        same($raw,file_get_contents($f));
        $backup=$store->migrateLegacyWithBackup(true);
        same($raw,file_get_contents($backup));
        same(2,json_decode((string)file_get_contents($f),true,512,JSON_THROW_ON_ERROR)['schema_version']);
        $store->transaction(static fn(array $state):array=>['state'=>$state,'result'=>null]);
        raises(static fn()=> $store->migrateLegacyWithBackup(true), RuntimeException::class);
    } finally {deleteTree($d);}
});

test('CMM17-06/07 decoded and reordered YAML credentials are rejected', static function (): void {
    $name='access'.'Token';$value='FauxSecret'.'ABC123XYZ';
    foreach ([
      '"access\\u0054oken": "'.$value.'"' . "\n",
      "environment:\n - value: ".$value."\n   name: ACCESS_TOKEN\n",
      "environment: [{value: ".$value.", name: ACCESS_TOKEN}]\n",
      "defaults:\n  name: safe\n  accessToken: ".$value."\n",
      "x: &anchor {name: ACCESS_TOKEN, value: ".$value."}\ny: *anchor\n",
    ] as $yaml) {
        same(1,cmm17Scan('yml',$yaml));
    }
    same(0,cmm17Scan('yaml',"jobs:\n  run:\n    - name: Test\n      command: echo READY\n"));
});

test('CMM17-08 PHP concatenated sensitive array/object properties are rejected', static function (): void {
    $key='access'.'Token';$a='FauxSecret';$b='ABC123XYZ';
    foreach ([
        '<?php $cfg["'.$key.'"] = "'.$a.'" . "'.$b.'";',
        '<?php $cfg->'.$key.' = "'.$a.'" . "'.$b.'";',
        '<?php $cfg["'.$key.'"] = "short";',
        '<?php $db_password = "x";',
    ] as $code) { same(1,cmm17Scan('php',$code)); }
});

test('CMM17-09 short shell and text credentials cannot pass strict scan', static function (): void {
    $name='DB_'.'PASSWORD';$value='Abc'.'123!';
    foreach (['sh'=>'#!/bin/sh' . "\nexport ".$name.'='.$value."\n",
              'txt'=>$name.'='.$value."\n"] as $ext=>$content) {
        same(1,cmm17Scan($ext,$content));
    }
});

test('CMM17-10 preformatted service errors in documentation are not definite outages', static function (): void {
    $r=Classifier::classify('site-a.example.com', ['status_code'=>200,
        'body'=>'<main><p>Here is an example:</p><pre>500 Internal Server Error</pre></main>']);
    check($r['healthy']!==false);
    same('application_internal_server_error', Classifier::classify('site-a.example.com',
        ['status_code'=>200,'body'=>'<h1>500 Internal Server Error</h1>'])['code']);
});

test('CMM17-11 state engine event admission equals outbox contract', static function (): void {
    foreach ([['code'=>str_repeat('c',129),'detail'=>'short'],
              ['code'=>'x','detail'=>str_repeat('y',2049)]] as $issue) {
        raises(static fn()=> StateEngine::transition([],['site-a.example.com'=>$issue],1000,3600,['site-a.example.com']),InvalidArgumentException::class);
    }
    $r=StateEngine::transition([],['site-a.example.com'=>['code'=>'valid','detail'=>'okay']],1000,3600,['site-a.example.com']);
    \Portfolio\IncidentState\EventOutbox::stage(['schema_version'=>2,'modes'=>[]], 'uptime', $r['events'],1000);
});

test('CMM17-12 full portable NFC is available without ext-intl', static function (): void {
    foreach ([["\u{AC00}","\u{1100}\u{1161}"],["\u{00E9}","e\u{0301}"],["\u{1E69}","s\u{0323}\u{0307}"]] as $pair) {
        same(PortableNfc::normalize($pair[0]),PortableNfc::normalize($pair[1]));
        same('healthy',Classifier::classify('site-a.example.com',['status_code'=>200,'body'=>$pair[0]],['contains'=>$pair[1]])['code']);
    }
});

test('CMM17-13 obsolete parallel CSS interpretation has been removed', static function (): void {
    $reflection=new ReflectionClass(Classifier::class);
    foreach (['inlineRules','hiddenInlineStyle','inlineVisibility'] as $method) {
        check(!$reflection->hasMethod($method));
    }
});

test('CMM17 machine-readable JSON endpoint establishes health with explicit positive evidence', static function (): void {
    $policy=['json_health'=>['field'=>'status','equals'=>'ok']];
    same('healthy',Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'{"status":"ok"}'],$policy)['code']);
    same('content_assertion_failed',Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'{"status":"down"}'],$policy)['code']);
    same(null,Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'{"status":"ok","status":"down"}'],$policy)['healthy']);
    same(null,Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'{"other":"ok"}'],$policy)['healthy']);
    same(null,Classifier::classify('site-a.example.com', ['status_code'=>201,'body'=>'{"status":"ok"}'],$policy)['healthy']);
    same(null,Classifier::classify('site-a.example.com', ['status_code'=>200,'body'=>'<div class="x">ok</div>'],$policy)['healthy']);
});

test('CMM17 config validates JSON health contracts without weakening standard policies', static function (): void {
    $d=tmp();
    try {
        $cfg=json_decode((string)file_get_contents(dirname(__DIR__).'/config/demo.json'),true,512,JSON_THROW_ON_ERROR);
        $cfg['content_policies']['site-a.example.com']=['json_health'=>['field'=>'status','equals'=>'ok']];
        file_put_contents($d.'/config.json',json_encode($cfg,JSON_THROW_ON_ERROR));
        $loaded=Config::load($d.'/config.json','uptime');
        same('status',$loaded['content_policies']['site-a.example.com']['json_health']['field']);
        foreach ([['field'=>'status'],['field'=>'status','equals'=>''],['field'=>'access.token','equals'=>'ok']] as $bad) {
            $cfg['content_policies']['site-a.example.com']=['json_health'=>$bad];
            file_put_contents($d.'/config.json',json_encode($cfg,JSON_THROW_ON_ERROR));
            raises(static fn()=>Config::load($d.'/config.json','uptime'),InvalidArgumentException::class);
        }
    } finally {deleteTree($d);}
});

test('CMM17 unknown server-error headings cannot silently close incidents', static function (): void {
    foreach (['<h1>HTTP 500: A temporary server failure</h1>',
        '<h1>Server Error: something went wrong</h1>',
        '<h1>Database failure: check status logs</h1>',
        '<p>HTTP status 502 - upstream unreachable</p>',
        '<h1>Critical error: retry service</h1>'] as $html) {
        $r=Classifier::classify('site-a.example.com',['status_code'=>200,'body'=>$html]);
        check($r['healthy'] !== true);
    }
    same('healthy',Classifier::classify('site-a.example.com',
        ['status_code'=>200,'body'=>'<h1>Guide to HTTP 500 errors</h1><p>READY</p>'])['code']);
});

test('CMM17 independent re-audit: unknown or null endpoint policy fields are rejected', static function (): void {
    foreach ([['json_health'=>null],['json_healht'=>['field'=>'status','equals'=>'ok']],
       ['contains'=>'READY','unexpected'=>false]] as $policy) {
        raises(static fn()=>Classifier::classify('site-a.example.com',['status_code'=>200,'body'=>'READY'],$policy),InvalidArgumentException::class);
    }
});

test('CMM17 independent re-audit: unknown persistent state envelope fields fail closed', static function (): void {
    $d=tmp();
    try {
        $f=$d.'/s.json';$store=new StateStore($f);
        $store->transaction(static fn(array $s):array=>['state'=>$s,'result'=>null]);
        $s=json_decode((string)file_get_contents($f),true,512,JSON_THROW_ON_ERROR);
        $s['unrecognized_event_queue']=[];
        file_put_contents($f,json_encode($s,JSON_THROW_ON_ERROR));$before=file_get_contents($f);
        raises(static fn()=> $store->transaction(static fn(array $s):array=>['state'=>$s,'result'=>null]),RuntimeException::class);
        same($before,file_get_contents($f));
    } finally {deleteTree($d);}
});

test('CMM17 independent re-audit: unexpected Python release files fail closed', static function (): void {
    same(1,cmm17Scan('py','print("ordinary script")'));
});
