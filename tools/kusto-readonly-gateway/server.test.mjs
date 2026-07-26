import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { buildForwardPayload, createGatewayServer, createRateLimiter, splitTopLevelStatements, timespanToSeconds, validateKql } from './server.mjs';

async function withServer(options, run) {
  const server = createGatewayServer(options);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  }
  finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

async function withUpstreamStub(run) {
  const received = [];
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      received.push({ url: request.url, body: Buffer.concat(chunks).toString('utf8') });
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"Tables":[]}');
    });
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');

  try {
    await run(new URL(`http://127.0.0.1:${upstream.address().port}`), received);
  }
  finally {
    await new Promise((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
  }
}

// ---- lexer parity (H1c) -------------------------------------------------------

test('a backslash-escaped quote cannot hide a second statement', () => {
  // The reported bypass. Kusto reads the literal as a single `"` and then a
  // second statement; a lexer blind to the backslash saw the quote close and
  // re-open, swallowing the `;` and the `.drop` into one `print` statement.
  const attack = 'print x = "\\""; .drop table SecurityIncident';

  assert.equal(splitTopLevelStatements(attack).length, 2, 'the drop must be seen as its own statement');
  assert.equal(validateKql(attack, 'query').allowed, false);
  assert.equal(validateKql(attack, 'mgmt').allowed, false);
});

test('the same trick with single quotes is also split', () => {
  const attack = "print x = '\\''; .drop table SecurityIncident";
  assert.equal(validateKql(attack, 'query').allowed, false);
});

test('verbatim literals treat a backslash as data, not an escape', () => {
  // @"C:\path\" is a complete literal: the trailing backslash escapes nothing,
  // so treating it as an escape would swallow the closing quote and drag the
  // next statement inside the string.
  const csl = 'print path = @"C:\\temp\\"; .drop table SecurityIncident';
  assert.equal(splitTopLevelStatements(csl).length, 2);
  assert.equal(validateKql(csl, 'query').allowed, false);
});

test('a doubled quote inside a verbatim literal stays inside it', () => {
  const csl = 'print quoted = @"he said ""hello"" loudly"';
  assert.equal(splitTopLevelStatements(csl).length, 1);
  assert.equal(validateKql(csl, 'query').allowed, true);
});

test('the h@\'...\' obfuscated literal form is understood', () => {
  const csl = "print secret = h@'not; a statement'";
  assert.equal(splitTopLevelStatements(csl).length, 1);
  assert.equal(validateKql(csl, 'query').allowed, true);
});

test('an unterminated literal is refused rather than guessed at', () => {
  // If the lexer cannot tell where the statement ends, neither can the policy.
  for (const csl of ['print x = "abc', "print x = 'abc", 'print x = @"abc', 'print 1 /* unclosed']) {
    const result = validateKql(csl, 'query');
    assert.equal(result.allowed, false, `${csl} must be refused`);
    assert.match(result.reason, /unterminated/i);
  }
});

test('escapes do not break ordinary multi-statement splitting', () => {
  assert.equal(splitTopLevelStatements('print a = "x\\ty"; print b = 2').length, 2);
  assert.equal(splitTopLevelStatements("print message = 'one; two'; print message = 'three'").length, 2);
});

test('allows read-only query statements and KQL let bindings', () => {
  const result = validateKql("let incidents = SecurityIncident | take 10; incidents | count", 'query');
  assert.equal(result.allowed, true);
});

test('does not split semicolons inside KQL string literals', () => {
  const statements = splitTopLevelStatements("print message = 'one; two'; print message = 'three'");
  assert.equal(statements.length, 2);
  assert.equal(validateKql("print message = 'one; two'; print message = 'three'", 'query').allowed, true);
});

for (const command of ['.drop table SecurityIncident', '.add database Sample', '.alter table SecurityIncident policy retention', '.create table Scratch (Value:string)', '.delete table SecurityIncident records', '.ingest into table SecurityIncident <| print Value = "x"', '.set-or-append SecurityIncident <| print Value = "x"']) {
  test(`blocks ${command.split(' ')[0]} on the query endpoint`, () => {
    const result = validateKql(command, 'query');
    assert.equal(result.allowed, false);
  });
}

test('allows a single show command on the management endpoint', () => {
  const result = validateKql('.show tables | count', 'mgmt');
  assert.equal(result.allowed, true);
});

test('blocks create and multi-statement management commands', () => {
  assert.equal(validateKql('.create table Scratch (Value:string)', 'mgmt').allowed, false);
  assert.equal(validateKql('.show tables; .drop table SecurityIncident', 'mgmt').allowed, false);
});

test('blocks management commands hidden after a line comment', () => {
  const result = validateKql('// harmless looking comment\n.drop table SecurityIncident', 'query');
  assert.equal(result.allowed, false);
});

// ---- .show subcommand allowlist ---------------------------------------------
// .show is read-only for data but not for secrets: queries, journal, and
// principals disclose other students' activity and real tenant identities.

for (const command of ['.show version', '.show databases', '.show databases schema', '.show tables', '.show table SecurityIncident schema', '.show table SecurityIncident cslschema', '.show functions', '.show schema']) {
  test(`allows metadata read ${command}`, () => {
    assert.equal(validateKql(command, 'mgmt').allowed, true);
  });
}

for (const command of ['.show queries', '.show commands-and-queries', '.show journal', '.show cluster principals', '.show database CyberDefendStudentSnapshot principals', '.show ingestion failures', '.show external tables', '.show cluster identity', '.show table SecurityIncident extents']) {
  test(`blocks disclosure command ${command}`, () => {
    assert.equal(validateKql(command, 'mgmt').allowed, false);
  });
}

// ---- query-language egress and code-execution primitives ---------------------

for (const csl of ['externaldata (x:string) ["http://169.254.169.254/latest"]', 'print 1 | evaluate python(typeof(x:int), "code")', 'evaluate http_request("http://example.com")', 'T | evaluate sql_request("Server=x", "select 1")', "cluster('other.kusto.windows.net').database('x').T | take 1"]) {
  test(`blocks egress primitive in ${csl.slice(0, 24)}...`, () => {
    assert.equal(validateKql(csl, 'query').allowed, false);
  });
}

test('still allows harmless evaluate plugins such as bag_unpack', () => {
  assert.equal(validateKql('SecurityIncident | evaluate bag_unpack(AdditionalData)', 'query').allowed, true);
});

test('rejects a statement hidden inside a string from reaching Kusto', () => {
  // This test previously asserted the opposite -- that the lexer saw one
  // statement and allowed the payload -- because it documented a known gap: the
  // lexer modelled ''/"" doubling but not backslash escapes, so a crafted
  // literal could hide a second statement, and only the raw-text deny scan
  // caught the subset of payloads containing a denied primitive. The lexer now
  // handles escapes and verbatim literals, so the smuggled statement is seen
  // and refused on its own merits.
  assert.equal(validateKql('print x = "\\""; .drop table T', 'query').allowed, false, 'the hidden .drop must be seen');
  assert.equal(validateKql('print x = "\\""; cluster(\'x\').database(\'y\')', 'query').allowed, false, 'deny scan still fails closed');
});

// ---- canonical forwarded body (validate-one-thing, forward-the-same-thing) ---

test('rebuilds the forwarded body from validated fields only', () => {
  const payload = JSON.parse('{"csl":".show tables","Csl":".drop table SecurityIncident","db":"CyberDefendStudentSnapshot","extra":"x"}');
  const forward = buildForwardPayload(payload);

  assert.equal(forward.csl, '.show tables');
  assert.equal('Csl' in forward, false);
  assert.equal('extra' in forward, false);
  assert.equal(forward.db, 'CyberDefendStudentSnapshot');
});

test('forces read-only options and drops notruncation', () => {
  const forward = buildForwardPayload({
    csl: 'print 1',
    db: 'db',
    properties: { Options: { notruncation: true, servertimeout: '08:00:00', queryconsistency: 'strongconsistency' }, Parameters: { p: 'v' } }
  }, { forceReadOnly: true, maxServerTimeoutSeconds: 240 });

  assert.equal('notruncation' in forward.properties.Options, false);
  assert.equal(forward.properties.Options.servertimeout, '00:04:00');
  assert.equal(forward.properties.Options.request_readonly, true);
  assert.equal(forward.properties.Options.query_language, 'kql');
  assert.equal(forward.properties.Options.queryconsistency, 'strongconsistency');
  assert.deepEqual(forward.properties.Parameters, { p: 'v' });
});

test('honours the read-only escape hatch', () => {
  const forward = buildForwardPayload({ csl: 'print 1' }, { forceReadOnly: false });
  assert.equal('request_readonly' in forward.properties.Options, false);
});

test('parses Kusto timespan literals', () => {
  assert.equal(timespanToSeconds('00:04:00'), 240);
  assert.equal(timespanToSeconds('1.00:00:00'), 86400);
  assert.equal(timespanToSeconds('bogus'), null);
  assert.equal(timespanToSeconds(undefined), null);
});

// ---- crash resistance ---------------------------------------------------------
// A request body of the literal four bytes `null` parses successfully and then
// crashed the whole process before the handler was hardened. The gateway must
// answer 400 and keep serving.

test('survives a null JSON body and keeps serving', async () => {
  await withServer({}, async (base) => {
    const first = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: 'null' });
    assert.equal(first.status, 400);

    const second = await fetch(`${base}/healthz`);
    assert.equal(second.status, 200);
  });
});

test('rejects non-object JSON bodies and malformed JSON', async () => {
  await withServer({}, async (base) => {
    for (const body of ['null', 'true', '42', '"csl"', '[1,2]']) {
      const response = await fetch(`${base}/v1/rest/query`, { method: 'POST', body });
      assert.equal(response.status, 400, `body ${body}`);
    }

    const malformed = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: '{not json' });
    assert.equal(malformed.status, 400);
  });
});

// ---- HTTP error paths ---------------------------------------------------------

test('returns 404 for unknown routes and 405 for wrong methods', async () => {
  await withServer({}, async (base) => {
    assert.equal((await fetch(`${base}/v1/rest/ingest`, { method: 'POST', body: '{}' })).status, 404);
    assert.equal((await fetch(`${base}/v1/rest/query`, { method: 'GET' })).status, 405);
    assert.equal((await fetch(`${base}/v1/rest/query`, { method: 'DELETE' })).status, 405);
  });
});

test('returns 413 when the body exceeds the configured limit', async () => {
  await withServer({ maximumBodyBytes: 64 }, async (base) => {
    const response = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'x'.repeat(256) }) });
    assert.equal(response.status, 413);
  });
});

test('returns 403 for a blocked command over HTTP', async () => {
  await withServer({}, async (base) => {
    const response = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: '.drop table SecurityIncident', db: 'db' }) });
    assert.equal(response.status, 403);
  });
});

// ---- database allowlist -------------------------------------------------------

test('rejects databases outside KUSTO_ALLOWED_DATABASES', async () => {
  await withUpstreamStub(async (upstream, received) => {
    await withServer({ upstream, allowedDatabases: new Set(['cyberdefendstudentsnapshot']) }, async (base) => {
      const blocked = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'print 1', db: 'KustoMonitoringPersistentDatabase' }) });
      assert.equal(blocked.status, 403);

      const missing = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'print 1' }) });
      assert.equal(missing.status, 403);

      const allowed = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'print 1', db: 'CyberDefendStudentSnapshot' }) });
      assert.equal(allowed.status, 200);
      assert.equal(received.length, 1);
    });
  });
});

test('keeps .show cluster blocked', () => {
  // Decided 2026-07-26: stays blocked. The pre-hardening gateway allowed every
  // .show, so this is a deliberate behaviour change rather than an oversight,
  // and it is asserted here so it is not quietly reverted. It is not part of the
  // web UI's add-connection handshake -- students connect and work normally --
  // and .show cluster principals is the disclosure the allowlist exists to stop.
  for (const command of ['.show cluster', '.show cluster principals', '.show cluster policy caching']) {
    assert.equal(validateKql(command, 'mgmt').allowed, false, `${command} must stay blocked`);
  }
});

test('completes the ADX web UI add-connection handshake', async () => {
  // Regression: the web UI's opening calls carry no db, because discovering the
  // databases is what they are for. Requiring one made dataexplorer.azure.com
  // fail to add the connection at all with an opaque 403, even though every
  // database-scoped call worked. Observed against the real UI on 2026-07-26.
  await withUpstreamStub(async (upstream, received) => {
    await withServer({ upstream, allowedDatabases: new Set(['cyberdefendstudentsnapshot']) }, async (base) => {
      for (const csl of ['.show version', '.show databases', '.show databases schema', '.show schema']) {
        const response = await fetch(`${base}/v1/rest/mgmt`, { method: 'POST', body: JSON.stringify({ csl }) });
        assert.equal(response.status, 200, `${csl} without a db should reach the cluster`);
      }

      assert.equal(received.length, 4);
    });
  });
});

test('a database-less request is not a way around the allowlist', async () => {
  await withUpstreamStub(async (upstream, received) => {
    await withServer({ upstream, allowedDatabases: new Set(['cyberdefendstudentsnapshot']) }, async (base) => {
      // Row data never travels without a named, allowed database.
      const query = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'SecurityIncident | take 1' }) });
      assert.equal(query.status, 403);

      // Nor does a management command that is not cluster-scoped discovery.
      const scoped = await fetch(`${base}/v1/rest/mgmt`, { method: 'POST', body: JSON.stringify({ csl: '.show tables' }) });
      assert.equal(scoped.status, 403);

      // And whitespace is not a loophole for a data query.
      const blank = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'print 1', db: '   ' }) });
      assert.equal(blank.status, 403);

      assert.equal(received.length, 0);
    });
  });
});

test('forwards the auth metadata probe the ADX web UI sends first', async () => {
  await withUpstreamStub(async (upstream, received) => {
    await withServer({ upstream }, async (base) => {
      const response = await fetch(`${base}/v1/rest/auth/metadata`);
      assert.equal(response.status, 200);
      assert.equal(received[0].url, '/v1/rest/auth/metadata');

      const posted = await fetch(`${base}/v1/rest/auth/metadata`, { method: 'POST' });
      assert.equal(posted.status, 405);
    });
  });
});

test('forwards the canonical body, not the raw client bytes', async () => {
  await withUpstreamStub(async (upstream, received) => {
    await withServer({ upstream }, async (base) => {
      const raw = '{"csl":"print 1","Csl":".drop table SecurityIncident","db":"db","properties":{"Options":{"notruncation":true}}}';
      const response = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: raw });
      assert.equal(response.status, 200);

      const forwarded = JSON.parse(received[0].body);
      assert.equal(forwarded.csl, 'print 1');
      assert.equal('Csl' in forwarded, false);
      assert.equal('notruncation' in forwarded.properties.Options, false);
      assert.equal(forwarded.properties.Options.request_readonly, true);
    });
  });
});

// ---- rate limiting and concurrency -------------------------------------------

test('token bucket refuses once the burst is spent', () => {
  const limiter = createRateLimiter({ burst: 2, perMinute: 60 });
  const start = 1_000_000;
  assert.equal(limiter.take('a', start), true);
  assert.equal(limiter.take('a', start), true);
  assert.equal(limiter.take('a', start), false);
  assert.equal(limiter.take('b', start), true, 'other sources have their own bucket');
  assert.equal(limiter.take('a', start + 61_000), true, 'tokens refill over time');
});

test('answers 429 when the per-source budget is exhausted', async () => {
  await withServer({ rateBurst: 2, ratePerMinute: 1 }, async (base) => {
    const body = JSON.stringify({ csl: '.drop table T', db: 'db' });
    assert.equal((await fetch(`${base}/v1/rest/query`, { method: 'POST', body })).status, 403);
    assert.equal((await fetch(`${base}/v1/rest/query`, { method: 'POST', body })).status, 403);
    const limited = await fetch(`${base}/v1/rest/query`, { method: 'POST', body });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '10');
  });
});

test('answers 429 at the concurrent-query cap', async () => {
  await withServer({ maxInFlight: 0 }, async (base) => {
    const response = await fetch(`${base}/v1/rest/query`, { method: 'POST', body: JSON.stringify({ csl: 'print 1', db: 'db' }) });
    assert.equal(response.status, 429);
  });
});

// ---- CORS ---------------------------------------------------------------------

test('allows ADX browser headers and private-network access to the local proxy', async () => {
  await withServer({}, async (base) => {
    const response = await fetch(`${base}/v1/rest/query`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://dataexplorer.azure.com',
        'Access-Control-Request-Headers': 'authorization,content-type,x-ms-app,x-ms-client-version,x-ms-user-id',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Private-Network': 'true'
      }
    });

    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://dataexplorer.azure.com');
    assert.equal(response.headers.get('access-control-allow-private-network'), 'true');
    assert.equal(response.headers.get('access-control-allow-headers'), 'authorization,content-type,x-ms-app,x-ms-client-version,x-ms-user-id');
  });
});

test('rejects preflight from an origin outside the allowlist', async () => {
  await withServer({}, async (base) => {
    const response = await fetch(`${base}/v1/rest/query`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' }
    });
    assert.equal(response.status, 403);
  });
});
