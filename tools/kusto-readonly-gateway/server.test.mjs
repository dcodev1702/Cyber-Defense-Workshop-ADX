import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { createGatewayServer, splitTopLevelStatements, validateKql } from './server.mjs';

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

test('allows ADX browser headers and private-network access to the local proxy', async () => {
  const server = createGatewayServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  try {
    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/rest/query`, {
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
  }
  finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});