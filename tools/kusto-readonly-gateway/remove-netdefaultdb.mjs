import { rm } from 'node:fs/promises';
import path from 'node:path';

const upstream = new URL(process.env.KUSTO_UPSTREAM_URL ?? 'http://kusto:8080');
const defaultDatabase = process.env.KUSTO_DEFAULT_DATABASE_NAME ?? 'NetDefaultDB';
const retainedDatabase = process.env.KUSTO_RETAINED_DATABASE_NAME ?? 'CyberDefendStudentSnapshot';
const checkIntervalMilliseconds = Number(process.env.KUSTO_DEFAULT_DATABASE_CHECK_INTERVAL_MS ?? 2_000);
const stateRoot = process.env.KUSTO_STATE_ROOT ?? '/kustodata';

for (const databaseName of [defaultDatabase, retainedDatabase]) {
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(databaseName)) {
    throw new Error('Kusto database names must be alphanumeric identifiers.');
  }
}

async function executeManagementCommand(csl) {
  const response = await fetch(new URL('/v1/rest/mgmt', upstream), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ csl })
  });

  if (!response.ok) {
    throw new Error(`Kusto management request failed with HTTP ${response.status}.`);
  }

  return response.json();
}

async function removeDefaultDatabaseWhenSafe() {
  const response = await executeManagementCommand('.show databases | project DatabaseName');
  const databaseNames = new Set(response.Tables?.[0]?.Rows?.map((row) => row[0]) ?? []);

  if (!databaseNames.has(retainedDatabase)) {
    return;
  }

  if (databaseNames.has(defaultDatabase)) {
    await executeManagementCommand(`.drop database ${defaultDatabase} ifexists`);
    console.log(`Removed ${defaultDatabase} after ${retainedDatabase} became available.`);
  }

  await rm(path.join(stateRoot, 'dbs', defaultDatabase), { force: true, recursive: true });
}

async function check() {
  try {
    await removeDefaultDatabaseWhenSafe();
  }
  catch (error) {
    console.error(`Default database cleanup will retry: ${error.message}`);
  }
}

await check();
setInterval(check, checkIntervalMilliseconds);