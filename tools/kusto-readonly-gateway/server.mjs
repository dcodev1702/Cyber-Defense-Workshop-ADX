import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const defaultAllowedOrigins = ['https://dataexplorer.azure.com'];
const defaultAllowedRequestHeaders = 'authorization, content-type, x-ms-activity-id, x-ms-client-request-id';
const hopByHopHeaders = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

export function splitTopLevelStatements(csl) {
  const statements = [];
  let statementStart = 0;
  let inBlockComment = false;
  let inDoubleQuote = false;
  let inLineComment = false;
  let inSingleQuote = false;

  for (let index = 0; index < csl.length; index += 1) {
    const character = csl[index];
    const nextCharacter = csl[index + 1];

    if (inLineComment) {
      if (character === '\n' || character === '\r') {
        inLineComment = false;
      }
      continue;
    }

    if (inBlockComment) {
      if (character === '*' && nextCharacter === '/') {
        inBlockComment = false;
        index += 1;
      }
      continue;
    }

    if (inSingleQuote) {
      if (character === "'" && nextCharacter === "'") {
        index += 1;
      }
      else if (character === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      if (character === '"' && nextCharacter === '"') {
        index += 1;
      }
      else if (character === '"') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (character === '/' && nextCharacter === '/') {
      inLineComment = true;
      index += 1;
      continue;
    }

    if (character === '/' && nextCharacter === '*') {
      inBlockComment = true;
      index += 1;
      continue;
    }

    if (character === "'") {
      inSingleQuote = true;
      continue;
    }

    if (character === '"') {
      inDoubleQuote = true;
      continue;
    }

    if (character === ';') {
      statements.push(csl.slice(statementStart, index));
      statementStart = index + 1;
    }
  }

  statements.push(csl.slice(statementStart));
  return statements;
}

export function trimLeadingComments(statement) {
  let remainder = statement;

  while (remainder.length > 0) {
    remainder = remainder.trimStart();
    if (remainder.startsWith('//')) {
      const lineBreakIndex = remainder.search(/[\r\n]/);
      remainder = lineBreakIndex === -1 ? '' : remainder.slice(lineBreakIndex + 1);
      continue;
    }

    if (remainder.startsWith('/*')) {
      const commentEndIndex = remainder.indexOf('*/', 2);
      remainder = commentEndIndex === -1 ? '' : remainder.slice(commentEndIndex + 2);
      continue;
    }

    return remainder;
  }

  return remainder;
}

function firstManagementVerb(statement) {
  const match = /^\.([A-Za-z]+)/.exec(trimLeadingComments(statement));
  return match ? match[1].toLowerCase() : null;
}

// ".show" is read-only with respect to data, but not with respect to secrets:
// .show queries echoes other students' query text, .show journal is the full
// command history, and on the managed ADX path .show cluster principals
// discloses real tenant identities. So the management endpoint permits only the
// metadata reads the ADX web UI and the workshop exercises actually need,
// instead of every command whose first verb happens to be "show".
//
// .show cluster is deliberately absent, decided 2026-07-26. It is not part of
// the web UI's add-connection handshake, so students connect and work normally;
// clicking into cluster-level detail returns 403. That is the intended
// behaviour and a regression test asserts it -- the pre-hardening gateway
// allowed it, so its absence is a decision, not an oversight.
const managementShowAllowlist = [
  /^\.show\s+version\b/i,
  /^\.show\s+schema\b/i,
  /^\.show\s+databases\b(?![^|]*\bprincipals\b)/i,
  /^\.show\s+database\b(?![^|]*\b(?:principals|policy|permissions)\b)[^|]*\bschema\b/i,
  /^\.show\s+tables\b/i,
  /^\.show\s+table\s+\S+\s+(?:schema|cslschema)\b/i,
  /^\.show\s+functions\b/i,
  /^\.show\s+function\s+\S+/i
];

// The ADX web UI cannot name a database in its opening calls, because those
// calls are how it discovers which databases exist. Requiring a database on
// every request therefore made https://dataexplorer.azure.com fail to add the
// connection at all, with an opaque "Request failed with status code 403",
// while every database-scoped call worked normally. These commands are
// cluster-scoped, already on the .show allowlist, and disclose no row data, so
// a request that names no database is legitimate for these and only these.
const clusterScopedShowAllowlist = [
  /^\.show\s+version\b/i,
  /^\.show\s+databases\b(?![^|]*\bprincipals\b)/i,
  /^\.show\s+schema\b/i
];

export function isClusterScopedRequest(csl) {
  if (typeof csl !== 'string') {
    return false;
  }

  const statements = splitTopLevelStatements(csl)
    .map(trimLeadingComments)
    .filter((statement) => statement.length > 0);

  return statements.length === 1
    && clusterScopedShowAllowlist.some((pattern) => pattern.test(statements[0]));
}

// KQL query-language primitives that never start with a dot but still reach
// outside the database: externaldata performs arbitrary outbound HTTP from the
// lab host, the request plugins open attacker-supplied connections, python/r
// execute code where the sandbox is enabled, and cluster() pivots laterally
// using the host's own identity. The scan is deliberately applied to the raw
// csl text rather than the lexed statements, so a match inside a string literal
// is also rejected: that direction fails closed, which is the correct failure
// mode for a policy boundary.
const deniedCslPatterns = [
  {
    pattern: /\bexternal_?data\b/i,
    reason: 'externaldata is not permitted through the read-only gateway: it performs outbound requests from the lab host.'
  },
  {
    pattern: /\bevaluate\s+(?:hint\s*\.\s*\S+\s+)*(?:python|r|http_request|http_request_post|sql_request|mysql_request|cosmosdb_sql_request|azure_digital_twins_query_request|ai_embeddings|ai_chat_completion[s]?)\b/i,
    reason: 'This evaluate plugin is not permitted through the read-only gateway: it executes code or reaches outside the cluster.'
  },
  {
    pattern: /\bcluster\s*\(/i,
    reason: 'cluster() is not permitted through the read-only gateway: cross-cluster queries would pivot using the host identity.'
  }
];

export function validateKql(csl, endpoint) {
  if (typeof csl !== 'string' || csl.trim().length === 0) {
    return { allowed: false, reason: 'The KQL request must include a non-empty csl string.' };
  }

  for (const { pattern, reason } of deniedCslPatterns) {
    if (pattern.test(csl)) {
      return { allowed: false, reason };
    }
  }

  const statements = splitTopLevelStatements(csl)
    .map(trimLeadingComments)
    .filter((statement) => statement.length > 0);

  if (statements.length === 0) {
    return { allowed: false, reason: 'The KQL request does not contain a statement.' };
  }

  if (endpoint === 'mgmt') {
    if (statements.length !== 1 || firstManagementVerb(statements[0]) !== 'show') {
      return {
        allowed: false,
        reason: 'The read-only gateway permits only one .show command on the management endpoint.'
      };
    }

    if (!managementShowAllowlist.some((pattern) => pattern.test(statements[0]))) {
      return {
        allowed: false,
        reason: 'This .show command is not on the gateway allowlist of metadata reads (.show version, databases, database schema, tables, table schema, functions).'
      };
    }

    return { allowed: true };
  }

  for (const statement of statements) {
    if (firstManagementVerb(statement) !== null) {
      return {
        allowed: false,
        reason: 'Management commands are not permitted on the read-only query endpoint.'
      };
    }
  }

  return { allowed: true };
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Kusto timespan literals: [d.]hh:mm:ss with an optional fraction.
export function timespanToSeconds(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const match = /^(?:(\d+)\.)?(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\.\d+)?$/.exec(value.trim());
  if (!match) {
    return null;
  }

  return (Number(match[1] ?? 0) * 86400) + (Number(match[2]) * 3600) + (Number(match[3]) * 60) + Number(match[4]);
}

function secondsToTimespan(totalSeconds) {
  const seconds = Math.max(1, Math.floor(totalSeconds));
  const pad = (part) => String(part).padStart(2, '0');
  return `${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
}

// Client-supplied request options the gateway is willing to forward. Everything
// else is dropped: properties are forwarded to Kustainer untouched otherwise,
// which would let a student set notruncation or an unbounded servertimeout.
const forwardableOptionKeys = ['queryconsistency', 'deferpartialqueryfailures', 'results_progressive_enabled'];

// The forwarded body is rebuilt from the fields the gateway validated, instead
// of forwarding the client's raw bytes. The gateway's view of csl comes from
// V8's JSON.parse while Kustainer's comes from .NET, and any parser
// disagreement (duplicate keys, key casing, escaped key names) between the two
// would otherwise be a full policy bypass: the gateway validates one string and
// Kustainer executes another.
export function buildForwardPayload(payload, { forceReadOnly = true, maxServerTimeoutSeconds = 240 } = {}) {
  const forward = { csl: payload.csl };
  if (typeof payload.db === 'string') {
    forward.db = payload.db;
  }

  const clientProperties = isPlainObject(payload.properties) ? payload.properties : {};
  const clientOptions = isPlainObject(clientProperties.Options) ? clientProperties.Options : {};

  const options = {};
  for (const key of forwardableOptionKeys) {
    if (key in clientOptions) {
      options[key] = clientOptions[key];
    }
  }

  const requestedSeconds = timespanToSeconds(clientOptions.servertimeout);
  const clampedSeconds = Math.min(requestedSeconds ?? maxServerTimeoutSeconds, maxServerTimeoutSeconds);
  options.servertimeout = secondsToTimespan(clampedSeconds);
  options.query_language = 'kql';
  if (forceReadOnly) {
    options.request_readonly = true;
  }

  forward.properties = { Options: options };
  if (isPlainObject(clientProperties.Parameters)) {
    forward.properties.Parameters = clientProperties.Parameters;
  }

  return forward;
}

// A token bucket per source address plus a global in-flight cap. Behind the
// TCP-mode tunnel every student arrives from the connector's address, so the
// per-source bucket mostly matters for local use; the in-flight cap is what
// actually protects the shared 4-CPU Kustainer from one runaway query fanning
// out into a classroom outage.
export function createRateLimiter({ burst, perMinute }) {
  const buckets = new Map();

  return {
    take(key, now = Date.now()) {
      if (buckets.size > 1000) {
        for (const [existingKey, bucket] of buckets) {
          if (now - bucket.updated > 600_000) {
            buckets.delete(existingKey);
          }
        }
      }

      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { tokens: burst, updated: now };
        buckets.set(key, bucket);
      }

      bucket.tokens = Math.min(burst, bucket.tokens + ((now - bucket.updated) * (perMinute / 60_000)));
      bucket.updated = now;

      if (bucket.tokens < 1) {
        return false;
      }

      bucket.tokens -= 1;
      return true;
    }
  };
}

function parseAllowedOrigins(value) {
  const configuredOrigins = (value ?? defaultAllowedOrigins.join(','))
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  return new Set(configuredOrigins);
}

function parseAllowedDatabases(value) {
  const names = (value ?? '')
    .split(',')
    .map((name) => name.trim().toLowerCase())
    .filter((name) => name.length > 0);

  return names.length > 0 ? new Set(names) : null;
}

function setCorsHeaders(request, response, allowedOrigins) {
  const origin = request.headers.origin;
  if (!origin || !allowedOrigins.has(origin)) {
    return;
  }

  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Access-Control-Allow-Credentials', 'true');
  response.setHeader('Access-Control-Expose-Headers', 'x-ms-activity-id, x-ms-client-request-id');
  response.setHeader('Vary', 'Origin');
}

function writeJson(response, statusCode, payload) {
  if (response.headersSent) {
    response.destroy();
    return;
  }

  response.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// One structured line per decision, so a class incident ("who dropped the
// tunnel", "who is hammering the emulator") can be answered from
// `docker compose logs kusto-readonly-gateway` instead of guesswork. In a
// cyber-defense workshop this is also a teaching artifact: it is the telemetry
// produced by the thing the students are querying through.
function logDecision(details) {
  console.log(JSON.stringify({ time: new Date().toISOString(), ...details }));
}

function getCorsPreflightHeaders(request) {
  const requestedHeaders = request.headers['access-control-request-headers'];
  const headers = {
    'access-control-allow-headers': typeof requestedHeaders === 'string' && requestedHeaders.trim().length > 0
      ? requestedHeaders
      : defaultAllowedRequestHeaders,
    'access-control-allow-methods': 'POST, OPTIONS'
  };

  if (request.headers['access-control-request-private-network'] === 'true') {
    headers['access-control-allow-private-network'] = 'true';
  }

  return headers;
}

function readRequestBody(request, maximumBodyBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > maximumBodyBytes) {
        // Pause rather than destroy: destroying the socket here races the 413
        // response and the client sees a connection reset instead of the
        // explanatory status. The handler closes the connection after replying.
        request.pause();
        reject(new Error(`Request body exceeds the ${maximumBodyBytes}-byte limit.`));
        return;
      }

      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function sanitizeForwardHeaders(headers, contentLength, upstream) {
  const forwardedHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || hopByHopHeaders.has(name.toLowerCase())) {
      continue;
    }

    forwardedHeaders[name] = value;
  }

  forwardedHeaders.host = upstream.host;
  forwardedHeaders['content-length'] = String(contentLength);
  return forwardedHeaders;
}

function copyUpstreamHeaders(upstreamHeaders, response) {
  for (const [name, value] of Object.entries(upstreamHeaders)) {
    if (value === undefined || hopByHopHeaders.has(name.toLowerCase()) || name.toLowerCase().startsWith('access-control-')) {
      continue;
    }

    response.setHeader(name, value);
  }
}

function getEndpoint(pathname) {
  if (pathname === '/healthz') {
    return 'health';
  }

  if (/^\/v[12]\/rest\/query$/i.test(pathname)) {
    return 'query';
  }

  if (/^\/v1\/rest\/mgmt$/i.test(pathname)) {
    return 'mgmt';
  }

  if (/^\/v[12]\/rest\/ping$/i.test(pathname)) {
    return 'ping';
  }

  // The ADX web UI fetches this before it will talk to a cluster at all; it is
  // how the browser learns that the local emulator wants no AAD sign-in.
  // Kustainer answers 200 with a body that carries no data, so forward it
  // rather than returning 404 and leaving the UI to guess at an auth mode.
  if (/^\/v1\/rest\/auth\/metadata$/i.test(pathname)) {
    return 'auth-metadata';
  }

  return null;
}

function forwardRequest(request, response, body, upstream, allowedOrigins) {
  const upstreamRequest = http.request({
    protocol: upstream.protocol,
    hostname: upstream.hostname,
    port: upstream.port || 80,
    method: request.method,
    path: request.url,
    headers: sanitizeForwardHeaders(request.headers, body.length, upstream)
  }, (upstreamResponse) => {
    copyUpstreamHeaders(upstreamResponse.headers, response);
    setCorsHeaders(request, response, allowedOrigins);
    response.writeHead(upstreamResponse.statusCode ?? 502);
    upstreamResponse.pipe(response);
  });

  upstreamRequest.on('error', (error) => {
    setCorsHeaders(request, response, allowedOrigins);
    writeJson(response, 502, { error: 'Kusto upstream is unavailable.', detail: error.message });
  });

  upstreamRequest.end(body);
}

export function createGatewayServer({
  allowedOrigins = parseAllowedOrigins(process.env.KUSTO_ALLOWED_ORIGINS),
  maximumBodyBytes = Number(process.env.KUSTO_MAX_BODY_BYTES ?? 1_048_576),
  upstream = new URL(process.env.KUSTO_UPSTREAM_URL ?? 'http://kusto:8080'),
  allowedDatabases = parseAllowedDatabases(process.env.KUSTO_ALLOWED_DATABASES),
  forceReadOnly = process.env.KUSTO_FORCE_READONLY !== 'false',
  maxServerTimeoutSeconds = Number(process.env.KUSTO_MAX_SERVER_TIMEOUT_SECONDS ?? 240),
  rateBurst = Number(process.env.KUSTO_RATE_BURST ?? 60),
  ratePerMinute = Number(process.env.KUSTO_RATE_PER_MINUTE ?? 300),
  maxInFlight = Number(process.env.KUSTO_MAX_IN_FLIGHT ?? 8)
} = {}) {
  const rateLimiter = createRateLimiter({ burst: rateBurst, perMinute: ratePerMinute });
  let inFlight = 0;

  async function handleRequest(request, response) {
    const requestUrl = new URL(request.url, 'http://gateway.local');
    const endpoint = getEndpoint(requestUrl.pathname);
    const source = request.socket.remoteAddress ?? 'unknown';
    setCorsHeaders(request, response, allowedOrigins);

    if (request.method === 'OPTIONS') {
      const origin = request.headers.origin;
      if (!origin || !allowedOrigins.has(origin)) {
        writeJson(response, 403, { error: 'This browser origin is not permitted.' });
        return;
      }

      response.writeHead(204, getCorsPreflightHeaders(request));
      response.end();
      return;
    }

    if (endpoint === 'health') {
      writeJson(response, 200, { status: 'healthy' });
      return;
    }

    if (endpoint === 'ping') {
      if (!['GET', 'POST'].includes(request.method)) {
        writeJson(response, 405, { error: 'Only GET and POST are permitted for ping.' });
        return;
      }

      forwardRequest(request, response, Buffer.alloc(0), upstream, allowedOrigins);
      return;
    }

    if (endpoint === 'auth-metadata') {
      if (request.method !== 'GET') {
        writeJson(response, 405, { error: 'Only GET is permitted for auth metadata.' });
        return;
      }

      forwardRequest(request, response, Buffer.alloc(0), upstream, allowedOrigins);
      return;
    }

    if (!endpoint) {
      logDecision({ source, method: request.method, path: requestUrl.pathname, outcome: 'unknown-route', status: 404 });
      writeJson(response, 404, { error: 'The read-only gateway does not expose this Kusto route.' });
      return;
    }

    if (request.method !== 'POST') {
      writeJson(response, 405, { error: 'Only POST is permitted for Kusto query and management routes.' });
      return;
    }

    if (!rateLimiter.take(source)) {
      logDecision({ source, endpoint, outcome: 'rate-limited', status: 429 });
      response.setHeader('Retry-After', '10');
      writeJson(response, 429, { error: 'Too many requests. Wait a few seconds and try again.' });
      return;
    }

    if (inFlight >= maxInFlight) {
      logDecision({ source, endpoint, outcome: 'at-capacity', status: 429 });
      response.setHeader('Retry-After', '5');
      writeJson(response, 429, { error: 'The gateway is at its concurrent-query limit. Wait a few seconds and try again.' });
      return;
    }

    let body;
    try {
      body = await readRequestBody(request, maximumBodyBytes);
    }
    catch (error) {
      response.setHeader('Connection', 'close');
      writeJson(response, 413, { error: error.message });
      response.once('finish', () => request.destroy());
      return;
    }

    let payload;
    try {
      payload = JSON.parse(body.toString('utf8'));
    }
    catch {
      writeJson(response, 400, { error: 'Kusto requests must contain a JSON body.' });
      return;
    }

    // JSON.parse succeeds on the literals null, true, and 42; only an object
    // has the fields the policy below inspects. This is the request shape that
    // crashed the gateway process before the handler was hardened.
    if (!isPlainObject(payload)) {
      writeJson(response, 400, { error: 'Kusto requests must contain a JSON object body.' });
      return;
    }

    // A named database must be on the allowlist. A request naming none is
    // permitted only for the cluster-scoped discovery commands above, and only
    // on the management endpoint: a database-less *query* would run against the
    // engine's default database, which is exactly what the allowlist exists to
    // prevent.
    if (allowedDatabases) {
      const requestedDatabase = typeof payload.db === 'string' ? payload.db.trim() : '';
      const databaseAllowed = requestedDatabase.length > 0
        ? allowedDatabases.has(requestedDatabase.toLowerCase())
        : (endpoint === 'mgmt' && isClusterScopedRequest(payload.csl));

      if (!databaseAllowed) {
        logDecision({ source, endpoint, outcome: 'blocked-database', db: payload.db ?? null, status: 403 });
        writeJson(response, 403, { error: 'This database is not exposed through the read-only gateway.' });
        return;
      }
    }

    const validation = validateKql(payload.csl, endpoint);
    if (!validation.allowed) {
      logDecision({ source, endpoint, outcome: 'blocked-kql', reason: validation.reason, status: 403 });
      writeJson(response, 403, { error: validation.reason });
      return;
    }

    const forwardBody = Buffer.from(JSON.stringify(buildForwardPayload(payload, { forceReadOnly, maxServerTimeoutSeconds })), 'utf8');

    inFlight += 1;
    response.once('close', () => {
      inFlight -= 1;
    });

    logDecision({ source, endpoint, outcome: 'forwarded', db: typeof payload.db === 'string' ? payload.db : null });
    forwardRequest(request, response, forwardBody, upstream, allowedOrigins);
  }

  return http.createServer((request, response) => {
    // The evaluation of 2026-07-26 confirmed that a request body of the four
    // bytes `null` terminated the whole gateway process through an unhandled
    // promise rejection, because Node ends the process on unhandled rejections
    // by default and the async handler had no catch. One malformed request from
    // one student must never end the class, so every failure path lands here.
    handleRequest(request, response).catch((error) => {
      logDecision({ outcome: 'handler-error', error: error?.message ?? String(error), status: 500 });
      writeJson(response, 500, { error: 'The gateway failed to process this request.' });
    });
  });
}

function startGateway() {
  // Second layer of the same defence: even if a code path rejects or throws
  // outside the per-request catch, the process logs and keeps serving rather
  // than taking the classroom down with it.
  process.on('unhandledRejection', (reason) => {
    logDecision({ outcome: 'unhandled-rejection', error: reason instanceof Error ? reason.message : String(reason) });
  });
  process.on('uncaughtException', (error) => {
    logDecision({ outcome: 'uncaught-exception', error: error?.message ?? String(error) });
  });

  const port = Number(process.env.PORT ?? 8081);
  const server = createGatewayServer();
  server.listen(port, '0.0.0.0', () => {
    console.log(`Kusto read-only gateway listening on port ${port}.`);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startGateway();
}
