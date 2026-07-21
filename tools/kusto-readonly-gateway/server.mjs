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

export function validateKql(csl, endpoint) {
  if (typeof csl !== 'string' || csl.trim().length === 0) {
    return { allowed: false, reason: 'The KQL request must include a non-empty csl string.' };
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

function parseAllowedOrigins(value) {
  const configuredOrigins = (value ?? defaultAllowedOrigins.join(','))
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  return new Set(configuredOrigins);
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
  response.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
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
        reject(new Error(`Request body exceeds the ${maximumBodyBytes}-byte limit.`));
        request.destroy();
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
  upstream = new URL(process.env.KUSTO_UPSTREAM_URL ?? 'http://kusto:8080')
} = {}) {
  return http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, 'http://gateway.local');
    const endpoint = getEndpoint(requestUrl.pathname);
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

    if (!endpoint) {
      writeJson(response, 404, { error: 'The read-only gateway does not expose this Kusto route.' });
      return;
    }

    if (request.method !== 'POST') {
      writeJson(response, 405, { error: 'Only POST is permitted for Kusto query and management routes.' });
      return;
    }

    let body;
    try {
      body = await readRequestBody(request, maximumBodyBytes);
    }
    catch (error) {
      writeJson(response, 413, { error: error.message });
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

    const validation = validateKql(payload.csl, endpoint);
    if (!validation.allowed) {
      writeJson(response, 403, { error: validation.reason });
      return;
    }

    forwardRequest(request, response, body, upstream, allowedOrigins);
  });
}

function startGateway() {
  const port = Number(process.env.PORT ?? 8081);
  const server = createGatewayServer();
  server.listen(port, '0.0.0.0', () => {
    console.log(`Kusto read-only gateway listening on port ${port}.`);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startGateway();
}