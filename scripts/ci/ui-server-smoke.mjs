import assert from 'node:assert/strict';
import http from 'node:http';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createUiServer } = require('../../scripts/serve-ui.js');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
  });
}

function request(port, path, options = {}) {
  return new Promise((resolve, reject) => {
    let timeout = null;
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: options.method || 'GET',
        headers: options.headers || {},
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          if (timeout) {
            clearTimeout(timeout);
          }
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      },
    );
    if (options.timeoutMs) {
      timeout = setTimeout(() => {
        req.destroy(new Error(`request timed out after ${options.timeoutMs}ms`));
      }, options.timeoutMs);
    }
    req.on('error', (err) => {
      if (timeout) {
        clearTimeout(timeout);
      }
      reject(err);
    });
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

const closedProbe = http.createServer();
const closedApiPort = await listen(closedProbe);
await close(closedProbe);

const upstreamRequests = [];
const upstream = http.createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    const received = {
      method: req.method,
      url: req.url,
      host: req.headers.host,
      capability: req.headers['x-mneme-capability'],
      contentType: req.headers['content-type'],
      body: body,
    };
    upstreamRequests.push(received);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(received));
  });
});
const upstreamPort = await listen(upstream);

const server = createUiServer({ apiPort: upstreamPort });
const port = await listen(server);

try {
  const root = await request(port, '/');
  assert.equal(root.status, 200);
  assert.match(root.headers['content-type'], /text\/html/);
  assert.match(root.body, /<link rel="stylesheet" href="\/index\.css">/);
  assert.match(root.body, /<script src="\/index\.js"><\/script>/);

  const settings = await request(port, '/settings');
  assert.equal(settings.status, 200);
  assert.match(settings.body, /id="view-settings"/);

  const css = await request(port, '/index.css');
  assert.equal(css.status, 200);
  assert.match(css.headers['content-type'], /text\/css/);
  assert.match(css.body, /--bg-primary/);

  const js = await request(port, '/index.js');
  assert.equal(js.status, 200);
  assert.match(js.headers['content-type'], /text\/javascript/);
  assert.match(js.body, /async function probeDaemon/);

  const traversal = await request(port, '/%2e%2e%2fCLAUDE.md');
  assert.equal(traversal.status, 403);

  const malformed = await request(port, '/%E0%A4%A');
  assert.equal(malformed.status, 400);

  const proxied = await request(port, '/api/v1/health?probe=1&min_tier=trusted');
  assert.equal(proxied.status, 200);
  assert.equal(upstreamRequests[0].method, 'GET');
  assert.equal(upstreamRequests[0].url, '/v1/health?probe=1&min_tier=trusted');

  const posted = await request(port, '/api/v1/auth/verify?trace=1', {
    method: 'POST',
    headers: {
      host: 'browser.example.test',
      'content-type': 'application/json',
      'x-mneme-capability': 'smoke-cap',
    },
    body: JSON.stringify({ capability_b64: 'abc123' }),
  });
  assert.equal(posted.status, 200);
  assert.equal(upstreamRequests[1].method, 'POST');
  assert.equal(upstreamRequests[1].url, '/v1/auth/verify?trace=1');
  assert.equal(upstreamRequests[1].host, `127.0.0.1:${upstreamPort}`);
  assert.equal(upstreamRequests[1].capability, 'smoke-cap');
  assert.equal(upstreamRequests[1].contentType, 'application/json');
  assert.equal(upstreamRequests[1].body, '{"capability_b64":"abc123"}');
  assert.equal(JSON.parse(posted.body).method, 'POST');
  assert.equal(JSON.parse(posted.body).capability, 'smoke-cap');
  assert.equal(JSON.parse(posted.body).body, '{"capability_b64":"abc123"}');

  await close(upstream);

  const gateway = await request(port, '/api/v1/health');
  assert.equal(gateway.status, 502);
  assert.match(gateway.headers['content-type'], /application\/json/);
  assert.equal(JSON.parse(gateway.body).code, 'BAD_GATEWAY');

  const stalledUpstream = http.createServer((_req, _res) => {});
  const stalledUpstreamPort = await listen(stalledUpstream);
  const stalledServer = createUiServer({ apiPort: stalledUpstreamPort, apiTimeoutMs: 50 });
  const stalledPort = await listen(stalledServer);
  try {
    const stalled = await request(stalledPort, '/api/v1/health', { timeoutMs: 1000 });
    assert.equal(stalled.status, 504);
    assert.match(stalled.headers['content-type'], /application\/json/);
    assert.equal(JSON.parse(stalled.body).code, 'GATEWAY_TIMEOUT');
  } finally {
    await close(stalledServer);
    await close(stalledUpstream);
  }
} finally {
  if (upstream.listening) {
    await close(upstream);
  }
  await close(server);
}
