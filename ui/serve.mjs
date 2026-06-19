#!/usr/bin/env node
// MNEME Desk — same-origin dev host (Phase Y0, untrusted glue; zero npm deps).
//
// Serves the ui/ static console AND reverse-proxies /v1/* to the mnemed daemon,
// so the browser talks to a single origin (no CORS, no daemon change). The
// operator capability is held HERE and injected server-side as
// `Authorization: Bearer <cap>` — the browser/renderer never holds it, so a
// compromised page cannot exfiltrate write/forget authority (it can only drive
// the actions the cap already allows, same as any local tool).
//
// Trust note: this process is UNTRUSTED glue, not part of the verifier TCB. It
// proves nothing; it only carries bytes. The daemon remains the sole authority
// and re-verifies every capability and receipt.
//
// Usage:
//   MNEME_CAP_FILE=cap.txt node ui/serve.mjs            # cap from file
//   MNEME_CAP="<b64>" node ui/serve.mjs                 # cap inline
//   MNEME_UI_PORT=8765 MNEME_DAEMON=http://127.0.0.1:7845 node ui/serve.mjs

import http from 'node:http';
import { readFile, readFileSync } from 'node:fs';
import { resolve, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const UI_DIR = resolve(fileURLToPath(new URL('.', import.meta.url)));
const PORT = Number(process.env.MNEME_UI_PORT || 8765);
const DAEMON = (process.env.MNEME_DAEMON || 'http://127.0.0.1:7845').replace(/\/$/, '');
const DAEMON_URL = new URL(DAEMON);

function loadCap() {
  if (process.env.MNEME_CAP && process.env.MNEME_CAP.trim()) return process.env.MNEME_CAP.trim();
  if (process.env.MNEME_CAP_FILE) {
    try {
      return readFileSync(process.env.MNEME_CAP_FILE, 'utf8').trim();
    } catch (e) {
      console.error(`[mneme-desk] could not read MNEME_CAP_FILE: ${e.message}`);
    }
  }
  return null;
}
const CAP = loadCap();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

// Reverse-proxy /v1/* to the daemon, injecting the operator cap if the caller
// did not already supply one. Fail-closed: the daemon authorizes, not us.
function proxyToDaemon(req, res) {
  const headers = { ...req.headers, host: DAEMON_URL.host };
  if (CAP && !headers.authorization) headers.authorization = `Bearer ${CAP}`;
  const upstream = http.request(
    {
      protocol: DAEMON_URL.protocol,
      hostname: DAEMON_URL.hostname,
      port: DAEMON_URL.port || 80,
      method: req.method,
      path: req.url,
      headers,
    },
    (up) => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on('error', (e) => {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ code: 'daemon_unreachable', message: e.message }));
  });
  req.pipe(upstream);
}

// Serve a static file from ui/ only (path-traversal safe). SPA routes fall back
// to index.html so client-side pushState routing (/settings) works on reload.
function serveStatic(req, res) {
  let rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (rel === '/' ) rel = '/index.html';
  let abs = normalize(resolve(UI_DIR, '.' + rel));
  if (!abs.startsWith(UI_DIR)) {
    res.writeHead(403); res.end('forbidden'); return;
  }
  readFile(abs, (err, buf) => {
    if (err) {
      // SPA fallback for extensionless routes; otherwise 404.
      if (!extname(rel)) return readFile(resolve(UI_DIR, 'index.html'), (e2, idx) => {
        if (e2) { res.writeHead(404); res.end('not found'); return; }
        res.writeHead(200, { 'content-type': MIME['.html'] }); res.end(idx);
      });
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, { 'content-type': MIME[extname(abs)] || 'application/octet-stream' });
    res.end(buf);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/v1' || req.url.startsWith('/v1/')) return proxyToDaemon(req, res);
  return serveStatic(req, res);
});

// Loopback only — never expose the cap-injecting proxy off-host.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[mneme-desk] http://127.0.0.1:${PORT}  ->  daemon ${DAEMON}`);
  console.log(`[mneme-desk] capability: ${CAP ? 'loaded (injected server-side)' : 'NONE (set MNEME_CAP_FILE) — authed routes will 401'}`);
});
