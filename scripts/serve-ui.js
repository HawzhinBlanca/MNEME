const http = require('http');
const fs = require('fs');
const path = require('path');

const DEFAULT_PORT = process.env.PORT || 3000;
const DEFAULT_PUBLIC_DIR = path.join(__dirname, '../ui');
const DEFAULT_API_TIMEOUT_MS = 15_000;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function isInsidePublicDir(publicDir, filePath) {
  const relative = path.relative(publicDir, filePath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function createUiServer(options = {}) {
  const publicDir = path.resolve(options.publicDir || DEFAULT_PUBLIC_DIR);
  const apiHost = options.apiHost || '127.0.0.1';
  const apiPort = options.apiPort || 7845;
  const apiTimeoutMs = options.apiTimeoutMs ?? DEFAULT_API_TIMEOUT_MS;

  return http.createServer((req, res) => {
    const requestUrl = new URL(req.url || '/', 'http://127.0.0.1');

    // Proxy API requests to the mnemed daemon
    if (requestUrl.pathname.startsWith('/api/')) {
      const targetPath = `${requestUrl.pathname.substring(4)}${requestUrl.search}`;
      const headers = { ...req.headers };
      delete headers.host; // Let node set the correct host header for the target
      let proxySettled = false;

      const failProxy = (statusCode, code, message) => {
        if (proxySettled) {
          return;
        }
        proxySettled = true;
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ code, message }));
      };

      const proxyReq = http.request({
        host: apiHost,
        port: apiPort,
        path: targetPath,
        method: req.method,
        headers: headers
      }, (proxyRes) => {
        proxySettled = true;
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });

      proxyReq.setTimeout(apiTimeoutMs, () => {
        failProxy(
          504,
          'GATEWAY_TIMEOUT',
          `Timed out waiting for local mnemed daemon on port ${apiPort} after ${apiTimeoutMs}ms`
        );
        proxyReq.destroy();
      });

      proxyReq.on('error', (err) => {
        failProxy(
          502,
          'BAD_GATEWAY',
          `Failed to connect to local mnemed daemon on port ${apiPort}: ${err.message}`
        );
      });

      req.pipe(proxyReq);
      return;
    }

    // Normalize URL path for SPA routing
    let safeUrl = requestUrl.pathname;
    if (safeUrl === '/' || safeUrl.startsWith('/settings')) {
      safeUrl = '/index.html';
    }

    let decodedPath;
    try {
      decodedPath = decodeURIComponent(safeUrl);
    } catch (_err) {
      res.statusCode = 400;
      res.end('Bad Request');
      return;
    }

    const filePath = path.resolve(publicDir, `.${decodedPath}`);

    // Ensure path is within publicDir to prevent path traversal
    if (!isInsidePublicDir(publicDir, filePath)) {
      res.statusCode = 403;
      res.end('Forbidden');
      return;
    }

    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.statusCode = 404;
          res.end('File Not Found');
        } else {
          res.statusCode = 500;
          res.end(`Internal Server Error: ${err.code}`);
        }
        return;
      }

      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    });
  });
}

if (require.main === module) {
  const server = createUiServer();
  server.listen(DEFAULT_PORT, () => {
    console.log(`MNEME web UI server listening on http://localhost:${DEFAULT_PORT}`);
  });
}

module.exports = { createUiServer };
