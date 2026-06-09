const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '../ui');

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

const server = http.createServer((req, res) => {
  // Normalize URL path
  let safeUrl = req.url;
  if (safeUrl === '/' || safeUrl.startsWith('/settings')) {
    safeUrl = '/index.html';
  }

  const filePath = path.join(PUBLIC_DIR, safeUrl);
  
  // Ensure path is within PUBLIC_DIR to prevent path traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
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

server.listen(PORT, () => {
  console.log(`MNEME web UI server listening on http://localhost:${PORT}`);
});
