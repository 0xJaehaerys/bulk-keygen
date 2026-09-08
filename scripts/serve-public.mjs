import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';

const defaultRoot = fileURLToPath(new URL('../dist/client/', import.meta.url));
const mime = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml', '.json': 'application/json', '.rsc': 'text/x-component',
  '.txt': 'text/plain; charset=utf-8', '.sha256': 'text/plain; charset=utf-8',
  '.zip': 'application/zip',
};

// This process only serves the compiled public directory. Wallet operations and
// BULK API requests happen directly in the browser; no request body is accepted.
export async function startPublicServer({ root = defaultRoot, port = 8080, host = '0.0.0.0' } = {}) {
  const base = await realpath(root);
  await readFile(resolve(base, 'index.html'));
  const headers = {};
  for (const line of (await readFile(resolve(base, '_headers'), 'utf8')).split('\n')) {
    const match = line.match(/^  ([A-Za-z-]+): (.+)$/);
    if (match) headers[match[1].toLowerCase()] = match[2];
  }
  if (!headers['content-security-policy']?.includes("frame-ancestors 'none'") ||
      headers['cache-control'] !== 'no-store' || headers['x-frame-options'] !== 'DENY' ||
      headers['x-content-type-options'] !== 'nosniff') {
    throw new Error('Missing hardened build headers. Run npm run build before serving.');
  }
  headers['strict-transport-security'] = 'max-age=31536000';

  const server = createServer(async (req, res) => {
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD', Connection: 'close' }).end();
      return;
    }
    try {
      // Do not use the incoming Host to construct links or resolve files. Railway
      // healthchecks use their own host while public requests use the domain.
      const path = decodeURIComponent((req.url ?? '').split('?')[0]);
      if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') ||
          path.includes('\0') || path.split('/').some(part => part.startsWith('.')) ||
          path === '/_headers') {
        res.writeHead(404).end(); return;
      }
      if (path === '/healthz') {
        const body = '{"status":"ok"}\n';
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
        res.end(req.method === 'HEAD' ? undefined : body); return;
      }
      const target = await realpath(resolve(base, `.${path === '/' ? '/index.html' : path}`));
      if (!target.startsWith(base + sep) || !mime[extname(target)]) { res.writeHead(404).end(); return; }
      const info = await stat(target);
      if (!info.isFile()) { res.writeHead(404).end(); return; }
      res.writeHead(200, { 'Content-Type': mime[extname(target)], 'Content-Length': info.size });
      if (req.method === 'HEAD') res.end();
      else await pipeline(createReadStream(target), res);
    } catch {
      if (!res.headersSent) res.writeHead(404).end();
      else res.destroy();
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const value = process.env.PORT ?? '8080';
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error('PORT must be between 1 and 65535.');
  const server = await startPublicServer({ port: Number(value) });
  process.stdout.write(`BULK Keygen static server listening on port ${server.address().port}\n`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
