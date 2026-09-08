import { createServer } from 'node:http';
import { readFile, realpath } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

export async function startLocalServer({ root = fileURLToPath(new URL('../dist/client/', import.meta.url)), port = 3017 } = {}) {
  const base = await realpath(root);
  await readFile(resolve(base, 'index.html'));
  const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.json': 'application/json', '.rsc': 'text/x-component', '.txt': 'text/plain; charset=utf-8' };
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // Only serve the built public files to this exact loopback origin.
    const expectedHost = `127.0.0.1:${server.address().port}`;
    if (req.headers.host !== expectedHost || (req.headers.origin && req.headers.origin !== `http://${expectedHost}`)) { res.writeHead(403).end(); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { Allow: 'GET, HEAD' }).end(); return; }
    try {
      const path = decodeURIComponent(new URL(req.url, `http://${expectedHost}`).pathname);
      if (path.includes('\0') || path.split('/').some(p => p.startsWith('.'))) { res.writeHead(404).end(); return; }
      const target = await realpath(resolve(base, `.${path === '/' ? '/index.html' : path}`));
      if (!target.startsWith(base + sep)) { res.writeHead(404).end(); return; }
      const body = await readFile(target);
      res.writeHead(200, { 'Content-Type': mime[extname(target)] ?? 'application/octet-stream', 'Content-Length': body.length });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return server;
}

export async function startLocalApp({ root, port } = {}, start = startLocalServer) {
  if (port !== undefined) return start({ root, port });
  // Only the default launch may choose another port. Never reuse an unknown server.
  for (let candidate = 3017; candidate <= 3026; candidate++) {
    try { return await start({ root, port: candidate }); }
    catch (error) { if (error.code !== 'EADDRINUSE' || candidate === 3026) throw error; }
  }
}

export async function runLocalCli(args = process.argv.slice(2)) {
  const value = args[0];
  if (Number(process.versions.node.split('.')[0]) < 24) { process.stderr.write('Node.js 24 or later is required. Install it from https://nodejs.org/en/download, then reopen your terminal.\n'); process.exitCode = 1; }
  else if (args.length > 1 || (value !== undefined && (!/^\d+$/.test(value) || Number(value) < 1024 || Number(value) > 65535))) { process.stderr.write('Usage: node START.mjs [port]\nPort must be between 1024 and 65535.\n'); process.exitCode = 1; }
  else {
    try {
      const server = await startLocalApp({ port: value === undefined ? undefined : Number(value) });
      process.stdout.write(`BULK Keygen: http://127.0.0.1:${server.address().port}\nOpen this exact URL in the browser with Backpack installed.\nLocal files only. Account reads and registration still require BULK internet access.\nKeep this terminal open. Press Ctrl+C to stop.\nNext time: type node and a space, then drag START.mjs into your terminal.\n`);
      for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close());
    } catch (e) {
      process.stderr.write(e?.code === 'EADDRINUSE' ? 'The requested port or default range is busy. Type node and a space, drag START.mjs into the terminal, then add a space and a free port such as 3030 before pressing Enter.\n' : e?.code === 'EACCES' || e?.code === 'EPERM' ? 'Local server access was blocked. Check your system policy; do not disable security protections or run as administrator.\n' : 'Local app files could not be opened. Extract a fresh local ZIP, then type node and a space and drag its START.mjs file into your terminal.\n'); process.exitCode = 1;
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await runLocalCli();
