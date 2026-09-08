import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { request } from 'node:http';
import { startPublicServer } from '../scripts/serve-public.mjs';

function get(port, path, method = 'GET', headers = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject); req.end();
  });
}

test('public server enforces static boundaries and headers, supports Railway healthchecks and downloads', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-public-test-'));
  const root = join(dir, 'public');
  let server;
  try {
    await mkdir(join(root, 'downloads'), { recursive: true });
    await writeFile(join(root, 'index.html'), '<h1>Keygen fixture</h1>');
    await assert.rejects(startPublicServer({ root, port: 0 }), /ENOENT/);
    await writeFile(join(root, '_headers'), '/*\n  Content-Security-Policy: default-src self\n');
    await assert.rejects(startPublicServer({ root, port: 0 }), /Missing hardened/);
    await writeFile(join(root, '_headers'), "/*\n  Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n  Cache-Control: no-store\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n");
    await writeFile(join(root, 'runtime.wasm'), Buffer.from([0, 97, 115, 109]));
    await writeFile(join(root, 'downloads/app.zip'), Buffer.from([80, 75, 3, 4]));
    await writeFile(join(dir, 'private.json'), 'private fixture');
    await symlink(join(dir, 'private.json'), join(root, 'escape.json'));
    server = await startPublicServer({ root, port: 0, host: '127.0.0.1' });
    const port = server.address().port;
    const page = await get(port, '/', 'GET', { Host: 'public.example' });
    assert.equal(page.status, 200); assert.match(page.body.toString(), /Keygen fixture/);
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    assert.equal(page.headers['strict-transport-security'], 'max-age=31536000');
    const head = await get(port, '/', 'HEAD');
    assert.equal(head.status, 200); assert.equal(head.body.length, 0);
    assert.equal(Number(head.headers['content-length']), page.body.length);
    const health = await get(port, '/healthz', 'GET', { Host: 'healthcheck.railway.app' });
    assert.equal(health.status, 200); assert.deepEqual(JSON.parse(health.body), { status: 'ok' });
    assert.equal((await get(port, '/runtime.wasm')).headers['content-type'], 'application/wasm');
    const zip = await get(port, '/downloads/app.zip');
    assert.equal(zip.headers['content-type'], 'application/zip'); assert.deepEqual([...zip.body], [80, 75, 3, 4]);
    for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
      const result = await get(port, '/', method);
      assert.equal(result.status, 405); assert.equal(result.headers.allow, 'GET, HEAD');
    }
    for (const path of ['/.env', '/.git/config', '/%2e%2e/private.json', '/escape.json', '/_headers', '/%00', '/%zz', '/downloads/', '//private.json', '/missing.js']) {
      assert.equal((await get(port, path)).status, 404, path);
    }
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});
