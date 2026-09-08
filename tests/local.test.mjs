import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, chmod, stat, rm, symlink, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { request } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import bs58 from 'bs58';
import { runCli } from '../scripts/keygen.mjs';
import { decryptVault, MAX_SUBMISSION_HISTORY } from '../lib/vault.ts';
import { startLocalServer, startLocalApp } from '../scripts/serve-local.mjs';

test('root starter launches by absolute path from an unrelated directory and keeps argument/port protections', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'BULK starter spaces юникод '));
  let child, held;
  try {
    await mkdir(join(dir, 'scripts')); await mkdir(join(dir, 'dist/client'), { recursive: true });
    await copyFile(new URL('../START.mjs', import.meta.url), join(dir, 'START.mjs'));
    await copyFile(new URL('../scripts/serve-local.mjs', import.meta.url), join(dir, 'scripts/serve-local.mjs'));
    await writeFile(join(dir, 'dist/client/index.html'), 'exact local starter fixture');
    const entry = join(dir, 'START.mjs');
    const invalid = spawnSync(process.execPath, [entry, 'invalid'], { cwd: tmpdir(), encoding: 'utf8' });
    assert.equal(invalid.status, 1); assert.match(invalid.stderr, /Port must/); assert.equal(invalid.stdout, '');
    const extra = spawnSync(process.execPath, [entry, '3030', '--open'], { cwd: tmpdir(), encoding: 'utf8' });
    assert.equal(extra.status, 1); assert.match(extra.stderr, /Usage:/);
    held = await startLocalServer({ root: join(dir, 'dist/client'), port: 0 });
    const occupied = spawnSync(process.execPath, [entry, String(held.address().port)], { cwd: tmpdir(), encoding: 'utf8' });
    assert.equal(occupied.status, 1); assert.match(occupied.stderr, /busy/); assert.equal(occupied.stdout, '');
    child = spawn(process.execPath, [entry], { cwd: tmpdir(), stdio: ['ignore', 'pipe', 'pipe'] });
    const url = await new Promise((resolve, reject) => {
      let output = '', errors = '';
      const timeout = setTimeout(() => reject(Error('Local starter timeout')), 10000);
      child.stderr.on('data', chunk => { errors += chunk; });
      child.once('error', error => { clearTimeout(timeout); reject(error); });
      child.once('exit', code => { clearTimeout(timeout); reject(Error(`Local starter exited ${code}: ${errors}`)); });
      child.stdout.on('data', chunk => {
        output += chunk;
        const match = output.match(/BULK Keygen: (http:\/\/127\.0\.0\.1:\d+)/);
        if (match) { clearTimeout(timeout); resolve(match[1]); }
      });
    });
    const response = await fetch(url);
    assert.equal(await response.text(), 'exact local starter fixture');
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    const hostile = await fetch(url, { headers: { Origin: 'https://untrusted.example' } });
    assert.equal(hostile.status, 403);
  } finally {
    if (child && child.exitCode === null) { const stopped = once(child, 'exit'); child.kill('SIGTERM'); await stopped; }
    if (held) await new Promise(resolve => held.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});

test('default launch tries a bounded port range; explicit ports and policy failures never fall back', async () => {
  const busy = Object.assign(new Error('occupied'), { code: 'EADDRINUSE' });
  const seen = [];
  const result = await startLocalApp({}, async ({ port }) => { seen.push(port); if (port < 3019) throw busy; return 'server'; });
  assert.equal(result, 'server'); assert.deepEqual(seen, [3017, 3018, 3019]);
  seen.length = 0;
  await assert.rejects(startLocalApp({ port: 3050 }, async ({ port }) => { seen.push(port); throw busy; }), { code: 'EADDRINUSE' });
  assert.deepEqual(seen, [3050]);
  seen.length = 0;
  await assert.rejects(startLocalApp({}, async ({ port }) => { seen.push(port); throw busy; }), { code: 'EADDRINUSE' });
  assert.deepEqual(seen, Array.from({ length: 10 }, (_, i) => 3017 + i));
  seen.length = 0;
  await assert.rejects(startLocalApp({}, async ({ port }) => { seen.push(port); throw Object.assign(new Error('policy'), { code: 'EPERM' }); }), { code: 'EPERM' });
  assert.deepEqual(seen, [3017]);
});

function ownerPair(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32);
  return { publicKey: bs58.encode(publicKey), bytes: [...seed, ...publicKey] };
}
test('local CLI generates and signs offline, persists exact retry, and never leaks keys to output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-cli-test-'));
  const owner = ownerPair(1), out = join(dir, 'agent.json'), ownerFile = join(dir, 'owner.json');
  const logs = [], network = [];
  let present = false, failOrder = true;
  const deps = {
    output: text => logs.push(text),
    fetcher: async (url, options) => {
      const body = JSON.parse(options.body); network.push({ url, body });
      if (url.endsWith('/account')) return new Response(JSON.stringify([{ fullAccount: { kind: 'MasterEOA', authorizedAgentWallets: present ? [JSON.parse(await readFile(out)).key.agent_public_key] : [] } }]));
      if (failOrder) throw new DOMException('timeout', 'TimeoutError');
      present = !body.actions[0].agentWalletCreation.d;
      return new Response(JSON.stringify({ status: 'ok', response: { type: 'order', data: { statuses: [{ agentWallet: { agent_wallet: body.actions[0].agentWalletCreation.a } }] } } }));
    },
  };
  try {
    await writeFile(ownerFile, JSON.stringify(owner.bytes), { mode: 0o600 });
    await runCli(['generate', '--owner', owner.publicKey, '--out', out], deps);
    assert.equal((await stat(out)).mode & 0o777, 0o600);
    assert.equal(network.length, 0);
    await assert.rejects(() => runCli(['generate', '--owner', owner.publicKey, '--out', out], deps), { code: 'EEXIST' });
    await runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps);
    assert.equal(network.length, 0);
    const signed = JSON.parse(await readFile(out));
    assert.equal(signed.submission.operation, 'register');
    await assert.rejects(() => runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps), /request already exists/);
    await assert.rejects(() => runCli(['submit', '--file', out, '--confirm-network', 'mainnet'], deps), /does not match/);
    assert.equal(network.length, 0);
    await runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps);
    assert.equal(network.filter(c => c.url.endsWith('/order')).length, 1);
    assert.equal(JSON.parse(logs.at(-1)).status, 'pending');
    failOrder = false;
    await runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps);
    const orders = network.filter(c => c.url.endsWith('/order'));
    assert.deepEqual(orders[0].body, orders[1].body);
    assert.equal(JSON.parse(logs.at(-1)).status, 'active');
    await runCli(['sign-revoke', '--file', out, '--owner-keypair', ownerFile], deps);
    const revokedBackup = JSON.parse(await readFile(out));
    assert.equal(revokedBackup.submission.operation, 'revoke');
    assert.deepEqual(revokedBackup.history, [signed.submission]);
    await runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps);
    assert.equal(JSON.parse(logs.at(-1)).status, 'revoked');
    assert.equal(JSON.parse(logs.at(-1)).account, owner.publicKey);
    assert.equal(JSON.parse(logs.at(-1)).directMembership, false);
    assert.equal(JSON.parse(logs.at(-1)).effectiveAccess, false);
    await assert.rejects(() => runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps), /request already exists/);
    for (const secret of [signed.key.agent_private_key_base58, JSON.stringify(owner.bytes), bs58.encode(Uint8Array.from(owner.bytes)), signed.submission.request.signature]) assert.equal(logs.join('\n').includes(secret), false);
    assert.equal(JSON.stringify(network).includes(signed.key.agent_private_key_base58), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('local CLI rejects wrong owners, permissive files, forged signatures and concurrent operations', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-cli-deny-'));
  const owner = ownerPair(2), other = ownerPair(3), out = join(dir, 'agent.json'), ownerFile = join(dir, 'owner.json');
  const deps = { output() {}, fetcher() { throw Error('No network request is allowed'); } };
  try {
    await runCli(['generate', '--owner', owner.publicKey, '--network', 'mainnet', '--out', out], deps);
    await writeFile(ownerFile, JSON.stringify(other.bytes), { mode: 0o600 });
    await assert.rejects(() => runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps), /does not match/);
    await chmod(out, 0o644);
    await assert.rejects(() => runCli(['status', '--file', out], deps), /chmod 600/);
    await chmod(out, 0o600);
    await writeFile(out + '.lock', '', { mode: 0o600 });
    await assert.rejects(() => runCli(['status', '--file', out], deps), /locked/);
    await rm(out + '.lock');
    await writeFile(ownerFile, JSON.stringify(owner.bytes), { mode: 0o600 });
    await runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps);
    const forged = JSON.parse(await readFile(out));
    forged.submission.request.signature = bs58.encode(new Uint8Array(64));
    await writeFile(out, JSON.stringify(forged));
    await assert.rejects(() => runCli(['submit', '--file', out, '--confirm-network', 'mainnet'], deps), /signature does not match/);
    const link = join(dir, 'linked.json'); await symlink(out, link);
    await assert.rejects(() => runCli(['status', '--file', link], deps));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('local static server serves only public files on its own loopback origin', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-server-test-'));
  const outside = await mkdtemp(join(tmpdir(), 'bulk-outside-test-'));
  let server;
  try {
    await writeFile(join(dir, 'index.html'), '<!doctype html><title>Local test</title>');
    await writeFile(join(dir, '.env'), 'never serve');
    await writeFile(join(outside, 'secret.txt'), 'never serve');
    await symlink(join(outside, 'secret.txt'), join(dir, 'link.txt'));
    server = await startLocalServer({ root: dir, port: 0 });
    const url = `http://127.0.0.1:${server.address().port}`;
    assert.equal(server.address().address, '127.0.0.1');
    const page = await fetch(url);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('x-frame-options'), 'DENY');
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(url, { method: 'POST' })).status, 405);
    const hostileHostStatus = await new Promise((resolve, reject) => {
      const req = request(url, { headers: { Host: 'evil.example' } }, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(hostileHostStatus, 403);
    assert.equal((await fetch(url, { headers: { Origin: 'https://evil.example' } })).status, 403);
    for (const path of ['/.env', '/link.txt', '/%2e%2e%2fsecret.txt']) assert.equal((await fetch(url + path)).status, 404);
  } finally { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } await rm(dir, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});


test('local CLI reports inherited child access after direct removal and preserves unknown parent evidence', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-cli-child-scope-'));
  const owner = ownerPair(5), child = ownerPair(6), other = ownerPair(7);
  const out = join(dir, 'agent.json'), ownerFile = join(dir, 'owner.json');
  const logs = [], requests = [], orders = [];
  let childPresent = false, childOwner = owner.publicKey, parentMode = 'present', agent;
  const deps = {
    output: text => logs.push(JSON.parse(text)),
    fetcher: async (url, options) => {
      const body = JSON.parse(options.body); requests.push(body);
      if (url.endsWith('/order')) {
        orders.push(body); childPresent = false;
        return new Response(JSON.stringify({ status: 'ok', response: { type: 'order', data: { statuses: [{ agentWallet: { agent_wallet: agent } }] } } }));
      }
      assert.ok(url.endsWith('/account'));
      if (body.user === child.publicKey) return new Response(JSON.stringify([{ fullAccount: { kind: 'SubAccount', parent: childOwner, authorizedAgentWallets: childPresent ? [agent] : [] } }]));
      assert.equal(body.user, owner.publicKey);
      if (parentMode === 'unreachable') throw new TypeError('Synthetic offline parent');
      const parent = parentMode === 'wrong-owner' ? { kind: 'SubAccount', parent: other.publicKey, authorizedAgentWallets: [] }
        : { kind: 'MasterEOA', ...(parentMode === 'missing-list' ? {} : { authorizedAgentWallets: parentMode === 'present' ? [agent] : [] }) };
      return new Response(JSON.stringify([{ fullAccount: parent }]));
    },
  };
  try {
    await writeFile(ownerFile, JSON.stringify(owner.bytes), { mode: 0o600 });
    await runCli(['generate', '--owner', owner.publicKey, '--account', child.publicKey, '--out', out], deps);
    agent = JSON.parse(await readFile(out)).key.agent_public_key;
    await runCli(['sign-revoke', '--file', out, '--owner-keypair', ownerFile], deps);
    await runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps);
    const removed = logs.at(-1);
    assert.equal(removed.status, 'direct_revoked');
    assert.equal(removed.directStatus, 'revoked');
    assert.equal(removed.account, child.publicKey);
    assert.equal(removed.owner, owner.publicKey);
    assert.equal(removed.directMembership, false);
    assert.equal(removed.inheritedMembership, true);
    assert.equal(removed.effectiveAccess, true);
    assert.equal(removed.sent, false); assert.equal(orders.length, 0);

    childPresent = true;
    await runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps);
    assert.equal(orders.length, 1);
    assert.equal(orders[0].account, child.publicKey);
    assert.equal(orders[0].signer, owner.publicKey);
    assert.equal(orders[0].actions[0].agentWalletCreation.d, true);
    assert.equal(logs.at(-1).status, 'direct_revoked');
    assert.equal(logs.at(-1).inheritedMembership, true);
    assert.equal(logs.at(-1).effectiveAccess, true);
    assert.equal(logs.at(-1).sent, true);

    for (parentMode of ['missing-list', 'unreachable', 'wrong-owner']) {
      await runCli(['status', '--file', out], deps);
      const uncertain = logs.at(-1);
      assert.equal(uncertain.status, 'direct_revoked');
      assert.equal(uncertain.directMembership, false);
      assert.equal(uncertain.inheritedMembership, null, parentMode);
      assert.equal(uncertain.effectiveAccess, null, parentMode);
    }
    parentMode = 'absent';
    await runCli(['status', '--file', out], deps);
    assert.equal(logs.at(-1).inheritedMembership, false);
    assert.equal(logs.at(-1).effectiveAccess, false);

    childPresent = true; parentMode = 'missing-list';
    await runCli(['status', '--file', out], deps);
    assert.equal(logs.at(-1).directMembership, true);
    assert.equal(logs.at(-1).effectiveAccess, true);

    childOwner = other.publicKey;
    const previousRequests = requests.length, previousLogs = logs.length;
    await assert.rejects(runCli(['submit', '--file', out, '--confirm-network', 'testnet'], deps), /does not own/);
    assert.equal(requests.length, previousRequests + 1);
    assert.equal(logs.length, previousLogs); assert.equal(orders.length, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('local CLI retains and verifies every historical request and refuses history overflow before owner signing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bulk-cli-history-'));
  const owner = ownerPair(8), out = join(dir, 'agent.json'), ownerFile = join(dir, 'owner.json');
  const logs = [], requests = [];
  const deps = {
    output: text => logs.push(text),
    fetcher: async (url, options) => {
      requests.push({ url, body: JSON.parse(options.body) });
      assert.ok(url.endsWith('/account'));
      return new Response(JSON.stringify([{ fullAccount: { kind: 'MasterEOA', authorizedAgentWallets: [] } }]));
    },
  };
  try {
    await writeFile(ownerFile, JSON.stringify(owner.bytes), { mode: 0o600 });
    await runCli(['generate', '--owner', owner.publicKey, '--out', out], deps);
    await runCli(['sign-register', '--file', out, '--owner-keypair', ownerFile], deps);
    const first = JSON.parse(await readFile(out)).submission;
    const saved = [first];
    for (let index = 0; index < MAX_SUBMISSION_HISTORY; index++) {
      await runCli(['sign-revoke', '--file', out, '--owner-keypair', ownerFile], deps);
      const next = JSON.parse(await readFile(out));
      assert.equal(next.history.length, index + 1);
      assert.deepEqual(next.history, saved);
      saved.push(next.submission);
    }
    assert.equal(requests.length, 0);
    const fullText = await readFile(out, 'utf8');
    const restored = await decryptVault(fullText, '', true);
    assert.deepEqual(restored.history, saved.slice(0, -1));
    assert.deepEqual(restored.submission, saved.at(-1));
    // A missing owner file proves the capacity check happens before owner-key access.
    await assert.rejects(runCli(['sign-revoke', '--file', out, '--owner-keypair', join(dir, 'missing-owner.json')], deps), /history|History/);
    assert.equal(await readFile(out, 'utf8'), fullText);
    assert.equal(requests.length, 0);
    await runCli(['status', '--file', out], deps);
    assert.equal(JSON.parse(logs.at(-1)).effectiveAccess, false);
    assert.equal(requests.length, 1);

    const forged = JSON.parse(fullText);
    forged.history[0].request.signature = bs58.encode(new Uint8Array(64));
    await writeFile(out, JSON.stringify(forged));
    const beforeLogs = logs.length;
    await assert.rejects(runCli(['status', '--file', out], deps), /signature does not match/);
    assert.equal(requests.length, 1); assert.equal(logs.length, beforeLogs);
    for (const entry of saved) assert.equal(logs.join('\n').includes(entry.request.signature), false);
    assert.equal(logs.join('\n').includes(restored.key.secretKey), false);
    assert.equal(JSON.stringify(requests).includes(restored.key.secretKey), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
