// Offline UI harness using the real crypto code and disposable owner signatures.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { registerHooks, createRequire } from 'node:module';
import { generateKeyPairSync, sign } from 'node:crypto';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const bs58 = require('bs58').default;
const asset = new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url).href;
registerHooks({
  resolve(s, c, next) { return s.endsWith('.wasm?url') ? { url: 'test:agent-wasm', shortCircuit: true } : next(s, c); },
  load(u, c, next) { return u === 'test:agent-wasm' ? { format: 'module', source: `import fs from 'node:fs'; export default fs.readFileSync(new URL(${JSON.stringify(asset)}));`, shortCircuit: true } : next(u, c); },
});
const bulk = await import('../lib/bulk.ts');
const cryptoLib = await import('../lib/crypto.ts');
const vault = await import('../lib/vault.ts');
const walletLib = await import('../lib/wallet.ts');
const pair = generateKeyPairSync('ed25519');
const owner = bs58.encode(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
const child = '11111111111111111111111111111112';
const code = ts.transpileModule(fs.readFileSync(new URL('../app/page.tsx', import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText;
function all(n) { return !n || typeof n !== 'object' ? [] : [n, ...(Array.isArray(n) ? n : Object.values(n.props ?? {})).flatMap(all)]; }
function text(n) { return typeof n === 'string' ? n : Array.isArray(n) ? n.map(text).join('') : n && typeof n === 'object' ? text(n.props?.children) : ''; }
function fresh({ walletName = 'Phantom', agents = [], accountState = {}, orderReply = 'unknown' } = {}) {
  const state = [], refs = [], orders = [], signed = [], downloads = [], reads = [];
  let pauseRead = false, releaseRead, pauseSign = false, releaseSign, rejectSign, pauseConnect = false, releaseConnect, disconnect;
  let si = 0, ri = 0;
  const react = { useEffect() {}, useRef(v) { return refs[ri++] ??= { current: v }; }, useState(v) { const i = si++; if (!(i in state)) state[i] = v; return [state[i], next => { state[i] = typeof next === 'function' ? next(state[i]) : next; }]; } };
  const connection = { id: 'test-phantom', name: walletName, publicKey: { toString: () => owner }, subscribe(listener) { disconnect = listener; return () => {}; }, async signMessage(bytes, display) {
    assert.equal(display, walletName === 'Phantom' ? 'utf8' : 'hex'); if (walletName === 'Phantom') new TextDecoder('utf8', { fatal: true }).decode(bytes);
    signed.push(Uint8Array.from(bytes));
    const result = { signature: new Uint8Array(sign(null, bytes, pair.privateKey)), publicKey: this.publicKey };
    if (pauseSign) { pauseSign = false; return new Promise((resolve, reject) => { releaseSign = () => resolve(result); rejectSign = () => reject(new Error('Late wallet rejection')); }); }
    return result;
  } };
  const option = { id: 'test-phantom', name: walletName, async connect() { if (pauseConnect) { pauseConnect = false; return new Promise(resolve => { releaseConnect = () => resolve([connection]); }); } return [connection]; } };
  const providers = { availableWallets: () => [option], watchWallets: () => () => {} };
  const jsx = (type, props) => ({ type, props });
  const modules = { '@/lib/bulk': bulk, '@/lib/crypto': cryptoLib, '@/lib/vault': vault, '@/lib/wallet': walletLib, '@/lib/wallet-providers': providers };
  const exports = {}, window = {}; window.top = window; window.self = window;
  vm.runInNewContext(code, { exports, require: p => p === 'react' ? react : p === 'react/jsx-runtime' ? { jsx, jsxs: jsx } : modules[p] ?? new Proxy({}, { get: (_, name) => String(name) }), window, Uint8Array, Blob, setTimeout(fn) { fn(); }, navigator: { clipboard: { writeText: async () => {} } }, URL: { createObjectURL(blob) { downloads.push(blob); return 'blob:test'; }, revokeObjectURL() {} }, document: { createElement() { return { click() {} }; } } });
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (url.endsWith('/account')) { reads.push({ url, body }); if (pauseRead) { pauseRead = false; await new Promise(resolve => { releaseRead = resolve; }); } return new Response(JSON.stringify([{ fullAccount: body.user === owner ? { kind: 'MasterEOA', subAccounts: [{ pubkey: child }], ...(accountState.omitAgents ? {} : { authorizedAgentWallets: [...agents] }) } : { kind: 'SubAccount', parent: owner, ...(accountState.omitAgents ? {} : { authorizedAgentWallets: [...agents] }) } }])); }
    assert.ok(url.endsWith('/order'));
    assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
    orders.push(options.body);
    if (orderReply === 'accepted') return new Response(JSON.stringify({ status: 'ok', response: { type: 'order', data: { statuses: [{ agentWallet: { agent_wallet: body.actions[0].agentWalletCreation.a } }] } } }));
    throw new TypeError('synthetic timeout');
  };
  const render = () => { si = ri = 0; return exports.default(); };
  const button = label => { const n = all(render()).find(n => n.type === 'button' && (n.props['aria-label'] ?? text(n.props.children).trim()) === label); assert.ok(n, `Missing button ${label}`); return n; };
  const check = label => { const n = all(render()).find(n => n.type === 'label' && text(n).includes(label)); assert.ok(n, label); all(n).find(n => n.type === 'Checkbox').props.onCheckedChange(true); };
  const settle = async () => { for (let i = 0; i < 1000; i++) { render(); if (!refs[2]?.current) return; await new Promise(resolve => setTimeout(resolve, 1)); } assert.fail('UI did not settle'); };
  const click = async label => { const b = button(label); assert.ok(!b.props.disabled, `${label} disabled`); b.props.onClick(); await settle(); };
  return { render, button, check, settle, click, orders, signed, downloads, reads, network() { return all(render()).find(n => n.type === 'NetworkSwitcher').props; }, holdSign() { pauseSign = true; }, releaseSign() { releaseSign(); }, rejectSign() { rejectSign(); }, holdConnect() { pauseConnect = true; }, releaseConnect() { releaseConnect(); }, disconnect() { disconnect(); }, async waitSign() { for (let i = 0; i < 1000 && !releaseSign; i++) await new Promise(resolve => setTimeout(resolve, 1)); assert.ok(releaseSign); }, async waitRead() { for (let i = 0; i < 1000 && !releaseRead; i++) await new Promise(resolve => setTimeout(resolve, 1)); assert.ok(releaseRead); }, holdRead() { pauseRead = true; }, releaseRead() { releaseRead(); }, async connect() { await click('Connect wallet'); await click(walletName); }, async child() { const select = all(render()).find(n => n.type === 'Select' && n.props.value === owner); assert.ok(select); select.props.onValueChange(child); await settle(); } };
}

test('Phantom UI requires main scope, signs text, saves exact request before submit and retries without signing again', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh(); await a.connect(); await a.click('Create agent key');
    a.check('I saved my key');
    assert.equal(a.button('Sign registration').props.disabled, true);
    a.check('I authorize this key'); await a.click('Sign registration');
    assert.equal(a.signed.length, 1); assert.equal(a.orders.length, 0);
    assert.equal(a.button('Submit registration').props.disabled, true);
    await a.click('Save signed request backup');
    assert.equal(a.button('Submit registration').props.disabled, true, 'download dispatch is not saved acknowledgement');
    const backup = await vault.decryptVault(await a.downloads[0].text(), '', true);
    assert.equal(backup.submission.signatureMode, 'base58');
    await cryptoLib.validateSubmission(backup.key, backup.submission);
    a.check('I saved the updated backup'); await a.click('Submit registration');
    assert.equal(a.orders.length, 1); assert.equal(a.orders[0], JSON.stringify(backup.submission.request));
    await a.click('Retry original request');
    assert.equal(a.orders.length, 2); assert.equal(a.orders[1], a.orders[0]); assert.equal(a.signed.length, 1);
  } finally { globalThis.fetch = original; }
});

test('Phantom subaccount is explained and blocked before key generation or signature', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh(); await a.connect(); await a.child();
    assert.equal(a.button('Create agent key').props.disabled, true);
    assert.match(text(a.render()), /Phantom cannot sign a subaccount/);
    assert.equal(a.signed.length, 0); assert.equal(a.orders.length, 0);
  } finally { globalThis.fetch = original; }
});


test('network switching reloads only the chosen network and locks during work, keys, and pending subaccounts', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh();
    assert.equal(a.network().value, 'testnet');
    await a.connect();
    const staleChange = a.network().onChange;
    a.holdRead();
    a.network().onChange('mainnet');
    assert.match(a.network().lockedReason, /current action/);
    staleChange('testnet');
    assert.equal(a.network().value, 'mainnet');
    assert.match(a.reads.at(-1).url, /mainnet-api1/);
    a.releaseRead(); await a.settle();
    assert.equal(a.network().lockedReason, '');
    const creator = all(a.render()).find(n => n.type === 'SubaccountCreator');
    creator.props.onPendingChange(owner);
    const readCount = a.reads.length;
    assert.match(a.network().lockedReason, /pending subaccount/);
    a.network().onChange('testnet');
    assert.equal(a.network().value, 'mainnet'); assert.equal(a.reads.length, readCount);
    creator.props.onPendingChange('');
    a.network().onChange('testnet'); await a.settle();
    assert.match(a.reads.at(-1).url, /exchange-api/);
    await a.click('Create agent key');
    assert.match(a.network().lockedReason, /this key/);
    a.network().onChange('mainnet');
    assert.equal(a.network().value, 'testnet'); assert.equal(a.orders.length, 0); assert.equal(a.signed.length, 0);
  } finally { globalThis.fetch = original; }
});

test('plain import requires explicit JSON choice, shows no password and keeps imported key network locked', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh(); await a.click('Import saved key');
    assert.equal(a.button('Import key').props.disabled, true);
    assert.equal(all(a.render()).some(n => n.type === 'Input' && n.props.type === 'password'), false);
    await a.click('Encrypted backup');
    assert.equal(all(a.render()).some(n => n.type === 'Input' && n.props.type === 'password'), true);
    await a.click('JSON backup');
    assert.equal(all(a.render()).some(n => n.type === 'Input' && n.props.type === 'password'), false);
    const key = await cryptoLib.generateKey('mainnet', child, owner);
    const blob = new Blob([vault.exportBackup(key, null)]);
    const file = all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file');
    file.props.onChange({ target: { files: [blob] } });
    const form = all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file'));
    form.props.onSubmit({ preventDefault() {} }); await a.settle();
    assert.equal(a.network().value, 'mainnet');
    assert.match(a.network().lockedReason, /this key/);
    assert.equal(a.orders.length, 0); assert.equal(a.signed.length, 0); assert.equal(a.reads.length, 0);
    a.network().onChange('testnet'); assert.equal(a.network().value, 'mainnet');
  } finally { globalThis.fetch = original; }
});


test('wrong backup-type selection explains how to recover without importing or requesting a signature', async () => {
  const original = globalThis.fetch;
  try {
    const key = await cryptoLib.generateKey('mainnet', child, owner);
    const encrypted = await vault.encryptVault(key, 'disposable-test-passphrase');
    for (const [kind, contents, expected] of [
      ['JSON backup', encrypted, /Choose Encrypted backup and enter its password/],
      ['Encrypted backup', vault.exportBackup(key), /Choose JSON backup; no password is needed/],
    ]) {
      const a = fresh(); await a.click('Import saved key'); await a.click(kind);
      const file = all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file');
      file.props.onChange({ target: { files: [new Blob([contents])] } });
      const form = all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file'));
      form.props.onSubmit({ preventDefault() {} }); await a.settle();
      assert.match(text(a.render()), expected);
      assert.equal(a.network().value, 'testnet'); assert.equal(a.network().lockedReason, '');
      assert.equal(a.signed.length, 0); assert.equal(a.orders.length, 0); assert.equal(a.reads.length, 0);
    }
  } finally { globalThis.fetch = original; }
});


test('encrypted restore explains owner reconnect and enables scoped revoke only after wallet connection', async () => {
  const original = globalThis.fetch;
  try {
    const agents = [];
    const a = fresh({ walletName: 'Backpack', agents });
    await a.connect(); await a.child(); await a.click('Create agent key');
    a.check('I saved my key'); await a.click('Sign registration'); await a.click('Save signed request backup');
    const backup = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    const encrypted = await vault.encryptVault(backup.key, 'disposable-test-passphrase', backup.submission);
    agents.push(backup.key.publicKey);
    a.check('I saved the updated backup'); await a.click('Submit registration');
    await a.click('Clear key from page'); a.check('I have an up-to-date backup'); await a.click('Clear key');
    await a.click('Import saved key'); await a.click('Encrypted backup');
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'password').props.onChange({ target: { value: 'disposable-test-passphrase' } });
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file').props.onChange({ target: { files: [new Blob([encrypted])] } });
    const readsBefore = a.reads.length, signaturesBefore = a.signed.length, ordersBefore = a.orders.length;
    all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file')).props.onSubmit({ preventDefault() {} });
    await a.settle();
    assert.equal(a.reads.length, readsBefore); assert.equal(a.signed.length, signaturesBefore); assert.equal(a.orders.length, ordersBefore);
    assert.ok(a.button('Connect owner wallet'));
    assert.match(text(a.render()), /Importing a backup does not connect your wallet/);
    assert.equal(a.button('Revoke access').props.disabled, true);
    assert.equal(a.button('Revoke access').props['aria-describedby'], 'revoke-disabled-reason');
    assert.match(text(a.render()), /Connect the owner wallet to revoke access/);
    await a.click('Connect owner wallet'); await a.click('Backpack');
    assert.equal(all(a.render()).some(n => n.type === 'button' && text(n).trim() === 'Connect owner wallet'), false);
    assert.match(text(a.render()), /Check status to confirm whether this key is active/);
    await a.click('Check status');
    assert.equal(a.button('Revoke access').props.disabled, false);
    assert.equal(a.button('Revoke access').props['aria-describedby'], undefined);
    assert.equal(a.signed.length, signaturesBefore); assert.equal(a.orders.length, ordersBefore);
    await a.click('Revoke access'); await a.click('Sign revoke request');
    assert.equal(a.signed.length, signaturesBefore + 1);
    assert.equal(a.button('Submit revoke').props.disabled, true);
    await a.click('Save signed request backup');
    const revoked = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    assert.equal(revoked.submission.operation, 'revoke');
    assert.equal(revoked.key.account, child); assert.equal(revoked.key.owner, owner);
    await cryptoLib.validateSubmission(revoked.key, revoked.submission);
    assert.equal(a.orders.length, ordersBefore, 'revoke needs explicit backup acknowledgement and submit');
  } finally { globalThis.fetch = original; }
});


test('Stop waiting preserves keys and ignores a late signature without unlocking a newer action', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh({ walletName: 'Backpack' }); await a.connect(); await a.child(); await a.click('Create agent key');
    a.check('I saved my key'); a.holdSign(); a.button('Sign registration').props.onClick(); await a.waitSign();
    assert.equal(a.button('Download latest backup').props.disabled, true);
    await a.click('Stop waiting');
    assert.match(text(a.render()), /Signed or submitted requests are not cancelled/);
    assert.equal(a.button('Save key backup').props.disabled, false);
    await a.click('Save key backup');
    const saved = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    assert.equal(saved.submission, null);
    await a.click('Connect owner wallet'); a.holdRead(); a.button('Backpack').props.onClick(); await a.waitRead();
    a.releaseSign(); await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(a.button('Save key backup').props.disabled, true, 'late finally must not clear new operation busy');
    assert.equal(a.orders.length, 0);
    a.releaseRead(); await a.settle();
    assert.equal(a.button('Sign registration').props.disabled, false);
    assert.equal(a.signed.length, 1); assert.equal(a.orders.length, 0);
  } finally { globalThis.fetch = original; }
});

test('wallet disconnect releases a never-settled sign and ignores its late error', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh({ walletName: 'Backpack' }); await a.connect(); await a.child(); await a.click('Create agent key');
    a.check('I saved my key'); a.holdSign(); a.button('Sign registration').props.onClick(); await a.waitSign();
    a.disconnect(); await a.settle();
    assert.equal(a.button('Save key backup').props.disabled, false);
    await a.click('Connect owner wallet'); await a.click('Backpack');
    a.rejectSign(); await new Promise(resolve => setTimeout(resolve, 20));
    assert.doesNotMatch(text(a.render()), /Late wallet rejection/);
    assert.equal(a.button('Sign registration').props.disabled, false);
    assert.equal(a.orders.length, 0);
  } finally { globalThis.fetch = original; }
});

test('late connect cannot reconnect a stopped request or reset another action', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh({ walletName: 'Backpack' }); a.holdConnect(); await a.click('Connect wallet');
    a.button('Backpack').props.onClick();
    await a.click('Stop waiting');
    a.releaseConnect(); await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(a.button('Connect wallet')); assert.equal(a.reads.length, 0); assert.equal(a.orders.length, 0);
    await a.connect(); assert.ok(a.button('Create agent key'));
  } finally { globalThis.fetch = original; }
});

test('latest backup retains the original registration after signing revoke and after encrypted restore', async () => {
  const original = globalThis.fetch;
  try {
    const agents = [], a = fresh({ walletName: 'Backpack', agents }); await a.connect(); await a.child(); await a.click('Create agent key');
    a.check('I saved my key'); await a.click('Sign registration'); await a.click('Save signed request backup');
    const first = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    a.check('I saved the updated backup'); await a.click('Submit registration');
    agents.push(first.key.publicKey);
    await a.click('Revoke access'); await a.click('Sign revoke request'); await a.click('Save signed request backup');
    const latest = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    assert.equal(latest.history.length, 1);
    assert.deepEqual(latest.history[0], first.submission); assert.equal(latest.submission.operation, 'revoke');
    await cryptoLib.validateSubmission(latest.key, latest.history[0]); await cryptoLib.validateSubmission(latest.key, latest.submission);
    const encrypted = await vault.encryptVault(latest.key, 'disposable-test-passphrase', latest.submission, latest.history);
    await a.click('Clear key from page'); a.check('I have an up-to-date backup'); await a.click('Clear key');
    await a.click('Import saved key'); await a.click('Encrypted backup');
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'password').props.onChange({ target: { value: 'disposable-test-passphrase' } });
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file').props.onChange({ target: { files: [new Blob([encrypted])] } });
    all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file')).props.onSubmit({ preventDefault() {} }); await a.settle();
    await a.click('Download latest backup');
    const restored = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
    assert.deepEqual(restored, latest);
    assert.equal(a.signed.length, 2); assert.equal(a.orders.length, 1, 'import and backup must not submit old authorizations');
  } finally { globalThis.fetch = original; }
});

test('key-only restore explains missing signed backup and has an explicit safe restart path', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh({ walletName: 'Backpack' }); await a.connect(); await a.child(); await a.click('Create agent key');
    assert.match(text(a.render()), /After signing, save the updated backup/);
    await a.click('Save key backup'); const backup = await a.downloads.at(-1).text();
    await a.click('Clear key from page'); a.check('I have an up-to-date backup'); await a.click('Clear key');
    await a.click('Import saved key'); await a.click('JSON backup');
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file').props.onChange({ target: { files: [new Blob([backup])] } });
    all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file')).props.onSubmit({ preventDefault() {} }); await a.settle();
    assert.match(text(a.render()), /no signed registration request/);
    await a.click('Connect owner wallet'); await a.click('Backpack'); await a.click('Check status');
    await a.click('Clear key to start again');
    assert.equal(a.button('Clear key').props.disabled, true);
    a.check('I have an up-to-date backup'); await a.click('Clear key');
    assert.equal(a.network().lockedReason, ''); assert.equal(a.orders.length, 0); assert.equal(a.signed.length, 0);
  } finally { globalThis.fetch = original; }
});


test('a forged historical signature rejects the entire UI import before any connection or request', async () => {
  const original = globalThis.fetch;
  try {
    const key = await cryptoLib.generateKey('testnet', child, owner);
    const prepared = await cryptoLib.prepareRegistration(key, 'register');
    let request;
    try { request = await cryptoLib.finalizeRegistration(prepared, new Uint8Array(sign(null, prepared.messageBytes, pair.privateKey)), key); }
    finally { prepared.free(); }
    const current = { operation: 'register', request };
    const history = [{ operation: 'register', request: { ...request, signature: bs58.encode(new Uint8Array(64)) } }];
    const invalid = vault.exportBackup(key, current, history);
    const a = fresh({ walletName: 'Backpack' }); await a.click('Import saved key'); await a.click('JSON backup');
    all(a.render()).find(n => n.type === 'Input' && n.props.type === 'file').props.onChange({ target: { files: [new Blob([invalid])] } });
    all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'file')).props.onSubmit({ preventDefault() {} }); await a.settle();
    assert.match(text(a.render()), /signature does not match/);
    assert.equal(a.network().lockedReason, ''); assert.equal(a.orders.length, 0); assert.equal(a.signed.length, 0); assert.equal(a.reads.length, 0);
  } finally { globalThis.fetch = original; }
});


test('encrypted backup is visible beside JSON and saves signed recovery without sending or acknowledging it', async () => {
  const original = globalThis.fetch;
  try {
    const a = fresh({ walletName: 'Backpack' }); await a.connect(); await a.child(); await a.click('Create agent key');
    const region = all(a.render()).find(n => n.type === 'section' && n.props['aria-label'] === 'Backups');
    assert.ok(region); assert.match(text(region), /Save encrypted backup/); assert.match(text(region), /Unencrypted JSON/);
    const more = all(a.render()).filter(n => n.type === 'CollapsibleContent');
    assert.ok(more.every(n => !text(n).includes('Save encrypted backup')), 'encrypted backup must be outside collapsed options');
    const password = 'disposable-backup-test-password-2026';
    async function saveEncrypted() {
      await a.click('Save encrypted backup');
      const fields = all(a.render()).filter(n => n.type === 'Input' && n.props.type === 'password');
      assert.equal(fields.length, 2);
      for (const field of fields) field.props.onChange({ target: { value: password } });
      all(a.render()).find(n => n.type === 'form' && all(n).some(x => x.type === 'Input' && x.props.type === 'password')).props.onSubmit({ preventDefault() {} });
      await a.settle();
      const data = await a.downloads.at(-1).text();
      assert.equal(JSON.parse(data).format, 'bulk-agent-vault-v1');
      assert.doesNotMatch(data, /agent_private_key_base58|bulk-agent-backup-v2/);
      return vault.decryptVault(data, password);
    }
    const keyBackup = await saveEncrypted();
    assert.equal(keyBackup.submission, null);
    assert.equal(a.button('Sign registration').props.disabled, true, 'download is not saved acknowledgement');
    a.check('I saved my key'); await a.click('Sign registration');
    const readsBefore = a.reads.length;
    const signedBackup = await saveEncrypted();
    assert.deepEqual(signedBackup.key, keyBackup.key);
    await cryptoLib.validateSubmission(signedBackup.key, signedBackup.submission);
    assert.equal(a.button('Submit registration').props.disabled, true);
    assert.equal(a.reads.length, readsBefore); assert.equal(a.orders.length, 0); assert.equal(a.signed.length, 1);
    a.check('I saved the updated backup'); await a.click('Submit registration');
    assert.equal(a.orders.length, 1); assert.equal(a.orders[0], JSON.stringify(signedBackup.submission.request));
  } finally { globalThis.fetch = original; }
});


test('missing agent list after revoke stays unconfirmed and retries the same request without another signature', async () => {
  const original = globalThis.fetch;
  try {
    for (const orderReply of ['unknown', 'accepted']) {
      const agents = [], accountState = {};
      const a = fresh({ walletName: 'Backpack', agents, accountState, orderReply });
      await a.connect(); await a.child(); await a.click('Create agent key');
      a.check('I saved my key'); await a.click('Sign registration'); await a.click('Save signed request backup');
      const registered = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
      agents.push(registered.key.publicKey);
      a.check('I saved the updated backup'); await a.click('Submit registration');
      await a.click('Revoke access'); await a.click('Sign revoke request'); await a.click('Save signed request backup');
      const revoked = await vault.decryptVault(await a.downloads.at(-1).text(), '', true);
      accountState.omitAgents = true;
      a.check('I saved the updated backup'); await a.click('Submit revoke');
      assert.match(text(a.render()), /Revoke unconfirmed/);
      assert.match(text(a.render()), /BULK did not return the agent list/);
      const actions = all(a.render()).find(n => n.props?.className === 'active-actions');
      assert.match(text(actions), /Check status/);
      assert.match(text(actions), /Retry original request/);
      assert.doesNotMatch(text(actions), /Sign a new revoke request|Revoke access/);
      const count = a.orders.length;
      await a.click('Check status'); assert.equal(a.orders.length, count);
      await a.click('Retry original request');
      assert.equal(a.orders.length, count + 1);
      assert.equal(a.orders.at(-1), JSON.stringify(revoked.submission.request));
      assert.equal(a.signed.length, 2, 'retry must not request another signature');
      assert.match(text(a.render()), /Revoke unconfirmed/);
      accountState.omitAgents = false; agents.length = 0;
      await a.click('Check status');
      assert.match(text(a.render()), /Not listed/);
      assert.ok(!all(a.render()).some(n => n.type === 'button' && text(n).trim() === 'Retry original request'));
      assert.equal(a.orders.length, count + 1); assert.equal(a.signed.length, 2);
    }
  } finally { globalThis.fetch = original; }
});
