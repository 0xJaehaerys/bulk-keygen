// Offline component regression harness. No browser, exchange, or filesystem writes.
// Executed by npm test; all HTTP is intercepted and keys are disposable.
import test from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { registerHooks, createRequire } from 'node:module';
import { generateKeyPairSync, sign } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const site = fileURLToPath(new URL('../', import.meta.url));
const requireSite = createRequire(join(site, 'package.json'));
const ts = requireSite('typescript');
const bs58 = requireSite('bs58').default;
const asset = pathToFileURL(join(site, 'node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm')).href;
registerHooks({
  resolve(specifier, context, next) {
    return specifier === 'bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm?url'
      ? { url: 'test:subaccount-wasm', shortCircuit: true } : next(specifier, context);
  },
  load(url, context, next) {
    return url === 'test:subaccount-wasm'
      ? { format: 'module', source: `import fs from 'node:fs'; export default fs.readFileSync(new URL(${JSON.stringify(asset)}));`, shortCircuit: true }
      : next(url, context);
  },
});
const subs = await import(pathToFileURL(join(site, 'lib/subaccounts.ts')).href);
const bulk = await import(pathToFileURL(join(site, 'lib/bulk.ts')).href);
const walletLib = await import(pathToFileURL(join(site, 'lib/wallet.ts')).href);
const pair = generateKeyPairSync('ed25519');
const owner = bs58.encode(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
const child = '11111111111111111111111111111112';
const wrongChild = '11111111111111111111111111111113';
const source = fs.readFileSync(join(site, 'components/subaccount-creator.tsx'), 'utf8');
const code = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
}).outputText;

function all(node) {
  if (!node || typeof node !== 'object') return [];
  return [node, ...(Array.isArray(node) ? node : Object.values(node.props ?? {})).flatMap(all)];
}
function text(node) {
  return typeof node === 'string' ? node : Array.isArray(node) ? node.map(text).join('')
    : node && typeof node === 'object' ? text(node.props?.children) : '';
}
function fresh() {
  const state = [], refs = [], orders = [], reads = [], selected = [];
  let stateIndex = 0, refIndex = 0, epoch = 0, currentOwner = owner, busy = false;
  let lastRun = Promise.resolve(), mode = 'timeout', signed = 0, downloads = 0;
  let pendingOwner = '', release = null, childName = 'desk-1';
  const jsx = (type, props) => ({ type, props });
  const react = {
    useEffect() {},
    useRef(value) { return refs[refIndex++] ??= { current: value }; },
    useState(value) {
      const index = stateIndex++;
      if (!(index in state)) state[index] = value;
      return [state[index], next => { state[index] = typeof next === 'function' ? next(state[index]) : next; }];
    },
  };
  const signer = {
    name: 'Test wallet',
    get publicKey() { return currentOwner ? { toString: () => currentOwner } : null; },
    async signMessage(bytes) {
      signed++;
      return { signature: new Uint8Array(sign(null, bytes, pair.privateKey)), publicKey: { toString: () => owner } };
    },
  };
  const props = () => ({
    network: 'testnet', owner: currentOwner, hasKey: false, busy,
    wallet: () => signer,
    ensureContext(version, expectedOwner) {
      if (version !== epoch || (expectedOwner && expectedOwner !== currentOwner)) throw new bulk.BulkError('Context changed');
    },
    onPendingChange(value) { pendingOwner = value; },
    onVerified(address, info) { selected.push({ address, info }); },
    run(_label, task) {
      if (busy) return Promise.resolve();
      busy = true;
      lastRun = task(epoch).finally(() => { busy = false; });
      return lastRun;
    },
  });
  const require = path => path === 'react' ? react
    : path === 'react/jsx-runtime' ? { jsx, jsxs: jsx, Fragment: 'Fragment' }
    : path === '@/lib/subaccounts' ? subs : path === '@/lib/bulk' ? bulk : path === '@/lib/wallet' ? walletLib
    : new Proxy({}, { get: (_, name) => String(name) });
  const exports = {}, window = {};
  window.self = window; window.top = window;
  vm.runInNewContext(code, {
    exports, require, window, Uint8Array, Blob, console,
    URL: { createObjectURL() { return 'blob:synthetic'; }, revokeObjectURL() {} },
    document: { createElement() { return { click() { downloads++; } }; } },
    setTimeout(callback) { callback(); },
  });
  function success() {
    return new Response(JSON.stringify({ status: 'ok', response: { type: 'order', data: {
      statuses: [{ createSubAccount: { master: owner, sub: child, name: 'desk-1', margin: 0 } }],
    } } }));
  }
  // Every call is intercepted. There is deliberately no reference to original fetch.
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (url.endsWith('/account')) {
      reads.push(body.user);
      const info = body.user === owner
        ? { kind: 'MasterEOA', subAccounts: [], authorizedAgentWallets: [] }
        : { kind: 'SubAccount', parent: owner, name: body.user === wrongChild ? 'other-account' : childName,
            subAccounts: [], authorizedAgentWallets: [] };
      return new Response(JSON.stringify([{ fullAccount: info }]));
    }
    assert.ok(url.endsWith('/order'), 'Unexpected endpoint');
    orders.push(options.body);
    if (mode === 'timeout') throw new TypeError('Synthetic network failure');
    if (mode === 'delayed') return new Promise(resolve => { release = () => resolve(success()); });
    return success();
  };
  const render = () => { stateIndex = refIndex = 0; return exports.SubaccountCreator(props()); };
  const button = label => {
    const found = all(render()).find(node => node.type === 'button' && text(node.props.children).trim() === label);
    assert.ok(found, `Button not found: ${label}`); return found;
  };
  return {
    state, refs, orders, reads, selected, render, button,
    get signed() { return signed; }, get downloads() { return downloads; }, get pendingOwner() { return pendingOwner; },
    checkbox() { return all(render()).find(node => node.type === 'Checkbox'); },
    async sign() {
      all(render()).find(node => node.type === 'Input' && node.props.pattern).props.onChange({ target: { value: 'desk-1' } });
      all(render()).find(node => node.type === 'form').props.onSubmit({ preventDefault() {} });
      await lastRun; assert.equal(state[3], 'signed');
    },
    async settle() { await lastRun; },
    mode(value) { mode = value; },
    disconnect() { currentOwner = ''; epoch++; render(); },
    reconnect() { currentOwner = owner; epoch++; render(); },
    async waitOrder() { for (let i = 0; i < 100 && !release; i++) await new Promise(setImmediate); assert.ok(release); },
    release() { release(); },
    setChildName(value) { childName = value; },
    candidate(value) {
      const input = all(render()).find(node => node.type === 'Input' && node.props.placeholder === 'Public address from BULK');
      assert.ok(input, 'Editable candidate input missing'); input.props.onChange({ target: { value } });
    },
    async restore(value) {
      const control = all(render()).find(node => node.type === 'Input' && node.props.type === 'file');
      const encoded = JSON.stringify(value);
      control.props.onChange({ target: { files: [{ size: encoded.length, async text() { return encoded; } }], value: 'fixture' } });
      await lastRun;
    },
  };
}

await test('creation UI preserves authorization and recovery across nine failure scenarios', async () => {
const originalFetch = globalThis.fetch;
try {
const checks = [];
const a = fresh(); await a.sign(); assert.equal(a.orders.length, 0);
a.button('Create subaccount').props.onClick(); await a.settle(); assert.equal(a.orders.length, 0);
checks.push('No order before saved acknowledgement');
a.button('Save creation request').props.onClick(); assert.equal(a.downloads, 1);
a.checkbox().props.onCheckedChange(true);
const firstSubmit = a.button('Create subaccount'); firstSubmit.props.onClick(); firstSubmit.props.onClick();
await a.settle(); assert.equal(a.orders.length, 1); assert.equal(a.state[3], 'pending');
checks.push('Double click submits once');
const originalWire = a.orders[0], saved = { ...a.state[2] };
a.button('Retry original request').props.onClick(); await a.settle();
assert.equal(a.orders.length, 2); assert.equal(a.orders[1], originalWire); assert.equal(a.signed, 1);
checks.push('Retry preserves exact wire envelope and does not sign again');

const b = fresh(); await b.sign(); b.checkbox().props.onCheckedChange(true); b.mode('delayed');
b.button('Create subaccount').props.onClick(); await b.waitOrder(); b.disconnect(); b.release(); await b.settle();
assert.equal(b.state[3], 'pending'); assert.equal(b.state[2].address, child); assert.equal(b.selected.length, 0);
b.button('Save creation request').props.onClick(); assert.equal(b.downloads, 1);
checks.push('Receipt survives disconnect and remains downloadable without selecting account');
b.reconnect(); b.setChildName(undefined); b.button('Check subaccount').props.onClick(); await b.settle();
assert.equal(b.state[3], 'confirmed'); assert.equal(b.selected[0].address, child); assert.equal(b.orders.length, 1);
assert.equal(b.pendingOwner, '');
checks.push('Trusted receipt verifies after reconnect without another order or master-list membership');

const c = fresh(); await c.restore(saved); assert.equal(c.state[3], 'pending');
assert.equal(c.orders.length, 0); assert.equal(c.signed, 0);
c.button('Retry original request').props.onClick(); await c.settle(); assert.equal(c.orders[0], originalWire);
checks.push('Import is local and explicit retry preserves original envelope');

const d = fresh(); await d.restore({ ...saved, address: wrongChild });
const signatureBefore = d.state[2].request.signature, nonceBefore = d.state[2].request.nonce;
d.button('Check subaccount').props.onClick(); await d.settle();
assert.equal(d.state[3], 'pending'); assert.equal(d.selected.length, 0);
d.candidate(child); d.button('Check subaccount').props.onClick(); await d.settle();
assert.equal(d.state[3], 'confirmed'); assert.equal(d.selected[0].address, child);
assert.equal(d.state[2].request.signature, signatureBefore); assert.equal(d.state[2].request.nonce, nonceBefore);
assert.equal(d.signed, 0); assert.equal(d.orders.length, 0);
checks.push('Incorrect unsigned imported address can be corrected without signing or submission');

const e = fresh(); await e.restore({ ...saved, address: child }); e.setChildName(undefined);
e.button('Check subaccount').props.onClick(); await e.settle();
assert.equal(e.state[3], 'pending'); assert.equal(e.selected.length, 0);
checks.push('Imported address requires returned exact name, unlike trusted live receipt');

const f = fresh(); await f.sign(); f.checkbox().props.onCheckedChange(true); f.mode('success');
const originalVerify = crypto.subtle.verify;
crypto.subtle.verify = function (...args) {
  const verification = originalVerify.apply(this, args);
  // A real provider change while submitSubaccount awaits local signature validation.
  f.disconnect();
  return verification;
};
try {
  f.button('Create subaccount').props.onClick(); await f.settle();
  assert.equal(f.orders.length, 0, 'Wallet changed during async pre-submit verification, but /order was dispatched');
  assert.equal(f.selected.length, 0);
} finally { crypto.subtle.verify = originalVerify; }
checks.push('Wallet change during async pre-submit crypto validation prevents dispatch');

assert.equal(checks.length, 9);
} finally { globalThis.fetch = originalFetch; }
});
