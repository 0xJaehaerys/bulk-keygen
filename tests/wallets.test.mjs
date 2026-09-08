import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import bs58 from 'bs58';
import { getWallets } from '@wallet-standard/app';
import { availableWallets, watchWallets, supportsMessageSigning, standardWalletOption, phantomWalletOption } from '../lib/wallet-providers.ts';
import { signWithWallet, connectionError, authorizationError } from '../lib/wallet.ts';

function accountFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const bytes = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  return { privateKey, publicKey, account: { address: bs58.encode(bytes), publicKey: bytes, chains: ['solana:mainnet'], features: ['solana:signMessage'] } };
}
function fixture(name = 'Backpack') {
  const owner = accountFixture(), listeners = new Set(), calls = [];
  let response;
  const wallet = { version: '1.0.0', name, chains: ['solana:mainnet'], accounts: [owner.account], icon: 'data:image/svg+xml,', features: {
    'standard:connect': { version: '1.0.0', async connect() { return { accounts: wallet.accounts }; } },
    'standard:events': { version: '1.0.0', on(event, listener) { assert.equal(event, 'change'); listeners.add(listener); return () => listeners.delete(listener); } },
    'solana:signMessage': { version: '1.1.0', async signMessage(input) {
      calls.push(input); assert.ok(wallet.accounts.includes(input.account));
      if (response) return response(input);
      return [{ signedMessage: Uint8Array.from(input.message), signature: new Uint8Array(sign(null, input.message, owner.privateKey)) }];
    } },
  } };
  return { wallet, owner, calls, listeners, setResponse(fn) { response = fn; }, emit(properties) { listeners.forEach(listener => listener(properties)); } };
}

test('standard discovery requires Solana message signing and compatible feature versions', () => {
  const { wallet } = fixture();
  assert.equal(supportsMessageSigning(wallet), true);
  assert.equal(supportsMessageSigning({ ...wallet, chains: ['eip155:1'] }), false);
  for (const feature of ['standard:connect', 'standard:events', 'solana:signMessage']) {
    const missing = { ...wallet.features }; delete missing[feature];
    assert.equal(supportsMessageSigning({ ...wallet, features: missing }), false);
    assert.equal(supportsMessageSigning({ ...wallet, features: { ...wallet.features, [feature]: { ...wallet.features[feature], version: '9.0.0' } } }), false);
  }
});
test('standard signer preserves canonical binary, original account identity and selected public key', async () => {
  const f = fixture();
  const [connection] = await standardWalletOption(f.wallet).connect();
  const bytes = Uint8Array.of(1, 0, 255, 128, 17, 0, 0, 2);
  const signed = await signWithWallet(connection, bytes);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].account, f.owner.account);
  assert.deepEqual(f.calls[0].message, bytes);
  assert.notEqual(f.calls[0].message, bytes);
  assert.deepEqual(Object.keys(f.calls[0]).sort(), ['account', 'message']); // No invented Solana network switch.
  assert.equal(signed.publicKey.toString(), f.owner.account.address);
  assert.ok(verify(null, bytes, f.owner.publicKey, signed.signature));
});
test('wallet cannot prefix, replace or mutate the canonical signing message', async () => {
  for (const modify of [
    input => Uint8Array.of(0, ...input.message),
    input => { input.message.fill(0); return input.message; },
  ]) {
    const f = fixture();
    f.setResponse(input => [{ signedMessage: modify(input), signature: new Uint8Array(64) }]);
    const [connection] = await standardWalletOption(f.wallet).connect();
    const bytes = Uint8Array.of(1, 255, 2);
    await assert.rejects(() => signWithWallet(connection, bytes), error => error.code === 'WALLET_MESSAGE_CHANGED');
    assert.deepEqual(bytes, Uint8Array.of(1, 255, 2));
    assert.equal(f.calls.length, 1);
  }
});
test('standard signer rejects missing, multiple, wrong-length and non-Ed25519 signatures', async () => {
  for (const outputs of [[], [{ signature: new Uint8Array(64) }], [0, 0], [{ signature: new Uint8Array(32) }], [{ signature: new Uint8Array(64), signatureType: 'secp256k1' }]]) {
    const f = fixture();
    f.setResponse(input => outputs.map(output => ({ signedMessage: input.message, ...output })));
    const [connection] = await standardWalletOption(f.wallet).connect();
    // Missing signedMessage is covered separately; this case tests shape/algorithm/count.
    if (outputs.length === 1 && outputs[0].signature?.length === 64 && !outputs[0].signatureType) {
      f.setResponse(() => outputs);
    }
    await assert.rejects(() => signWithWallet(connection, Uint8Array.of(1)));
    assert.equal(f.calls.length, 1);
  }
});
test('all authorized accounts are offered and invalid or hardware-only accounts are excluded', async () => {
  const f = fixture(); const second = accountFixture();
  f.wallet.accounts.push(second.account, { ...accountFixture().account, features: [] }, { ...f.owner.account, address: second.account.address });
  const connections = await standardWalletOption(f.wallet).connect();
  assert.deepEqual(connections.map(c => c.publicKey.toString()), [f.owner.account.address, second.account.address]);
  f.wallet.accounts = [{ ...f.owner.account, features: [] }];
  await assert.rejects(() => standardWalletOption(f.wallet).connect(), /No Solana account/);
});
test('account removal or unregister while signing aborts without a second signing attempt', async () => {
  for (const change of ['accounts', 'registration']) {
    const f = fixture(); let registered = true;
    const [connection] = await standardWalletOption(f.wallet, () => registered).connect();
    f.setResponse(input => {
      if (change === 'accounts') f.wallet.accounts = []; else registered = false;
      return [{ signedMessage: input.message, signature: new Uint8Array(64) }];
    });
    await assert.rejects(() => signWithWallet(connection, Uint8Array.of(1)), error => error.code === 'WALLET_CHANGED');
    assert.equal(connection.publicKey, null);
    await assert.rejects(() => signWithWallet(connection, Uint8Array.of(1)));
    assert.equal(f.calls.length, 1);
  }
});
test('standard events respect omitted properties and subscriptions clean up', async () => {
  const f = fixture(); const [connection] = await standardWalletOption(f.wallet).connect();
  let changes = 0; const off = connection.subscribe(() => changes++);
  f.emit({}); assert.equal(changes, 0);
  f.emit({ accounts: [] }); f.emit({ chains: [] }); f.emit({ features: {} }); assert.equal(changes, 3);
  off(); assert.equal(f.listeners.size, 0); f.emit({ accounts: [] }); assert.equal(changes, 3);
});
test('registry discovers late wallets, removes unregistered wallets and avoids duplicate Phantom', async () => {
  globalThis.window = new EventTarget();
  const registry = getWallets(); const updates = [];
  const stop = watchWallets(options => updates.push(options));
  const f = fixture('Phantom'); const legacy = { publicKey: null, signMessage() {}, connect() {}, on() {}, removeListener() {} };
  window.phantom = { solana: legacy };
  const remove = registry.register(f.wallet);
  assert.deepEqual(availableWallets().map(w => w.name), ['Phantom']);
  const id = availableWallets()[0].id;
  assert.equal(availableWallets()[0].id, id);
  const [connection] = await availableWallets()[0].connect();
  remove(); assert.equal(connection.publicKey, null);
  assert.equal(availableWallets()[0].name, 'Phantom'); // Retained legacy fallback.
  delete window.phantom; window.dispatchEvent(new Event('focus'));
  assert.equal(updates.at(-1).length, 0);
  const count = updates.length; stop(); const removeAgain = registry.register(f.wallet); removeAgain();
  assert.equal(updates.length, count);
  delete globalThis.window;
});
test('legacy Phantom retains hex display and no automatic signing or reconnection', async () => {
  const f = fixture(); let signed = 0;
  const listeners = new Map();
  const phantom = { publicKey: { toString: () => f.owner.account.address }, async connect() { return { publicKey: this.publicKey }; }, on(event, fn) { listeners.set(event, fn); }, removeListener(event) { listeners.delete(event); }, async signMessage(message, display) {
    signed++; assert.equal(display, 'hex'); return { signature: new Uint8Array(sign(null, message, f.owner.privateKey)), publicKey: this.publicKey };
  } };
  const [connection] = await phantomWalletOption(phantom).connect(); assert.equal(signed, 0);
  const off = connection.subscribe(() => {}); assert.equal(listeners.size, 2); off(); assert.equal(listeners.size, 0);
  await signWithWallet(connection, Uint8Array.of(255)); assert.equal(signed, 1);
  phantom.publicKey = null;
  await assert.rejects(() => signWithWallet(connection, Uint8Array.of(255))); assert.equal(signed, 1);
});
test('wallet errors use the selected known provider and do not expose arbitrary names or messages', () => {
  assert.match(connectionError({ code: 4001 }, 'Solflare').message, /Solflare/);
  assert.match(authorizationError({ code: -32000 }, 'wallet', 'Backpack').message, /Backpack -32000/);
  assert.doesNotMatch(authorizationError({ message: 'private diagnostic' }, 'wallet', 'private diagnostic').message, /private diagnostic|Phantom/);
});
