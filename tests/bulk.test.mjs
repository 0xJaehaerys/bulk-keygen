import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import bs58 from 'bs58';
import init, { WasmKeypair, prepareAgentWallet } from 'bulk-keychain-wasm';
import { NETWORKS, parseAccount, agentMembership, readbackState, assertOwner, assertRegistrationEnvelope, registrationResult, readAccount, submitRegistration, exportKey, validPublicKey } from '../lib/bulk.ts';

await init({ module_or_path: readFileSync(new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url)) });
const ownerPair = new WasmKeypair();
const owner = ownerPair.pubkey;
const pk = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), ownerPair.secretKey()]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(pk);
ownerPair.free();
const agentPair = new WasmKeypair();
const key = { network: 'testnet', owner, account: owner, publicKey: agentPair.pubkey, secretKey: agentPair.toBase58(), createdAt: '2026-09-08T00:00:00Z' };
agentPair.free();
const childPair = new WasmKeypair(); const child = childPair.pubkey; childPair.free();
const master = { kind: 'MasterEOA', parent: null, subAccounts: [{ pubkey: child }], authorizedAgentWallets: [] };
const childInfo = { kind: 'SubAccount', parent: owner, subAccounts: [], authorizedAgentWallets: [key.publicKey] };
function signed(network = 'testnet', account = owner) {
  const p = prepareAgentWallet(key.publicKey, false, { signatureDomain: network, account, signer: owner, nonce: '1788816000000000123' });
  try {
    const bytes = p.messageBytes;
    const signature = sign(null, bytes, pk);
    const raw = p.finalizeBytes(signature);
    if (typeof raw.actions === 'string') raw.actions = JSON.parse(raw.actions);
    return { raw, bytes, signature };
  } finally { p.free(); }
}
const success = { status: 'ok', response: { type: 'order', data: { statuses: [{ agentWallet: { agent_wallet: key.publicKey } }] } } };

test('current mainnet and testnet endpoints are pinned independently', () => {
  assert.equal(NETWORKS.mainnet.api, 'https://mainnet-api1.bulk.trade/api/v1');
  assert.equal(NETWORKS.testnet.api, 'https://exchange-api.bulk.trade/api/v1');
});
test('official WASM generates a recoverable 64-byte keypair export', () => {
  assert.equal(bs58.decode(key.secretKey).length, 64);
  const restored = WasmKeypair.fromBase58(key.secretKey);
  try { assert.equal(restored.pubkey, key.publicKey); } finally { restored.free(); }
  assert.ok(validPublicKey(key.publicKey)); assert.equal(validPublicKey(key.secretKey), false);
});
test('real SDK canonical registration matches owner and preserves uint64 nonce', () => {
  const { raw, bytes, signature } = signed();
  assert.ok(verify(null, bytes, publicKey, signature));
  const tx = assertRegistrationEnvelope(raw, key);
  assert.deepEqual(tx.actions, [{ agentWalletCreation: { a: key.publicKey, d: false } }]);
  assert.equal(tx.nonce, '1788816000000000123');
  assert.equal(bytes.at(-1), 2);
  assert.equal(signed('mainnet').bytes.at(-1), 1);
});
test('signature cannot be reused for a different network or account', () => {
  const a = signed();
  assert.equal(verify(null, signed('mainnet').bytes, publicKey, a.signature), false);
  assert.equal(verify(null, signed('testnet', child).bytes, publicKey, a.signature), false);
});
test('browser Ed25519 verifier accepts raw wallet signature and rejects mutations', async () => {
  const a = signed();
  const k = await crypto.subtle.importKey('raw', bs58.decode(owner), 'Ed25519', false, ['verify']);
  assert.ok(await crypto.subtle.verify('Ed25519', k, a.signature, a.bytes));
  const mutated = Uint8Array.from(a.bytes); mutated[0] ^= 1;
  assert.equal(await crypto.subtle.verify('Ed25519', k, a.signature, mutated), false);
});
test('strict account readback establishes owner and selected subaccount', () => {
  assertOwner(parseAccount([{ fullAccount: master }]), owner, owner);
  assertOwner(parseAccount([{ fullAccount: childInfo }]), child, owner);
  assert.throws(() => assertOwner(childInfo, child, key.publicKey));
  assert.throws(() => assertOwner(master, child, owner));
  assert.throws(() => parseAccount([{ fullAccount: { ...master, kind: 'Isolated' } }]));
  assert.throws(() => parseAccount([{ fullAccount: { ...master, authorizedAgentWallets: 'invalid' } }]));
  assert.throws(() => parseAccount([{ fullAccount: { ...childInfo, parent: null } }]));
});
test('master readback accepts an omitted optional parent and keeps owner checks strict', async () => {
  const { parent: _parent, ...withoutParent } = master;
  const got = await readAccount('mainnet', owner, async () => new Response(JSON.stringify([{ fullAccount: withoutParent }])));
  assert.equal(got.parent, null);
  assertOwner(got, owner, owner);
  assert.throws(() => assertOwner(got, owner, child));
  assert.throws(() => assertOwner(got, child, owner));
  for (const parent of ['', owner, child, 0, false, {}]) {
    assert.throws(() => parseAccount([{ fullAccount: { ...master, parent } }]));
  }
  const { parent: _childParent, ...childWithoutParent } = childInfo;
  assert.throws(() => parseAccount([{ fullAccount: childWithoutParent }]));
  assert.throws(() => parseAccount([{ fullAccount: { ...childInfo, parent: '' } }]));
});
test('live minimal master response loads without claiming empty account lists', async () => {
  for (const network of ['mainnet', 'testnet']) {
    const got = await readAccount(network, owner, async () => new Response(JSON.stringify([{ fullAccount: { kind: 'MasterEOA', name: 'Test account' } }])));
    assertOwner(got, owner, owner);
    assert.equal(got.parent, null);
    assert.equal(got.subAccounts, null);
    assert.equal(got.authorizedAgentWallets, null);
    assert.equal(agentMembership(got, key.publicKey), null);
    for (const intent of [null, 'register', 'revoke']) assert.equal(readbackState(got, key.publicKey, intent), 'pending');
  }
});
test('agent readback distinguishes unavailable, absent and present after either operation', () => {
  const absent = parseAccount([{ fullAccount: master }]);
  const present = parseAccount([{ fullAccount: { ...master, authorizedAgentWallets: [key.publicKey] } }]);
  assert.equal(agentMembership(absent, key.publicKey), false);
  assert.equal(agentMembership(present, key.publicKey), true);
  assert.equal(readbackState(absent, key.publicKey, null), 'absent');
  assert.equal(readbackState(absent, key.publicKey, 'register'), 'pending');
  assert.equal(readbackState(absent, key.publicKey, 'revoke'), 'revoked');
  assert.equal(readbackState(present, key.publicKey, null), 'active');
  assert.equal(readbackState(present, key.publicKey, 'register'), 'active');
  assert.equal(readbackState(present, key.publicKey, 'revoke'), 'pending');
});
test('omitted discovery fields never weaken child ownership or accept malformed lists', () => {
  const childAccount = parseAccount([{ fullAccount: { kind: 'SubAccount', parent: owner } }]);
  assertOwner(childAccount, child, owner);
  assert.throws(() => assertOwner(childAccount, child, key.publicKey));
  assert.throws(() => assertOwner(childAccount, owner, owner));
  for (const field of ['authorizedAgentWallets', 'subAccounts']) {
    for (const value of [null, false, {}, '', ['invalid']]) {
      assert.throws(() => parseAccount([{ fullAccount: { ...master, [field]: value } }]));
    }
  }
});
test('envelope rejects unrelated actions, agents, signers and unsafe number nonces', () => {
  const { raw } = signed();
  for (const tx of [
    { ...raw, signer: child }, { ...raw, account: child }, { ...raw, nonce: Number(raw.nonce) },
    ...['0', '01', ' 1', '+1', '1.0', '1e3', '18446744073709551616', '0'.repeat(24000) + '1'].map(nonce => ({ ...raw, nonce })),
    { ...raw, actions: [...raw.actions, { cancelAll: {} }] },
    { ...raw, actions: [{ agentWalletCreation: { a: child, d: false } }] },
    { ...raw, actions: [{ agentWalletCreation: { a: key.publicKey, d: true } }] },
    { ...raw, actions: [{ agentWalletCreation: { a: key.publicKey, d: false, extra: 1 } }] },
  ]) assert.throws(() => assertRegistrationEnvelope(tx, key));
});
test('HTTP ok with agentWalletFailed remains rejection', () => {
  assert.equal(registrationResult(success, key.publicKey), 'accepted');
  assert.equal(registrationResult(success, child), 'unknown');
  assert.equal(registrationResult({ status: 'ok', response: { type: 'order', data: { statuses: [{ agentWalletFailed: { message: 'Unauthorized' } }] } } }, key.publicKey), 'rejected');
  assert.equal(registrationResult({ status: 'ok' }, key.publicKey), 'unknown');
});
test('readback is unsigned and sends only an account identifier', async () => {
  const calls = [];
  const got = await readAccount('testnet', child, async (url, options) => { calls.push({ url, options }); return new Response(JSON.stringify([{ fullAccount: childInfo }])); });
  assert.ok(got.authorizedAgentWallets.includes(key.publicKey));
  assert.equal(calls[0].url, `${NETWORKS.testnet.api}/account`);
  assert.deepEqual(JSON.parse(calls[0].options.body), { type: 'fullAccount', user: child });
  assert.equal(calls[0].options.credentials, 'omit');
});
test('submission includes no secret, uses one request and never retries a timeout', async () => {
  const tx = assertRegistrationEnvelope(signed().raw, key);
  let calls = 0;
  await assert.rejects(() => submitRegistration('testnet', tx, async (_url, options) => {
    calls++;
    assert.ok(!options.body.includes(key.secretKey));
    assert.deepEqual(Object.keys(JSON.parse(options.body)).sort(), ['account', 'actions', 'nonce', 'signature', 'signer']);
    assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
    throw new DOMException('timeout', 'TimeoutError');
  }));
  assert.equal(calls, 1);
});
test('account not found gives a usable network/account error', async () => {
  await assert.rejects(() => readAccount('mainnet', owner, async () => new Response('{}', { status: 404 })), error => error.code === 'ACCOUNT_NOT_FOUND');
});
test('account transport failures identify BULK without blaming Phantom or exposing raw errors', async () => {
  for (const [failure, code] of [
    [new TypeError('private diagnostic'), 'ACCOUNT_NETWORK_ERROR'],
    [new DOMException('private diagnostic', 'TimeoutError'), 'ACCOUNT_TIMEOUT'],
  ]) {
    let calls = 0;
    await assert.rejects(() => readAccount('mainnet', owner, async () => { calls++; throw failure; }), error => {
      assert.equal(error.code, code);
      assert.match(error.message, /BULK Mainnet/);
      assert.doesNotMatch(error.message, /private diagnostic|wallet|Phantom|key status/);
      return true;
    });
    assert.equal(calls, 1);
  }
});
test('account HTTP and invalid JSON failures remain distinct and never expose server bodies', async () => {
  for (const status of [429, 502]) {
    await assert.rejects(() => readAccount('mainnet', owner, async () => new Response('private diagnostic', { status })), error => {
      assert.equal(error.code, 'ACCOUNT_HTTP_ERROR');
      assert.match(error.message, new RegExp(`BULK Mainnet.*HTTP ${status}`));
      assert.doesNotMatch(error.message, /private diagnostic|key status/);
      return true;
    });
  }
  await assert.rejects(() => readAccount('testnet', owner, async () => new Response('<html>private diagnostic</html>')), error => {
    assert.equal(error.code, 'ACCOUNT_RESPONSE_ERROR');
    assert.match(error.message, /BULK Testnet/);
    assert.doesNotMatch(error.message, /private diagnostic/);
    return true;
  });
});
test('export carries the exact account, network and recoverable agent secret', () => {
  const document = JSON.parse(exportKey(key));
  assert.equal(document.account_public_key, key.account);
  assert.equal(document.agent_private_key_base58, key.secretKey);
  assert.equal(document.api_url, NETWORKS.testnet.api);
  assert.equal(document.signature_domain, 'testnet');
  assert.ok(!('registration_status' in document)); // Export is not evidence of registration.
});
