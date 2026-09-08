import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { createPrivateKey, sign } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BulkError, publicKeyBytes } from '../lib/bulk.ts';
import { authorizationError, connectionError, signWithWallet } from '../lib/wallet.ts';
import { standardWalletOption } from '../lib/wallet-providers.ts';
import { exportBackup, decryptVault, encryptVault } from '../lib/vault.ts';
import { runCli } from '../scripts/keygen.mjs';

// Use the exact application crypto module in Node; only Vite's WASM asset URL
// import is replaced with local bytes. No provider or exchange connection.
const assetUrl = new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url).href;
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm?url') return { url: 'test:bulk-wasm-asset', shortCircuit: true };
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url === 'test:bulk-wasm-asset') return { format: 'module', source: `import { readFileSync } from 'node:fs'; export default readFileSync(new URL(${JSON.stringify(assetUrl)}));`, shortCircuit: true };
    return next(url, context);
  },
});
const { loadSdk, generateKey, prepareRegistration, finalizeRegistration, validateKeypair, validateSubmission } = await import('../lib/crypto.ts');
const sdk = await loadSdk();
const { registrationMessage } = await import('../lib/crypto.ts');
const { registrationModeForWallet } = await import('../lib/wallet.ts');
const { default: bs58 } = await import('bs58');
const ownerPair = new sdk.WasmKeypair();
const owner = ownerPair.pubkey;
const signer = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), ownerPair.secretKey()]), format: 'der', type: 'pkcs8' });
ownerPair.free();

test('Phantom master registration and revoke verify Base58 text and preserve recovery mode', async () => {
  for (const network of ['testnet', 'mainnet']) {
    const key = await generateKey(network, owner, owner);
    assert.equal(registrationModeForWallet('Phantom', key.account, key.owner), 'base58');
    for (const operation of ['register', 'revoke']) {
      const prepared = await prepareRegistration(key, operation);
      try {
        const message = registrationMessage(prepared, key, operation, 'base58');
        assert.deepEqual(message, new TextEncoder().encode(bs58.encode(prepared.messageBytes)));
        const signature = new Uint8Array(sign(null, message, signer));
        const request = await finalizeRegistration(prepared, signature, key, operation, 'base58');
        const attempt = { operation, request, signatureMode: 'base58' };
        const backup = await decryptVault(exportBackup(key, attempt), '', true);
        assert.equal(backup.submission.signatureMode, 'base58');
        await validateSubmission(backup.key, backup.submission);
        await assert.rejects(() => finalizeRegistration(prepared, signature, key, operation), /signature does not match/);
        const rawSignature = new Uint8Array(sign(null, prepared.messageBytes, signer));
        await assert.rejects(() => finalizeRegistration(prepared, rawSignature, key, operation, 'base58'), /signature does not match/);
        assert.throws(() => exportBackup(key, { ...attempt, signatureMode: 'unknown' }), /signing mode/);
        const malformed = JSON.parse(exportBackup(key, attempt));
        malformed.submission.signatureMode = 'unknown';
        await assert.rejects(() => decryptVault(JSON.stringify(malformed), '', true), /signing mode/);
      } finally { prepared.free(); }
    }
  }
});

test('Phantom cannot silently broaden subaccount permission or use Base58 for another action', async () => {
  const child = (await generateKey('testnet', owner, owner)).publicKey;
  const key = await generateKey('testnet', child, owner);
  assert.throws(() => registrationModeForWallet('Phantom', child, owner), /subaccount/);
  assert.equal(registrationModeForWallet('Another wallet', child, owner), 'raw');
  const prepared = await prepareRegistration(key);
  try { assert.throws(() => registrationMessage(prepared, key, 'register', 'base58'), /main account/); }
  finally { prepared.free(); }
  const mainKey = await generateKey('testnet', owner, owner);
  const main = await prepareRegistration(mainKey);
  try {
    assert.throws(() => registrationMessage(main, mainKey, 'revoke', 'base58'), /action/);
    assert.throws(() => registrationMessage(main, mainKey, 'register', 'offchain'), /signing mode/);
  } finally { main.free(); }
});

test('encrypted text-mode backup recovers through CLI without new signing, custom headers or secret transmission', async () => {
  const key = await generateKey('testnet', owner, owner);
  const prepared = await prepareRegistration(key);
  const directory = await mkdtemp(join(tmpdir(), 'bulk-text-recovery-'));
  try {
    const bytes = registrationMessage(prepared, key, 'register', 'base58');
    const request = await finalizeRegistration(prepared, new Uint8Array(sign(null, bytes, signer)), key, 'register', 'base58');
    const attempt = { operation: 'register', request, signatureMode: 'base58' };
    const encrypted = await encryptVault(key, 'a disposable unique test password', attempt);
    const restored = await decryptVault(encrypted, 'a disposable unique test password');
    assert.deepEqual(restored.submission, attempt);
    await validateSubmission(restored.key, restored.submission);
    await assert.rejects(() => validateSubmission(key, { ...attempt, signatureMode: 'raw' }), /signature does not match/);
    const file = join(directory, 'agent.json');
    await writeFile(file, exportBackup(restored.key, restored.submission), { mode: 0o600 });
    const orders = [];
    const logs = [];
    const deps = { output: text => logs.push(text), fetcher: async (url, options) => {
      if (url.endsWith('/account')) return new Response(JSON.stringify([{ fullAccount: { kind: 'MasterEOA', authorizedAgentWallets: [] } }]));
      orders.push(options.body);
      assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
      assert.equal(options.body.includes(key.secretKey), false);
      assert.equal(options.body.includes('signatureMode'), false);
      throw new DOMException('synthetic timeout', 'TimeoutError');
    } };
    await runCli(['submit', '--file', file, '--confirm-network', 'testnet'], deps);
    await runCli(['submit', '--file', file, '--confirm-network', 'testnet'], deps);
    assert.equal(orders.length, 2);
    assert.equal(orders[0], orders[1]);
    assert.deepEqual(JSON.parse(orders[0]), request);
    assert.equal(logs.some(text => text.includes(key.secretKey)), false);
  } finally { prepared.free(); await rm(directory, { recursive: true, force: true }); }
});

test('connection errors identify Phantom separately from account loading and signing', () => {
  for (const code of [4001, 4100, 4900, -32002, -32603]) {
    const error = connectionError({ code, message: 'private diagnostic' }, 'Phantom');
    assert.equal(error.code, 'WALLET_CONNECTION_ERROR');
    assert.match(error.message, /Phantom/);
    assert.ok(error.message.includes(String(code)));
    assert.doesNotMatch(error.message, /private diagnostic|Signature|key remains/);
  }
  assert.doesNotMatch(connectionError(new Error('private diagnostic')).message, /private diagnostic/);
});

test('application prepares and verifies binary wallet signing with automatic SDK nonces on both networks', async () => {
  for (const network of ['mainnet', 'testnet']) {
    const key = await generateKey(network, owner, owner);
    for (const operation of ['register', 'revoke']) {
      const prepared = await prepareRegistration(key, operation);
      try {
        const canonical = prepared.messageBytes;
        let calls = 0;
        const wallet = { async signMessage(bytes, display) {
          calls++;
          assert.equal(display, 'hex');
          assert.deepEqual(bytes, canonical);
          assert.notEqual(bytes, canonical);
          assert.equal(bytes.at(-1), network === 'mainnet' ? 1 : 2);
          return { signature: new Uint8Array(sign(null, bytes, signer)) };
        } };
        const signed = await signWithWallet(wallet, canonical);
        const tx = await finalizeRegistration(prepared, signed.signature, key, operation);
        assert.equal(calls, 1);
        assert.equal(tx.actions[0].agentWalletCreation.d, operation === 'revoke');
        assert.equal(tx.account, owner);
        assert.equal(tx.nonce, prepared.nonce);
        assert.match(tx.nonce, /^\d+$/);
      } finally { prepared.free(); }
    }
  }
});

test('wallet refusal preserves canonical bytes and never retries signing', async () => {
  const bytes = Uint8Array.of(0, 255, 128, 0, 2);
  const original = Uint8Array.from(bytes);
  let calls = 0;
  await assert.rejects(() => signWithWallet({ async signMessage(message) { calls++; message.fill(0); throw { code: -32000 }; } }, bytes));
  assert.equal(calls, 1);
  assert.deepEqual(bytes, original);
});
test('Wallet Standard signatures finalize through the real BULK SDK on both networks', async () => {
  const account = { address: owner, publicKey: publicKeyBytes(owner), chains: ['solana:mainnet'], features: ['solana:signMessage'] };
  const wallet = { version: '1.0.0', name: 'Test wallet', chains: ['solana:mainnet'], accounts: [account], features: {
    'standard:connect': { version: '1.0.0', async connect() { return { accounts: [account] }; } },
    'standard:events': { version: '1.0.0', on() { return () => {}; } },
    'solana:signMessage': { version: '1.0.0', async signMessage({ message }) { return [{ signedMessage: message, signature: new Uint8Array(sign(null, message, signer)), signatureType: 'ed25519' }]; } },
  } };
  const [connection] = await standardWalletOption(wallet).connect();
  for (const network of ['testnet', 'mainnet']) {
    const key = await generateKey(network, owner, owner);
    const prepared = await prepareRegistration(key);
    try {
      const signed = await signWithWallet(connection, prepared.messageBytes);
      const tx = await finalizeRegistration(prepared, signed.signature, key);
      assert.equal(tx.signer, owner);
      assert.equal(tx.account, owner);
      assert.deepEqual(tx.actions, [{ agentWalletCreation: { a: key.publicKey, d: false } }]);
    } finally { prepared.free(); }
  }
});
test('plain recovery files still pass full keypair and owner signature validation before use', async () => {
  const key = await generateKey('testnet', owner, owner);
  const prepared = await prepareRegistration(key);
  try {
    const request = await finalizeRegistration(prepared, new Uint8Array(sign(null, prepared.messageBytes, signer)), key);
    const attempt = { operation: 'register', request };
    const restored = await decryptVault(exportBackup(key, attempt), '', true);
    await validateKeypair(restored.key);
    await validateSubmission(restored.key, restored.submission);
    // Same-length valid base58 signature from another message passes file shape,
    // but must still fail the application's signature validation.
    const other = await prepareRegistration(key, 'revoke');
    try {
      const otherRequest = await finalizeRegistration(other, new Uint8Array(sign(null, other.messageBytes, signer)), key, 'revoke');
      const forged = await decryptVault(exportBackup(key, { operation: 'register', request: { ...request, signature: otherRequest.signature } }), '', true);
      await assert.rejects(() => validateSubmission(forged.key, forged.submission), /signature does not match/);
    } finally { other.free(); }
  } finally { prepared.free(); }
});

test('authorization failures identify the failing boundary without exposing raw inputs', () => {
  const secret = 'do-not-expose-key-or-request';
  for (const step of ['account', 'prepare', 'wallet', 'verify', 'readback']) {
    const error = authorizationError(new TypeError(secret), step);
    assert.equal(error.message.includes(secret), false);
    assert.notEqual(error.message, 'Action failed.');
    if (step === 'readback') assert.equal(error.message.includes('Request not sent'), false);
    else assert.ok(error.message.includes('Request not sent'));
  }
  assert.match(authorizationError({ code: -32002, message: secret }, 'wallet', 'Phantom').message, /Another Phantom approval/);
  assert.match(authorizationError({ code: -32000, message: secret }, 'wallet', 'Phantom').message, /Phantom -32000/);
  assert.match(authorizationError({ code: 4100 }, 'wallet').message, /not authorized/);
  assert.match(authorizationError({ code: 4900 }, 'wallet').message, /disconnected/);
  assert.match(authorizationError(new DOMException(secret, 'NotSupportedError'), 'verify').message, /cannot verify Ed25519/);
  assert.equal(authorizationError({ name: secret, code: secret, message: secret }, 'prepare').message.includes(secret), false);
  const known = new BulkError('The selected wallet changed.');
  assert.equal(authorizationError(known, 'wallet'), known);
});
