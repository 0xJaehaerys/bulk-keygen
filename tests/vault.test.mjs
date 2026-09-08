import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import init, { WasmKeypair, prepareAgentWallet } from 'bulk-keychain-wasm';
import bs58 from 'bs58';
import { createPrivateKey, sign } from 'node:crypto';
import { exportBackup, encryptVault, decryptVault, parseKeyExport, MAX_VAULT_BYTES } from '../lib/vault.ts';
import { assertRegistrationEnvelope, exportKey, submitRegistration } from '../lib/bulk.ts';

await init({ module_or_path: readFileSync(new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url)) });
const pair = new WasmKeypair(), owner = new WasmKeypair();
const key = { network: 'testnet', owner: owner.pubkey, account: owner.pubkey, publicKey: pair.pubkey, secretKey: pair.toBase58(), createdAt: '2026-09-08T00:00:00Z' };
const signer = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), owner.secretKey()]), format: 'der', type: 'pkcs8' });
pair.free(); owner.free();
const password = 'disposable vault test phrase 93';
function submission(operation) {
  const prepared = prepareAgentWallet(key.publicKey, operation === 'revoke', { signatureDomain: key.network, account: key.account, signer: key.owner, nonce: '1788816000000000123' });
  try { return { operation, request: assertRegistrationEnvelope(prepared.finalizeBytes(sign(null, prepared.messageBytes, signer)), key, operation) }; }
  finally { prepared.free(); }
}

test('vault round trip encrypts metadata, secret and original signed recovery envelope', async () => {
  const pending = submission('register');
  const encrypted = await encryptVault(key, password, pending);
  for (const sensitive of [key.secretKey, key.publicKey, key.owner, pending.request.signature, password]) assert.equal(encrypted.includes(sensitive), false);
  assert.deepEqual(await decryptVault(encrypted, password), { key, submission: pending });
  const second = JSON.parse(await encryptVault(key, password));
  const first = JSON.parse(encrypted);
  assert.notEqual(first.salt, second.salt); assert.notEqual(first.iv, second.iv); assert.notEqual(first.ciphertext, second.ciphertext);
});
test('authentication rejects wrong password and ciphertext, salt or IV changes', async () => {
  const encrypted = await encryptVault(key, password);
  await assert.rejects(() => decryptVault(encrypted, 'a different long password'), /Incorrect password or damaged file/);
  for (const field of ['ciphertext', 'salt', 'iv']) {
    const changed = JSON.parse(encrypted), bytes = Buffer.from(changed[field], 'base64'); bytes[0] ^= 1; changed[field] = bytes.toString('base64');
    await assert.rejects(() => decryptVault(JSON.stringify(changed), password), /Incorrect password or damaged file/);
  }
});
test('vault rejects oversized files, weak passwords and hostile KDF/header parameters', async () => {
  await assert.rejects(() => encryptVault(key, 'short'));
  await assert.rejects(() => decryptVault(' '.repeat(MAX_VAULT_BYTES + 1), password), /too large/);
  const encrypted = JSON.parse(await encryptVault(key, password));
  for (const change of [{ iterations: 1 }, { iterations: 9999999999 }, { cipher: 'AES-CBC' }, { format: 'bulk-agent-vault-v2' }, { iv: 'not-base64' }, { salt: 'AA==' }, { url: 'https://evil.example' }]) {
    await assert.rejects(() => decryptVault(JSON.stringify({ ...encrypted, ...change }), password));
  }
});
test('legacy plaintext requires explicit consent and does not pretend to retain request status', async () => {
  await assert.rejects(() => decryptVault(exportKey(key), ''), /unencrypted/);
  assert.deepEqual(await decryptVault(exportKey(key), '', true), { key, submission: null });
});
test('ordinary JSON preserves the exact key and signed recovery request without a password', async () => {
  for (const attempt of [null, submission('register'), submission('revoke')]) {
    const document = exportBackup(key, attempt);
    await assert.rejects(() => decryptVault(document, ''), /unencrypted/);
    const restored = await decryptVault(document, '', true);
    assert.deepEqual(restored, { key, submission: attempt });
    assert.equal(JSON.parse(document).format, 'bulk-agent-backup-v1');
    assert.equal('registration_status' in JSON.parse(document), false);
    if (attempt) {
      const calls = [];
      const mock = async (_url, options) => { calls.push(options.body); throw new DOMException('timeout', 'TimeoutError'); };
      await assert.rejects(() => submitRegistration(key.network, attempt.request, mock));
      await assert.rejects(() => submitRegistration(restored.key.network, restored.submission.request, mock));
      assert.equal(calls[0], calls[1]);
    }
  }
});
test('ordinary JSON import retains strict metadata and recovery envelope validation', async () => {
  const raw = JSON.parse(exportBackup(key, submission('register')));
  for (const change of [
    { extra: true }, { format: 'bulk-agent-backup-v2' }, { submission: undefined },
    { key: { ...raw.key, api_url: 'https://evil.example' } },
    { submission: { ...raw.submission, operation: 'transfer' } },
    { submission: { ...raw.submission, request: { ...raw.submission.request, account: key.publicKey } } },
    { submission: { ...raw.submission, request: { ...raw.submission.request, nonce: Number(raw.submission.request.nonce) } } },
  ]) await assert.rejects(() => decryptVault(JSON.stringify({ ...raw, ...change }), '', true));
});
test('import cannot change pinned API, domain, account format or private key format', () => {
  const raw = JSON.parse(exportKey(key));
  for (const change of [{ api_url: 'https://evil.example' }, { network: '__proto__' }, { signature_domain: 'mainnet' }, { account_public_key: 'bad' }, { agent_private_key_base58: key.publicKey }, { private_key_format: 'seed' }, { created_at: 'invalid' }]) {
    assert.throws(() => parseKeyExport({ ...raw, ...change }));
  }
});
test('keypair validation must compare reconstructed full pair, not just SDK publicKey', () => {
  const corrupt = bs58.decode(key.secretKey); corrupt[63] ^= 1;
  const restored = WasmKeypair.fromBytes(corrupt.slice(0, 32));
  try { assert.equal(restored.pubkey, key.publicKey); assert.notEqual(restored.toBase58(), bs58.encode(corrupt)); }
  finally { restored.free(); corrupt.fill(0); }
});
test('revocation binds d:true and cannot pass a registration allowlist', async () => {
  const attempt = submission('revoke');
  assert.equal(attempt.request.actions[0].agentWalletCreation.d, true);
  assert.throws(() => assertRegistrationEnvelope(attempt.request, key));
  assert.deepEqual(await decryptVault(await encryptVault(key, password, attempt), password), { key, submission: attempt });
});
test('explicit recovery can send the identical envelope without changing nonce or signature', async () => {
  const attempt = submission('register'), calls = [];
  const mock = async (_url, options) => { calls.push(options.body); throw new DOMException('timeout', 'TimeoutError'); };
  await assert.rejects(() => submitRegistration(key.network, attempt.request, mock));
  assert.equal(calls.length, 1);
  await assert.rejects(() => submitRegistration(key.network, attempt.request, mock));
  assert.equal(calls.length, 2); assert.equal(calls[0], calls[1]);
});
