import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import init, { WasmKeypair, prepareAgentWallet } from 'bulk-keychain-wasm';
import bs58 from 'bs58';
import { createPrivateKey, sign } from 'node:crypto';
import { exportBackup, encryptVault, decryptVault, parseKeyExport, appendSubmissionHistory, MAX_VAULT_BYTES, MAX_BACKUP_PLAINTEXT_BYTES, MAX_SUBMISSION_HISTORY, VAULT_ITERATIONS } from '../lib/vault.ts';
import { assertRegistrationEnvelope, exportKey, submitRegistration } from '../lib/bulk.ts';

await init({ module_or_path: readFileSync(new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url)) });
const pair = new WasmKeypair(), owner = new WasmKeypair();
const key = { network: 'testnet', owner: owner.pubkey, account: owner.pubkey, publicKey: pair.pubkey, secretKey: pair.toBase58(), createdAt: '2026-09-08T00:00:00Z' };
const signer = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), owner.secretKey()]), format: 'der', type: 'pkcs8' });
pair.free(); owner.free();
const password = 'disposable vault test phrase 93';
function submission(operation, nonce = '1788816000000000123') {
  const prepared = prepareAgentWallet(key.publicKey, operation === 'revoke', { signatureDomain: key.network, account: key.account, signer: key.owner, nonce });
  try { return { operation, request: assertRegistrationEnvelope(prepared.finalizeBytes(sign(null, prepared.messageBytes, signer)), key, operation) }; }
  finally { prepared.free(); }
}

test('vault round trip encrypts metadata, secret and original signed recovery envelope', async () => {
  const pending = submission('register');
  const encrypted = await encryptVault(key, password, pending);
  for (const sensitive of [key.secretKey, key.publicKey, key.owner, pending.request.signature, password]) assert.equal(encrypted.includes(sensitive), false);
  assert.deepEqual(await decryptVault(encrypted, password), { key, submission: pending, history: [] });
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
  assert.deepEqual(await decryptVault(exportKey(key), '', true), { key, submission: null, history: [] });
});
test('ordinary JSON preserves the exact key and signed recovery request without a password', async () => {
  for (const attempt of [null, submission('register'), submission('revoke')]) {
    const document = exportBackup(key, attempt);
    await assert.rejects(() => decryptVault(document, ''), /unencrypted/);
    const restored = await decryptVault(document, '', true);
    assert.deepEqual(restored, { key, submission: attempt, history: [] });
    assert.equal(JSON.parse(document).format, 'bulk-agent-backup-v2');
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
    { extra: true }, { format: 'bulk-agent-backup-v3' }, { submission: undefined }, { history: undefined }, { history: null },
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
  assert.deepEqual(await decryptVault(await encryptVault(key, password, attempt), password), { key, submission: attempt, history: [] });
});
test('explicit recovery can send the identical envelope without changing nonce or signature', async () => {
  const attempt = submission('register'), calls = [];
  const mock = async (_url, options) => { calls.push(options.body); throw new DOMException('timeout', 'TimeoutError'); };
  await assert.rejects(() => submitRegistration(key.network, attempt.request, mock));
  assert.equal(calls.length, 1);
  await assert.rejects(() => submitRegistration(key.network, attempt.request, mock));
  assert.equal(calls.length, 2); assert.equal(calls[0], calls[1]);
});

async function legacyEncrypted(plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const encryptionKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: VAULT_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('bulk-agent-vault-v1'), tagLength: 128 }, encryptionKey, new TextEncoder().encode(plaintext));
  return JSON.stringify({ format: 'bulk-agent-vault-v1', kdf: 'PBKDF2-SHA256', iterations: VAULT_ITERATIONS, cipher: 'AES-256-GCM', salt: Buffer.from(salt).toString('base64'), iv: Buffer.from(iv).toString('base64'), ciphertext: Buffer.from(ciphertext).toString('base64') });
}
test('v1 JSON and encrypted backups import without inventing earlier request history', async () => {
  const attempt = submission('register');
  const legacy = JSON.stringify({ format: 'bulk-agent-backup-v1', key: JSON.parse(exportKey(key)), submission: attempt });
  for (const result of [await decryptVault(legacy, '', true), await decryptVault(await legacyEncrypted(legacy), password)]) {
    assert.deepEqual(result, { key, submission: attempt, history: [] });
    assert.equal(JSON.parse(exportBackup(result.key, result.submission, result.history)).format, 'bulk-agent-backup-v2');
  }
});
test('v2 history preserves earlier authorizations exactly through plain and encrypted recovery', async () => {
  const earlier = submission('register', '1'), current = submission('revoke', '2');
  const history = appendSubmissionHistory([], earlier);
  const plain = exportBackup(key, current, history), encrypted = await encryptVault(key, password, current, history);
  for (const result of [await decryptVault(plain, '', true), await decryptVault(encrypted, password)]) {
    assert.deepEqual(result, { key, submission: current, history: [earlier] });
    assert.equal(JSON.stringify(result.history[0].request), JSON.stringify(earlier.request));
  }
  assert.equal(encrypted.includes(earlier.request.signature), false);
  assert.equal(encrypted.includes(key.secretKey), false);
});
test('history append deduplicates only identical requests and never evicts at capacity', () => {
  const previous = submission('register', '1');
  const once = appendSubmissionHistory([], previous);
  assert.deepEqual(appendSubmissionHistory(once, { ...previous, signatureMode: 'raw' }), once);
  assert.deepEqual(appendSubmissionHistory(once, null), once);
  assert.notEqual(appendSubmissionHistory(once, null), once);
  const anotherMode = { ...previous, signatureMode: 'base58' };
  assert.equal(appendSubmissionHistory(once, anotherMode).length, 2);
  const full = Array.from({ length: MAX_SUBMISSION_HISTORY }, (_, i) => submission(i % 2 ? 'revoke' : 'register', String(i + 1)));
  assert.deepEqual(appendSubmissionHistory(full, full[0]), full);
  assert.throws(() => appendSubmissionHistory(full, submission('revoke', '100')), /history is full/);
  assert.equal(full.length, MAX_SUBMISSION_HISTORY);
});
test('every historical request is structurally bound to the same key and account', async () => {
  const earlier = submission('register', '1'), current = submission('revoke', '2');
  const raw = JSON.parse(exportBackup(key, current, [earlier]));
  for (const mutation of [
    { ...earlier, operation: 'transfer' },
    { ...earlier, signatureMode: 'unknown' },
    { ...earlier, request: { ...earlier.request, signer: key.publicKey } },
    { ...earlier, request: { ...earlier.request, account: key.publicKey } },
    { ...earlier, request: { ...earlier.request, actions: [{ agentWalletCreation: { a: key.owner, d: false } }] } },
    { ...earlier, request: { ...earlier.request, nonce: '01' } },
    { ...earlier, request: { ...earlier.request, signature: 'bad' } },
  ]) {
    await assert.rejects(() => decryptVault(JSON.stringify({ ...raw, history: [mutation] }), '', true));
    assert.throws(() => exportBackup(key, current, [mutation]));
  }
});
test('noncanonical signed nonces cannot enter import or export recovery files', async () => {
  const canonical = submission('register', '1');
  for (const nonce of ['01', '0'.repeat(24000) + '1', '0', '18446744073709551616']) {
    const invalid = { ...canonical, request: { ...canonical.request, nonce } };
    const legacy = JSON.stringify({ format: 'bulk-agent-backup-v1', key: JSON.parse(exportKey(key)), submission: invalid });
    await assert.rejects(() => decryptVault(legacy, '', true));
    assert.throws(() => exportBackup(key, invalid));
    await assert.rejects(() => encryptVault(key, password, invalid));
  }
});
test('maximum bounded history restores through both formats and overflow fails before encryption', async () => {
  const history = Array.from({ length: MAX_SUBMISSION_HISTORY }, (_, i) => submission(i % 2 ? 'revoke' : 'register', String(i + 1)));
  const current = submission('revoke', '18446744073709551615');
  const plain = exportBackup(key, current, history), encrypted = await encryptVault(key, password, current, history);
  assert.ok(Buffer.byteLength(plain) <= MAX_BACKUP_PLAINTEXT_BYTES);
  assert.ok(Buffer.byteLength(encrypted) <= MAX_VAULT_BYTES);
  assert.deepEqual(await decryptVault(plain, '', true), { key, submission: current, history });
  assert.deepEqual(await decryptVault(encrypted, password), { key, submission: current, history });
  const tooMany = [...history, current];
  assert.throws(() => exportBackup(key, current, tooMany), /history/);
  await assert.rejects(() => encryptVault(key, 'short', current, tooMany), /history/);
  const raw = JSON.parse(plain); raw.history = tooMany;
  await assert.rejects(() => decryptVault(JSON.stringify(raw), '', true), /history/);
});
