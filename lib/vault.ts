import bs58 from 'bs58';
import { BulkError, NETWORKS, assertRegistrationEnvelope, exportKey, publicKeyBytes, record, signatureMode } from './bulk.ts';
import type { AgentKey, KeyBackup, Submission } from './bulk.ts';

export const MAX_VAULT_BYTES = 32768;
export const MAX_BACKUP_PLAINTEXT_BYTES = 16368;
export const MAX_SUBMISSION_HISTORY = 16;
const MAX_CIPHERTEXT_BYTES = MAX_BACKUP_PLAINTEXT_BYTES + 16;
export const VAULT_ITERATIONS = 600000;
const FORMAT = 'bulk-agent-vault-v1';
const encoder = new TextEncoder();
const aad = encoder.encode(FORMAT);

function exact(value: Record<string, unknown>, fields: string[]) {
  if (Object.keys(value).length !== fields.length || fields.some(k => !(k in value))) throw new BulkError('Unsupported key file format.');
}
function parse(text: string): Record<string, unknown> {
  if (encoder.encode(text).length > MAX_VAULT_BYTES) throw new BulkError('Key file too large. Maximum size: 32 KB.');
  try { return record(JSON.parse(text)); } catch { throw new BulkError('Could not read the key JSON file.'); }
}
function toBase64(bytes: Uint8Array) { return btoa(String.fromCharCode(...bytes)); }
function fromBase64(value: unknown, size?: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new BulkError('Invalid encrypted file.');
  const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  if (toBase64(bytes) !== value || (size !== undefined && bytes.length !== size)) throw new BulkError('Invalid encrypted file.');
  return bytes;
}
function passwordBytes(password: string) {
  if (password.length < 12 || password.length > 1024) throw new BulkError('Use a unique passphrase with 12–1024 characters.');
  return encoder.encode(password);
}
async function derive(password: string, salt: Uint8Array<ArrayBuffer>) {
  const bytes = passwordBytes(password);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: VAULT_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}

// This validates file structure and fixed bindings. Call validateKeypair before using it.
export function parseKeyExport(value: unknown): AgentKey {
  const v = record(value);
  exact(v, ['format', 'network', 'api_url', 'signature_domain', 'account_public_key', 'owner_public_key', 'agent_public_key', 'agent_private_key_base58', 'private_key_format', 'created_at']);
  if (v.format !== 'bulk-agent-key-v1' || (v.network !== 'testnet' && v.network !== 'mainnet')) throw new BulkError('This is not a BULK Keygen file.');
  if (v.api_url !== NETWORKS[v.network].api || v.signature_domain !== NETWORKS[v.network].domain || v.private_key_format !== 'base58-64-byte-ed25519-keypair') throw new BulkError('The network or key format in the file does not match.');
  for (const name of ['account_public_key', 'owner_public_key', 'agent_public_key']) {
    if (typeof v[name] !== 'string' || (v[name] as string).length > 44) throw new BulkError('Invalid public address in the file.');
    publicKeyBytes(v[name] as string);
  }
  if (typeof v.agent_private_key_base58 !== 'string' || v.agent_private_key_base58.length > 88) throw new BulkError('Invalid agent private key in the file.');
  try { if (bs58.decode(v.agent_private_key_base58).length !== 64) throw Error(); } catch { throw new BulkError('Invalid agent private key in the file.'); }
  if (typeof v.created_at !== 'string' || v.created_at.length > 40 || !Number.isFinite(Date.parse(v.created_at))) throw new BulkError('Invalid key creation date.');
  return { network: v.network, account: v.account_public_key as string, owner: v.owner_public_key as string, publicKey: v.agent_public_key as string, secretKey: v.agent_private_key_base58, createdAt: v.created_at };
}
type SubmissionBinding = Pick<AgentKey, 'account' | 'owner' | 'publicKey'>;
function submissionBinding(value: unknown): SubmissionBinding {
  const s = record(value), tx = record(s.request);
  if (!Array.isArray(tx.actions) || tx.actions.length !== 1) throw new BulkError('Only one agent action is allowed.');
  const agent = record(record(tx.actions[0]).agentWalletCreation).a;
  for (const address of [tx.account, tx.signer, agent]) {
    if (typeof address !== 'string' || address.length > 44) throw new BulkError('Invalid public address in request history.');
    publicKeyBytes(address);
  }
  return { account: tx.account as string, owner: tx.signer as string, publicKey: agent as string };
}
function parseSubmission(value: unknown, key: SubmissionBinding): Submission {
  const s = record(value); exact(s, ['operation', 'request', ...('signatureMode' in s ? ['signatureMode'] : [])]);
  if (s.operation !== 'register' && s.operation !== 'revoke') throw new BulkError('Invalid action in the backup.');
  const mode = signatureMode(s.signatureMode);
  if (mode === 'base58' && key.account !== key.owner) throw new BulkError('Text signing is only supported for the main account.');
  return { operation: s.operation, request: assertRegistrationEnvelope(s.request, key, s.operation), ...('signatureMode' in s ? { signatureMode: mode } : {}) };
}
function parseHistory(value: unknown, key?: SubmissionBinding): Submission[] {
  if (!Array.isArray(value) || value.length > MAX_SUBMISSION_HISTORY) throw new BulkError(`Request history must contain at most ${MAX_SUBMISSION_HISTORY} entries. Keep the existing backup; no requests were discarded.`);
  let binding = key;
  return value.map(entry => {
    binding ??= submissionBinding(entry);
    return parseSubmission(entry, binding);
  });
}
function requestIdentity(value: Submission): string {
  return JSON.stringify({ operation: value.operation, request: value.request, signatureMode: signatureMode(value.signatureMode) });
}
// Call before preparing another signature. A full history must never evict an
// earlier authorization whose outcome may still be uncertain.
export function appendSubmissionHistory(history: Submission[], previous: Submission | null): Submission[] {
  const result = parseHistory(history);
  if (previous === null) return result;
  const entry = parseSubmission(previous, submissionBinding(result[0] ?? previous));
  if (result.some(saved => requestIdentity(saved) === requestIdentity(entry))) return result;
  if (result.length === MAX_SUBMISSION_HISTORY) throw new BulkError(`Request history is full (${MAX_SUBMISSION_HISTORY} entries). Keep the existing backup; no requests were discarded.`);
  return [...result, entry];
}
function parseBackup(backup: Record<string, unknown>): KeyBackup {
  if (backup.format !== 'bulk-agent-backup-v1' && backup.format !== 'bulk-agent-backup-v2') throw new BulkError('Unsupported backup version.');
  exact(backup, ['format', 'key', 'submission', ...(backup.format === 'bulk-agent-backup-v2' ? ['history'] : [])]);
  const key = parseKeyExport(backup.key);
  const submission = backup.submission === null ? null : parseSubmission(backup.submission, key);
  const history = backup.format === 'bulk-agent-backup-v2' ? parseHistory(backup.history, key) : [];
  return { key, submission, history };
}
export function exportBackup(key: AgentKey, submission: Submission | null = null, history: Submission[] = []): string {
  const parsed = parseBackup({ format: 'bulk-agent-backup-v2', key: JSON.parse(exportKey(key)), submission, history });
  const text = JSON.stringify({ format: 'bulk-agent-backup-v2', key: JSON.parse(exportKey(parsed.key)), submission: parsed.submission, history: parsed.history }, null, 2);
  if (encoder.encode(text).length > MAX_BACKUP_PLAINTEXT_BYTES) throw new BulkError('Backup is too large to restore. Keep the existing backup; no requests were discarded.');
  return text;
}
export async function encryptVault(key: AgentKey, password: string, submission: Submission | null = null, history: Submission[] = []): Promise<string> {
  // Validate the complete restoreable payload before KDF work or encryption.
  const plaintext = encoder.encode(exportBackup(key, submission, history));
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptionKey = await derive(password, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, plaintext);
    const text = JSON.stringify({ format: FORMAT, kdf: 'PBKDF2-SHA256', iterations: VAULT_ITERATIONS, cipher: 'AES-256-GCM', salt: toBase64(salt), iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) }, null, 2);
    if (encoder.encode(text).length > MAX_VAULT_BYTES) throw new BulkError('Encrypted backup is too large to restore. Keep the existing backup.');
    return text;
  } finally { plaintext.fill(0); }
}
export async function decryptVault(text: string, password: string, allowPlaintext = false): Promise<KeyBackup> {
  const v = parse(text);
  if (v.format === 'bulk-agent-key-v1' || v.format === 'bulk-agent-backup-v1' || v.format === 'bulk-agent-backup-v2') {
    if (!allowPlaintext) throw new BulkError('This file is unencrypted. Enable plaintext import to continue.');
    return v.format === 'bulk-agent-key-v1' ? { key: parseKeyExport(v), submission: null, history: [] } : parseBackup(v);
  }
  exact(v, ['format', 'kdf', 'iterations', 'cipher', 'salt', 'iv', 'ciphertext']);
  if (v.format !== FORMAT || v.kdf !== 'PBKDF2-SHA256' || v.iterations !== VAULT_ITERATIONS || v.cipher !== 'AES-256-GCM') throw new BulkError('Unsupported encrypted file version.');
  const salt = fromBase64(v.salt, 16), iv = fromBase64(v.iv, 12), ciphertext = fromBase64(v.ciphertext);
  if (ciphertext.length < 17 || ciphertext.length > MAX_CIPHERTEXT_BYTES) throw new BulkError('Invalid encrypted file.');
  const encryptionKey = await derive(password, salt);
  let plaintext: ArrayBuffer;
  try { plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, ciphertext); }
  catch { throw new BulkError('Incorrect password or damaged file.'); }
  try {
    return parseBackup(parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)));
  }
  finally { new Uint8Array(plaintext).fill(0); }
}
