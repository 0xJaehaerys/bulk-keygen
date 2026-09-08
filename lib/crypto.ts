import type { AgentKey, AgentOperation, Network, Submission, SignatureMode } from './bulk.ts';
import { NETWORKS, BulkError, assertAgentAction, assertRegistrationEnvelope, publicKeyBytes, signatureMode } from './bulk.ts';
import bs58 from 'bs58';
import type { WasmPreparedMessage } from 'bulk-keychain-wasm';
let sdkPromise: Promise<typeof import('bulk-keychain-wasm')> | undefined;
export function loadSdk() {
  sdkPromise ??= (async () => {
    const [sdk, { default: wasmUrl }] = await Promise.all([import('bulk-keychain-wasm'), import('bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm?url')]);
    await sdk.default({ module_or_path: wasmUrl });
    return sdk;
  })().catch(error => { sdkPromise = undefined; throw error; });
  return sdkPromise;
}
export async function generateKey(network: Network, account: string, owner: string): Promise<AgentKey> {
  publicKeyBytes(account); publicKeyBytes(owner);
  const sdk = await loadSdk();
  const pair = new sdk.WasmKeypair();
  try { return { network, account, owner, publicKey: pair.pubkey, secretKey: pair.toBase58(), createdAt: new Date().toISOString() }; } finally { pair.free(); }
}
export async function validateKeypair(key: AgentKey): Promise<void> {
  const bytes = bs58.decode(key.secretKey);
  if (bytes.length !== 64) throw new BulkError('The file must contain a 64-byte agent keypair.');
  const sdk = await loadSdk();
  const pair = sdk.WasmKeypair.fromBytes(bytes.slice(0, 32));
  try {
    if (pair.pubkey !== key.publicKey || pair.toBase58() !== key.secretKey) throw new BulkError('The public key does not match the agent private key.');
  } finally { pair.free(); bytes.fill(0); }
}
export async function prepareRegistration(key: AgentKey, operation: AgentOperation = 'register', nonce?: string): Promise<WasmPreparedMessage> {
  const sdk = await loadSdk();
  const prepared = sdk.prepareAgentWallet(key.publicKey, operation === 'revoke', { signatureDomain: NETWORKS[key.network].domain, account: key.account, signer: key.owner, ...(nonce ? { nonce } : {}) });
  try {
    const bytes = prepared.messageBytes;
    // Signature domain is the last canonical byte. Endpoints and domains are pinned together.
    if (bytes[bytes.length - 1] !== (key.network === 'mainnet' ? 1 : 2) || prepared.account !== key.account || prepared.signer !== key.owner) throw new BulkError('The network or owner in the request does not match.');
    assertAgentAction(prepared.actions, key.publicKey, operation);
    return prepared;
  } catch (error) { prepared.free(); throw error; }
}
export function registrationMessage(prepared: WasmPreparedMessage, key: AgentKey, operation: AgentOperation = 'register', mode: SignatureMode = 'raw'): Uint8Array {
  const selected = signatureMode(mode);
  if (prepared.account !== key.account || prepared.signer !== key.owner || prepared.messageBytes.at(-1) !== (key.network === 'mainnet' ? 1 : 2)) throw new BulkError('The signing context does not match.');
  assertAgentAction(prepared.actions, key.publicKey, operation);
  if (selected === 'base58') {
    // BULK's legacy text verifier accepts one owner-signed agent action only.
    // Never use this encoding to broaden a subaccount request to its parent.
    if (key.account !== key.owner) throw new BulkError('Text signing is only supported for the main account.');
    return new TextEncoder().encode(bs58.encode(prepared.messageBytes));
  }
  return Uint8Array.from(prepared.messageBytes);
}
export async function finalizeRegistration(prepared: WasmPreparedMessage, signature: Uint8Array, key: AgentKey, operation: AgentOperation = 'register', mode: SignatureMode = 'raw') {
  if (signature.length !== 64) throw new BulkError('Your wallet returned an invalid signature.');
  const publicKey = await crypto.subtle.importKey('raw', Uint8Array.from(publicKeyBytes(key.owner)), { name: 'Ed25519' }, false, ['verify']);
  const message = registrationMessage(prepared, key, operation, mode);
  const valid = await crypto.subtle.verify('Ed25519', publicKey, Uint8Array.from(signature), Uint8Array.from(message));
  if (!valid) throw new BulkError('The signature does not match the wallet or request. Request not sent.');
  const finalized = prepared.finalizeBytes(signature);
  // Current WASM returns native JSON actions; tolerate serialized SDK representation only here.
  if (typeof finalized.actions === 'string') finalized.actions = JSON.parse(finalized.actions);
  return assertRegistrationEnvelope(finalized, key, operation);
}
export async function validateSubmission(key: AgentKey, submission: Submission) {
  const tx = assertRegistrationEnvelope(submission.request, key, submission.operation);
  const prepared = await prepareRegistration(key, submission.operation, tx.nonce);
  try { await finalizeRegistration(prepared, bs58.decode(tx.signature), key, submission.operation, signatureMode(submission.signatureMode)); }
  finally { prepared.free(); }
}
