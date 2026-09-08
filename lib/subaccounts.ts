import bs58 from 'bs58';
import type { WasmPreparedMessage } from 'bulk-keychain-wasm';
import { BulkError, NETWORKS, apiRequest, assertOwner, normalizeSdkValue, publicKeyBytes, readAccount, record, validPublicKey } from './bulk.ts';
import type { FullAccount, Network } from './bulk.ts';
import { loadSdk } from './crypto.ts';

export interface CreateRequest {
  actions: [{ createSubAccount: { name: string } }];
  nonce: string; account: string; signer: string; signature: string;
}
export interface SubaccountRequest {
  format: 'bulk-subaccount-request-v1'; network: Network; owner: string; name: string;
  request: CreateRequest; address: string | null;
}
export function subaccountName(name: string): string {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new BulkError('Use 1–32 letters, numbers, hyphens or underscores.');
  return name;
}
function exact(v: Record<string, unknown>, fields: string[]) {
  if (Object.keys(v).length !== fields.length || fields.some(f => !(f in v))) throw new BulkError('Unexpected subaccount request fields.');
}
function assertCreateAction(raw: unknown, name: string) {
  const actions = normalizeSdkValue(raw);
  if (!Array.isArray(actions) || actions.length !== 1) throw new BulkError('Only one subaccount creation is allowed.');
  const action = record(actions[0]); exact(action, ['createSubAccount']);
  const create = record(action.createSubAccount); exact(create, ['name']);
  if (create.name !== subaccountName(name)) throw new BulkError('The subaccount name does not match.');
}
function assertNonce(nonce: unknown): asserts nonce is string {
  if (typeof nonce !== 'string' || !/^[1-9][0-9]{0,19}$/.test(nonce) || BigInt(nonce) > 18446744073709551615n) throw new BulkError('Invalid request nonce.');
}
export function assertCreateRequest(raw: unknown, owner: string, name: string): CreateRequest {
  publicKeyBytes(owner); subaccountName(name);
  const tx = record(normalizeSdkValue(raw)); exact(tx, ['actions', 'nonce', 'account', 'signer', 'signature']);
  assertNonce(tx.nonce); assertCreateAction(tx.actions, name);
  if (tx.account !== owner || tx.signer !== owner) throw new BulkError('Only the main account owner can create this subaccount.');
  if (typeof tx.signature !== 'string' || tx.signature.length > 88) throw new BulkError('Invalid wallet signature.');
  try { if (bs58.decode(tx.signature).length !== 64) throw Error(); } catch { throw new BulkError('Invalid wallet signature.'); }
  return { actions: [{ createSubAccount: { name } }], nonce: tx.nonce, account: owner, signer: owner, signature: tx.signature };
}
export async function prepareSubaccount(network: Network, owner: string, name: string, nonce?: string): Promise<WasmPreparedMessage> {
  publicKeyBytes(owner); subaccountName(name); if (nonce !== undefined) assertNonce(nonce);
  const sdk = await loadSdk();
  // Omit marginAmount entirely: this action creates an empty account and moves no funds.
  const prepared = sdk.prepareCreateSubAccount(name, { account: owner, signer: owner, signatureDomain: NETWORKS[network].domain, ...(nonce ? { nonce } : {}) });
  try {
    assertCreateAction(prepared.actions, name); assertNonce(prepared.nonce);
    if (prepared.account !== owner || prepared.signer !== owner || prepared.messageBytes.at(-1) !== (network === 'mainnet' ? 1 : 2)) throw new BulkError('The network or owner does not match.');
    return prepared;
  } catch (e) { prepared.free(); throw e; }
}
export async function finalizeSubaccount(prepared: WasmPreparedMessage, signature: Uint8Array, owner: string, name: string): Promise<CreateRequest> {
  if (signature.length !== 64) throw new BulkError('Invalid wallet signature.');
  const verifier = await crypto.subtle.importKey('raw', Uint8Array.from(publicKeyBytes(owner)), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', verifier, Uint8Array.from(signature), Uint8Array.from(prepared.messageBytes))) throw new BulkError('The signature does not match the owner or request. Request not sent.');
  const raw = prepared.finalizeBytes(signature);
  if (typeof raw.actions === 'string') raw.actions = JSON.parse(raw.actions);
  return assertCreateRequest(raw, owner, name);
}
export async function validateSubaccountRequest(value: SubaccountRequest) {
  const request = assertCreateRequest(value.request, value.owner, value.name);
  const prepared = await prepareSubaccount(value.network, value.owner, value.name, request.nonce);
  try { await finalizeSubaccount(prepared, bs58.decode(request.signature), value.owner, value.name); }
  finally { prepared.free(); }
}
export function exportSubaccountRequest(value: SubaccountRequest) { return JSON.stringify(value, null, 2); }
export async function importSubaccountRequest(text: string): Promise<SubaccountRequest> {
  if (new TextEncoder().encode(text).length > 8192) throw new BulkError('Creation request file too large. Maximum size: 8 KB.');
  let v: Record<string, unknown>;
  try { v = record(JSON.parse(text)); } catch { throw new BulkError('Could not read the creation request JSON.'); }
  exact(v, ['format', 'network', 'owner', 'name', 'request', 'address']);
  if (v.format !== 'bulk-subaccount-request-v1' || (v.network !== 'testnet' && v.network !== 'mainnet') || !validPublicKey(v.owner) || typeof v.name !== 'string') throw new BulkError('This is not a supported subaccount request.');
  if (v.address !== null && (!validPublicKey(v.address) || v.address === v.owner)) throw new BulkError('Invalid subaccount address.');
  const value: SubaccountRequest = { format: v.format, network: v.network, owner: v.owner, name: subaccountName(v.name), request: assertCreateRequest(v.request, v.owner, v.name), address: v.address as string | null };
  await validateSubaccountRequest(value);
  return value;
}
export function creationResult(body: unknown, attempt: SubaccountRequest): string | null {
  try {
    const b = record(body);
    if (b.status !== 'ok') return null;
    const response = record(b.response); if (response.type !== 'order') return null;
    const statuses = record(response.data).statuses;
    if (!Array.isArray(statuses) || statuses.length !== 1) return null;
    const row = record(statuses[0]);
    if (Object.keys(row).length !== 1) return null;
    const created = record(row.createSubAccount);
    if (created.master !== attempt.owner || created.name !== attempt.name || created.margin !== 0 || !validPublicKey(created.sub) || created.sub === attempt.owner) return null;
    return created.sub;
  } catch { return null; }
}
export async function submitSubaccount(attempt: SubaccountRequest, fetcher?: typeof fetch, beforeSend?: () => void): Promise<string | null> {
  await validateSubaccountRequest(attempt);
  const request = assertCreateRequest(attempt.request, attempt.owner, attempt.name);
  beforeSend?.();
  return creationResult(await apiRequest(attempt.network, '/order', request, fetcher), attempt);
}
export async function verifySubaccount(attempt: SubaccountRequest, address: string, fetcher?: typeof fetch, requireName = true): Promise<FullAccount> {
  const info = await readAccount(attempt.network, address, fetcher);
  assertOwner(info, address, attempt.owner);
  if (info.kind !== 'SubAccount' || ((requireName || info.name !== undefined) && info.name !== attempt.name)) throw new BulkError('Could not verify this subaccount name. Check the address in BULK and try again.');
  return info;
}
