import bs58 from 'bs58';

// Official API introduction + changelog v1.0.19 (2026-09-02).
// Keep endpoints and signing domains paired; never take endpoints from URL input.
export const NETWORKS = {
  testnet: { label: 'Testnet', api: 'https://exchange-api.bulk.trade/api/v1', domain: 'testnet' },
  mainnet: { label: 'Mainnet', api: 'https://mainnet-api1.bulk.trade/api/v1', domain: 'mainnet' },
} as const;
export type Network = keyof typeof NETWORKS;
export interface FullAccount { kind: 'MasterEOA' | 'SubAccount'; parent: string | null; name?: string; subAccounts: { pubkey: string }[] | null; authorizedAgentWallets: string[] | null }
export interface AgentKey { network: Network; account: string; owner: string; publicKey: string; secretKey: string; createdAt: string }
export interface Registration { actions: { agentWalletCreation: { a: string; d: boolean } }[]; nonce: string; account: string; signer: string; signature: string }
export type AgentOperation = 'register' | 'revoke';
export type SignatureMode = 'raw' | 'base58';
// Missing mode means raw for backups made before text signing was supported.
export interface Submission { operation: AgentOperation; request: Registration; signatureMode?: SignatureMode }
export function signatureMode(value: unknown): SignatureMode {
  if (value === undefined || value === 'raw') return 'raw';
  if (value === 'base58') return 'base58';
  throw new BulkError('Unsupported signing mode.');
}
export interface KeyBackup { key: AgentKey; submission: Submission | null }
export type RegistrationState = 'created' | 'signing' | 'signed' | 'submitting' | 'pending' | 'active' | 'rejected' | 'absent' | 'revoked';
export class BulkError extends Error { code: string; constructor(message: string, code = 'BULK_ERROR') { super(message); this.name = 'BulkError'; this.code = code; } }
export function record(v: unknown): Record<string, unknown> { if (!v || typeof v !== 'object' || Array.isArray(v)) throw new BulkError('BULK returned an unexpected response.'); return v as Record<string, unknown>; }
export function publicKeyBytes(key: string): Uint8Array { try { const bytes = bs58.decode(key); if (bytes.length !== 32) throw Error(); return bytes; } catch { throw new BulkError('Invalid public address.'); } }
export function validPublicKey(v: unknown): v is string { if (typeof v !== 'string') return false; try { publicKeyBytes(v); return true; } catch { return false; } }
export function parseAccount(body: unknown): FullAccount {
  if (!Array.isArray(body) || body.length !== 1) throw new BulkError('Could not verify account details.');
  const a = record(record(body[0]).fullAccount);
  if (a.kind !== 'MasterEOA' && a.kind !== 'SubAccount') throw new BulkError('Only external-wallet accounts and their subaccounts are supported.');
  if (a.kind === 'SubAccount' ? !validPublicKey(a.parent) : a.parent !== undefined && a.parent !== null) throw new BulkError('Could not verify the account owner.');
  if (a.authorizedAgentWallets !== undefined && (!Array.isArray(a.authorizedAgentWallets) || !a.authorizedAgentWallets.every(validPublicKey))) throw new BulkError('BULK returned invalid registered agents.');
  if (a.subAccounts !== undefined && (!Array.isArray(a.subAccounts) || !a.subAccounts.every(s => validPublicKey(record(s).pubkey)))) throw new BulkError('BULK returned invalid subaccounts.');
  // Live responses omit these optional fields. An omitted list is unknown, not empty.
  return { kind: a.kind, parent: a.kind === 'MasterEOA' ? null : a.parent as string, subAccounts: a.subAccounts === undefined ? null : a.subAccounts as { pubkey: string }[], authorizedAgentWallets: a.authorizedAgentWallets === undefined ? null : a.authorizedAgentWallets as string[], ...(typeof a.name === 'string' ? { name: a.name } : {}) };
}
export function agentMembership(account: FullAccount, agent: string): boolean | null {
  return account.authorizedAgentWallets?.includes(agent) ?? null;
}
export function readbackState(account: FullAccount, agent: string, intent: AgentOperation | null): 'active' | 'revoked' | 'absent' | 'pending' {
  const present = agentMembership(account, agent);
  if (present === null) return 'pending';
  if (present) return intent === 'revoke' ? 'pending' : 'active';
  return intent === 'revoke' ? 'revoked' : intent === 'register' ? 'pending' : 'absent';
}
export function assertOwner(a: FullAccount, account: string, owner: string) {
  publicKeyBytes(account); publicKeyBytes(owner);
  if ((a.kind === 'MasterEOA' && account === owner && a.parent === null) || (a.kind === 'SubAccount' && a.parent === owner && account !== owner)) return;
  throw new BulkError('This wallet does not own the selected account.');
}
export async function apiRequest(network: Network, path: '/account' | '/order', body: unknown, fetcher: typeof fetch = fetch): Promise<unknown> {
  const label = `BULK ${NETWORKS[network].label}`;
  let response: Response;
  try {
    response = await fetcher(`${NETWORKS[network].api}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) });
  } catch (error) {
    if (path !== '/account') throw error;
    if (error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name)) throw new BulkError(`${label} account request timed out. Try again shortly.`, 'ACCOUNT_TIMEOUT');
    // Browsers hide an HTTP failure when its response lacks CORS headers.
    // Do not infer an HTTP status or blame the wallet from a fetch exception.
    throw new BulkError(`Could not reach ${label} to load account details. The API may be unavailable or your connection may be blocking the request. Try again shortly.`, 'ACCOUNT_NETWORK_ERROR');
  }
  if (!response.ok) {
    if (response.status === 404 && path === '/account') throw new BulkError('Account not found on this network. Check your network and wallet in BULK.', 'ACCOUNT_NOT_FOUND');
    if (path === '/account') throw new BulkError(`${label} could not load account details (HTTP ${response.status}). ${response.status === 429 ? 'Too many requests. Wait before trying again.' : 'Try again shortly.'}`, 'ACCOUNT_HTTP_ERROR');
    throw new BulkError(`BULK request failed (HTTP ${response.status}). Check key status before retrying.`, 'HTTP_ERROR');
  }
  try { return await response.json(); } catch (error) {
    if (path !== '/account') throw error;
    throw new BulkError(`${label} returned an unreadable account response. Try again shortly.`, 'ACCOUNT_RESPONSE_ERROR');
  }
}
export async function readAccount(network: Network, account: string, fetcher?: typeof fetch): Promise<FullAccount> {
  publicKeyBytes(account);
  return parseAccount(await apiRequest(network, '/account', { type: 'fullAccount', user: account }, fetcher));
}
// serde_wasm_bindgen in SDK 0.1.26 emits nested Maps. JSON.stringify(Map)
// silently produces {}, so normalize before validating any wire payload.
export function normalizeSdkValue(value: unknown): unknown {
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => {
    if (typeof k !== 'string') throw new BulkError('The SDK returned invalid request fields.');
    return [k, normalizeSdkValue(v)];
  }));
  if (Array.isArray(value)) return value.map(normalizeSdkValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalizeSdkValue(v)]));
  return value;
}
export function assertAgentAction(raw: unknown, agent: string, operation: AgentOperation = 'register') {
  const actions = normalizeSdkValue(raw);
  if (!Array.isArray(actions) || actions.length !== 1) throw new BulkError('Only one agent action is allowed.');
  const action = record(actions[0]);
  const creation = record(action.agentWalletCreation);
  if (Object.keys(action).length !== 1 || Object.keys(creation).length !== 2 || creation.a !== agent || creation.d !== (operation === 'revoke')) throw new BulkError('The request does not match the selected key action.');
}
export function assertRegistrationEnvelope(raw: unknown, key: AgentKey, operation: AgentOperation = 'register'): Registration {
  const tx = record(normalizeSdkValue(raw));
  if (tx.account !== key.account || tx.signer !== key.owner || typeof tx.nonce !== 'string' || !/^\d+$/.test(tx.nonce) || BigInt(tx.nonce) > 18446744073709551615n || BigInt(tx.nonce) === 0n) throw new BulkError('The request does not match the selected account.');
  assertAgentAction(tx.actions, key.publicKey, operation);
  if (typeof tx.signature !== 'string' || bs58.decode(tx.signature).length !== 64) throw new BulkError('Invalid wallet signature.');
  // Select the fields explicitly. No private key or SDK diagnostics can cross HTTP.
  return { actions: [{ agentWalletCreation: { a: key.publicKey, d: operation === 'revoke' } }], nonce: tx.nonce, account: key.account, signer: key.owner, signature: tx.signature };
}
export function registrationResult(body: unknown, agent: string): 'accepted' | 'rejected' | 'unknown' {
  try {
    const b = record(body);
    if (b.status === 'err' || b.status === 'error') return 'rejected';
    if (b.status !== 'ok') return 'unknown';
    const response = record(b.response);
    if (response.type !== 'order') return 'unknown';
    const statuses = record(response.data).statuses;
    if (!Array.isArray(statuses) || statuses.length !== 1) return 'unknown';
    const status = record(statuses[0]);
    if ('agentWalletFailed' in status || 'error' in status) return 'rejected';
    if (record(status.agentWallet).agent_wallet === agent) return 'accepted';
  } catch { /* Unknown replies always require readback. */ }
  return 'unknown';
}
export async function submitRegistration(network: Network, tx: Registration, fetcher?: typeof fetch): Promise<'accepted' | 'rejected' | 'unknown'> {
  return registrationResult(await apiRequest(network, '/order', tx, fetcher), tx.actions[0].agentWalletCreation.a);
}
export function exportKey(key: AgentKey): string {
  return JSON.stringify({ format: 'bulk-agent-key-v1', network: key.network, api_url: NETWORKS[key.network].api, signature_domain: NETWORKS[key.network].domain, account_public_key: key.account, owner_public_key: key.owner, agent_public_key: key.publicKey, agent_private_key_base58: key.secretKey, private_key_format: 'base58-64-byte-ed25519-keypair', created_at: key.createdAt }, null, 2);
}
export function shortKey(key: string) { return `${key.slice(0, 6)}…${key.slice(-6)}`; }
export function friendlyError(error: unknown): string {
  if (error instanceof BulkError) return error.message;
  if (error && typeof error === 'object' && 'code' in error && error.code === 4001) return 'Cancelled in your wallet. Your key remains on this page.';
  if (error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name)) return 'Request timed out. Check key status before retrying. Keep the current key.';
  return 'Action failed. Check your connection and wallet. Your key remains on this page.';
}
