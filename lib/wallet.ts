import { BulkError } from './bulk.ts';
import type { SignatureMode } from './bulk.ts';

export interface WalletSigner {
  signMessage(message: Uint8Array, display?: 'hex' | 'utf8'): Promise<{ signature: Uint8Array; publicKey?: { toString(): string } }>;
}
export type AuthorizationStep = 'account' | 'prepare' | 'wallet' | 'verify' | 'readback';

export function isPhantomWallet(name: string) { return name.trim().toLowerCase() === 'phantom'; }
export const PHANTOM_SUBACCOUNT_MESSAGE = 'Phantom cannot sign a subaccount request in this tool. Use Backpack with the same owner address for subaccount-only access. Your account and key have not changed.';
export function registrationModeForWallet(name: string, account: string, owner: string): SignatureMode {
  if (!isPhantomWallet(name)) return 'raw';
  if (account !== owner) throw new BulkError(PHANTOM_SUBACCOUNT_MESSAGE, 'PHANTOM_SUBACCOUNT_UNSUPPORTED');
  return 'base58';
}
// The caller constructs and verifies exactly the bytes required by BULK.
// Display hints do not encode or transform the message.
export function signWithWallet(wallet: WalletSigner, message: Uint8Array, display: 'hex' | 'utf8' = 'hex') {
  return wallet.signMessage(Uint8Array.from(message), display);
}

function providerLabel(name: string) { return ['Phantom', 'Solflare', 'Backpack'].includes(name) ? name : 'Wallet'; }

export function connectionError(error: unknown, walletName = 'Wallet'): BulkError {
  if (error instanceof BulkError) return error;
  const label = providerLabel(walletName);
  const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'number' && Number.isSafeInteger(error.code) ? error.code : null;
  const messages: Record<number, string> = {
    4001: `Connection cancelled in ${label}.`,
    4100: `${label} has not authorized this connection. Open the extension and connect again.`,
    4900: `${label} is disconnected. Open the extension and connect again.`,
    [-32002]: `Another ${label} request is already open. Finish or cancel it first.`,
  };
  return new BulkError(`${code !== null && messages[code] ? messages[code] : `Could not connect to ${label}. Open and unlock the extension, then try again.`}${code !== null ? ` (${label} ${code})` : ''}`, 'WALLET_CONNECTION_ERROR');
}

export function authorizationError(error: unknown, step: AuthorizationStep, walletName = 'Wallet'): BulkError {
  const label = providerLabel(walletName);
  if (error instanceof BulkError) return error;
  const detail = error && typeof error === 'object' ? error as { code?: unknown; name?: unknown } : {};
  if (step === 'wallet') {
    const code = typeof detail.code === 'number' && Number.isSafeInteger(detail.code) ? detail.code : null;
    const messages: Record<number, string> = {
      4001: `Signature cancelled in ${label}.`,
      4100: `${label} has not authorized this wallet. Reconnect it and try again.`,
      4900: `${label} is disconnected. Open your wallet and reconnect.`,
      [-32000]: `${label} rejected the signing parameters.`,
      [-32002]: `Another ${label} approval is already open. Finish or cancel it first.`,
      [-32003]: `${label} rejected the signing request.`,
      [-32601]: 'This wallet does not support the requested signing method.',
      [-32603]: `${label} could not open or complete the signature request. Open the extension and try again.`,
    };
    const message = code !== null ? messages[code] ?? `${label} could not sign this message.` : `Could not request a ${label} signature. Open the extension and reconnect your wallet.`;
    return new BulkError(`${message}${code !== null ? ` (${label} ${code})` : ''} Request not sent. Your key is still here.`, 'WALLET_SIGNATURE_ERROR');
  }
  if (step === 'verify' && detail.name === 'NotSupportedError') return new BulkError('This browser cannot verify Ed25519 signatures. Update your browser before registering. Request not sent.', 'SIGNATURE_UNSUPPORTED');
  const messages: Record<Exclude<AuthorizationStep, 'wallet'>, string> = {
    account: 'Could not load account details from BULK. Check your connection and try again. Request not sent.',
    prepare: 'Could not prepare the BULK signing message. Request not sent. Your key is still here.',
    verify: 'Could not verify the wallet signature. Request not sent. Your key is still here.',
    readback: 'Could not check the request status with BULK. Keep your key and backup, then use Check status.',
  };
  // Fixed categories are safe to show; raw exception messages may contain inputs.
  const kind = typeof detail.name === 'string' && ['TypeError', 'SyntaxError', 'RuntimeError', 'AbortError', 'TimeoutError', 'NotSupportedError', 'OperationError'].includes(detail.name) ? detail.name : 'Unknown';
  return new BulkError(`${messages[step]} (${step.toUpperCase()}: ${kind})`, `AUTH_${step.toUpperCase()}`);
}
