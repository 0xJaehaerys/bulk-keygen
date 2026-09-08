import { getWallets } from '@wallet-standard/app';
import type { Wallet, WalletAccount } from '@wallet-standard/base';
import type { StandardConnectFeature, StandardEventsFeature } from '@wallet-standard/features';
import type { SolanaSignMessageFeature } from '@solana/wallet-standard-features';
import { BulkError, publicKeyBytes, validPublicKey } from './bulk.ts';
import type { WalletSigner } from './wallet.ts';

export interface WalletConnection extends WalletSigner {
  readonly id: string;
  readonly name: string;
  readonly publicKey: { toString(): string } | null;
  subscribe(onChange: () => void): () => void;
}
export interface WalletOption {
  readonly id: string;
  readonly name: string;
  connect(): Promise<WalletConnection[]>;
}
export interface LegacyPhantom extends WalletSigner {
  isPhantom?: boolean;
  publicKey: { toString(): string } | null;
  connect(): Promise<{ publicKey: { toString(): string } }>;
  on(event: string, callback: () => void): void;
  removeListener(event: string, callback: () => void): void;
}
declare global { interface Window { phantom?: { solana?: LegacyPhantom }; solana?: LegacyPhantom } }

type CompatibleWallet = Wallet & { features: StandardConnectFeature & StandardEventsFeature & SolanaSignMessageFeature };
const solanaChains = new Set(['solana:mainnet', 'solana:devnet', 'solana:testnet', 'solana:localnet']);
const ids = new WeakMap<object, string>();
let nextId = 0;
function walletId(wallet: object) { let id = ids.get(wallet); if (!id) { id = `wallet-${++nextId}`; ids.set(wallet, id); } return id; }
function displayName(name: string) { return name.replace(/[\p{C}]/gu, '').trim().slice(0, 40) || 'Solana wallet'; }
function bytesEqual(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((value, i) => value === b[i]); }

export function supportsMessageSigning(wallet: Wallet): wallet is CompatibleWallet {
  const features = wallet.features as Partial<CompatibleWallet['features']>;
  return wallet.version === '1.0.0' && wallet.chains.some(chain => solanaChains.has(chain))
    && features['standard:connect']?.version === '1.0.0' && typeof features['standard:connect'].connect === 'function'
    && features['standard:events']?.version === '1.0.0' && typeof features['standard:events'].on === 'function'
    && ['1.0.0', '1.1.0'].includes(features['solana:signMessage']?.version ?? '') && typeof features['solana:signMessage']?.signMessage === 'function';
}
function validAccount(account: WalletAccount) {
  return validPublicKey(account.address) && account.publicKey instanceof Uint8Array && account.publicKey.length === 32
    && bytesEqual(publicKeyBytes(account.address), account.publicKey)
    && account.chains.some(chain => solanaChains.has(chain)) && account.features.includes('solana:signMessage');
}
function changedWallet() { return new BulkError('Wallet disconnected or changed. Reconnect the owner wallet. Request not sent.', 'WALLET_CHANGED'); }

export function standardWalletOption(wallet: Wallet, isAvailable: () => boolean = () => true): WalletOption {
  const id = walletId(wallet), name = displayName(wallet.name);
  return { id, name, async connect() {
    if (!isAvailable() || !supportsMessageSigning(wallet)) throw new BulkError('This wallet does not support Solana message signing.');
    const { accounts } = await wallet.features['standard:connect'].connect();
    if (!isAvailable() || !supportsMessageSigning(wallet)) throw changedWallet();
    const eligible = accounts.filter(account => wallet.accounts.includes(account) && validAccount(account));
    if (!eligible.length) throw new BulkError('No Solana account with message signing is available. Select a supported account in your wallet.');
    return eligible.map(account => {
      // Keep the original WalletAccount object: wallets may require identity equality.
      const address = account.address;
      const authorized = () => isAvailable() && supportsMessageSigning(wallet) && wallet.accounts.includes(account)
        && account.address === address && validAccount(account);
      return {
        id, name,
        get publicKey() { return authorized() ? { toString: () => address } : null; },
        subscribe(onChange: () => void) {
          return wallet.features['standard:events'].on('change', properties => {
            // Properties omitted by the event have not changed.
            if (properties.accounts !== undefined || properties.chains !== undefined || properties.features !== undefined) onChange();
          });
        },
        async signMessage(message: Uint8Array) {
          if (!authorized()) throw changedWallet();
          const canonical = Uint8Array.from(message);
          const outputs = await wallet.features['solana:signMessage'].signMessage({ account, message: Uint8Array.from(canonical) });
          if (!authorized()) throw changedWallet();
          if (outputs.length !== 1) throw new BulkError('Wallet returned an unexpected number of signatures. Request not sent.');
          const output = outputs[0];
          if (!(output.signedMessage instanceof Uint8Array) || !bytesEqual(output.signedMessage, canonical)) throw new BulkError('This wallet changed the signing message. BULK requires the original bytes. Request not sent.', 'WALLET_MESSAGE_CHANGED');
          if (!(output.signature instanceof Uint8Array) || output.signature.length !== 64 || (output.signatureType !== undefined && output.signatureType !== 'ed25519')) throw new BulkError('Wallet returned an unsupported signature. Request not sent.');
          // The application still verifies this signature over the canonical BULK bytes.
          return { signature: Uint8Array.from(output.signature), publicKey: { toString: () => address } };
        },
      };
    });
  } };
}

// Retain the existing extension path for older Phantom versions without Standard.
export function phantomWalletOption(phantom: LegacyPhantom): WalletOption {
  const id = walletId(phantom);
  return { id, name: 'Phantom', async connect() {
    const result = await phantom.connect();
    const address = result.publicKey.toString(); publicKeyBytes(address);
    if (phantom.publicKey?.toString() !== address) throw changedWallet();
    return [{ id, name: 'Phantom',
      get publicKey() { return phantom.publicKey?.toString() === address ? { toString: () => address } : null; },
      subscribe(onChange) {
        phantom.on('accountChanged', onChange); phantom.on('disconnect', onChange);
        return () => { phantom.removeListener('accountChanged', onChange); phantom.removeListener('disconnect', onChange); };
      },
      async signMessage(message, display = 'hex') {
        if (phantom.publicKey?.toString() !== address) throw changedWallet();
        const signed = await phantom.signMessage(Uint8Array.from(message), display);
        if (phantom.publicKey?.toString() !== address) throw changedWallet();
        return signed;
      },
    }];
  } };
}

export function availableWallets(): WalletOption[] {
  // Never initialize the registry during server rendering.
  if (typeof window === 'undefined') return [];
  const registry = getWallets();
  const standard = registry.get().filter(supportsMessageSigning);
  const options = standard.map(wallet => standardWalletOption(wallet, () => registry.get().includes(wallet)));
  const phantom = window.phantom?.solana ?? (window.solana?.isPhantom ? window.solana : undefined);
  if (phantom && typeof phantom.signMessage === 'function' && typeof phantom.on === 'function' && typeof phantom.removeListener === 'function' && !standard.some(wallet => wallet.name.toLowerCase() === 'phantom')) options.push(phantomWalletOption(phantom));
  return options.sort((a, b) => a.name.localeCompare(b.name));
}
export function watchWallets(onChange: (wallets: WalletOption[]) => void) {
  const refresh = () => onChange(availableWallets());
  const registry = getWallets();
  const offRegister = registry.on('register', refresh), offUnregister = registry.on('unregister', refresh);
  window.addEventListener('focus', refresh); refresh();
  return () => { offRegister(); offUnregister(); window.removeEventListener('focus', refresh); };
}
