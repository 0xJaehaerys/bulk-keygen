'use client';
import { useEffect, useRef, useState } from 'react';
import { ArrowUpRight, ChevronDown, Download, Eye, EyeOff, KeyRound, LoaderCircle, LockKeyhole, RefreshCw, Wallet, Upload, Ban, Trash2 } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription } from '@/components/ui/alert-dialog';
import { exportBackup, encryptVault, decryptVault, MAX_VAULT_BYTES, appendSubmissionHistory } from '@/lib/vault';
import { NETWORKS, BulkError, agentMembership, assertOwner, exportKey, friendlyError, readAccount, readbackState, shortKey, submitRegistration } from '@/lib/bulk';
import type { AgentKey, FullAccount, Network, RegistrationState, AgentOperation, Submission } from '@/lib/bulk';
import { finalizeRegistration, generateKey, prepareRegistration, registrationMessage, validateKeypair, validateSubmission } from '@/lib/crypto';
import { authorizationError, connectionError, signWithWallet, isPhantomWallet, registrationModeForWallet, PHANTOM_SUBACCOUNT_MESSAGE } from '@/lib/wallet';
import type { AuthorizationStep } from '@/lib/wallet';
import { availableWallets, watchWallets } from '@/lib/wallet-providers';
import type { WalletConnection, WalletOption } from '@/lib/wallet-providers';
import { SubaccountCreator } from '@/components/subaccount-creator';
import { LocalVersion } from '@/components/local-version';
import { NetworkSwitcher } from '@/components/network-switcher';
import { CopyKeyButton } from '@/components/copy-key-button';
const labels: Record<RegistrationState, string> = { created: 'Not registered', signing: 'Awaiting signature', signed: 'Signed · not sent', submitting: 'Submitting', pending: 'Unconfirmed', active: 'Active', rejected: 'Rejected', absent: 'Not found', revoked: 'Not listed' };
export default function Home() {
  const [embedded, setEmbedded] = useState(false);
  const [network, setNetwork] = useState<Network>('testnet');
  const [owner, setOwner] = useState('');
  const [walletName, setWalletName] = useState('');
  const [wallets, setWallets] = useState<WalletOption[]>([]);
  const [walletAccounts, setWalletAccounts] = useState<WalletConnection[]>([]);
  const [accounts, setAccounts] = useState<string[]>([]);
  const [account, setAccount] = useState('');
  const [accountInfo, setAccountInfo] = useState<FullAccount | null>(null);
  const [subaccountOwner, setSubaccountOwner] = useState('');
  const [key, setKey] = useState<AgentKey | null>(null);
  const [saved, setSaved] = useState(false);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [masterScopeAccepted, setMasterScopeAccepted] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  const [stage, setStageState] = useState<RegistrationState>('created');
  const [submission, setSubmissionState] = useState<Submission | null>(null);
  const [history, setHistory] = useState<Submission[]>([]);
  const [importedKeyOnly, setImportedKeyOnly] = useState(false);
  const [canStopWaiting, setCanStopWaiting] = useState(false);
  const [dialog, setDialog] = useState<'export' | 'import' | 'plaintext' | 'revoke' | 'clear' | 'wallet' | 'wallet-account' | null>(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [importKind, setImportKind] = useState<'json' | 'encrypted' | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const provider = useRef<WalletConnection | null>(null);
  const epoch = useRef(0);
  const busyRef = useRef(false);
  const activeRun = useRef(0);
  const runPending = useRef(false);
  const unsubscribe = useRef<(() => void) | null>(null);
  const keyRef = useRef<AgentKey | null>(null);
  const submissionRef = useRef<Submission | null>(null);
  const beforeSigning = useRef<RegistrationState>('created');
  const stageRef = useRef<RegistrationState>('created');
  keyRef.current = key;
  function setSubmission(next: Submission | null) { submissionRef.current = next; setSubmissionState(next); setRecoverySaved(false); }
  function closeDialog() { setDialog(null); setWalletAccounts([]); setPassword(''); setConfirmPassword(''); setFile(null); setImportKind(null); setAcknowledged(false); setDialogError(''); }
  function setStage(next: RegistrationState) { stageRef.current = next; setStageState(next); }

  useEffect(() => {
    setEmbedded(window.self !== window.top);
    const preventLoss = (event: BeforeUnloadEvent) => { if (keyRef.current) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', preventLoss);
    const stopWatching = window.self === window.top ? watchWallets(options => {
      setWallets(options);
      if (provider.current && !provider.current.publicKey) invalidateWallet();
      setWalletAccounts(current => current.filter(connection => connection.publicKey));
    }) : () => {};
    return () => { epoch.current++; activeRun.current++; unsubscribe.current?.(); stopWatching(); window.removeEventListener('beforeunload', preventLoss); };
  }, []);

  function ensureContext(version: number, expectedOwner?: string) {
    if (window.self !== window.top) throw new BulkError('Open Keygen in its own tab to manage keys.');
    if (epoch.current !== version || (expectedOwner && provider.current?.publicKey?.toString() !== expectedOwner)) throw new BulkError('Wallet or account changed. Reconnect the original wallet and check status.');
  }
  async function run(label: string, task: (version: number) => Promise<void>) {
    if (window.self !== window.top) { setEmbedded(true); return; }
    if (busyRef.current) return;
    const operation = ++activeRun.current;
    busyRef.current = true; runPending.current = true; setBusy(label); setCanStopWaiting(true); setError(''); setNotice('');
    const version = ++epoch.current;
    try { await task(version); } catch (e) { if (activeRun.current === operation) setError(friendlyError(e)); }
    finally { if (activeRun.current === operation) { runPending.current = false; busyRef.current = false; setBusy(''); setCanStopWaiting(false); } }
  }
  function invalidateWallet() {
    epoch.current++; activeRun.current++;
    if (runPending.current) { runPending.current = false; busyRef.current = false; setBusy(''); setCanStopWaiting(false); }
    unsubscribe.current?.(); unsubscribe.current = null; provider.current = null;
    setOwner(''); setWalletName(''); setAccounts([]); setAccountInfo(null);
    if (!keyRef.current) setAccount('');
    if (stageRef.current === 'submitting') setStage('pending');
    if (stageRef.current === 'signing') setStage(beforeSigning.current);
    setError(keyRef.current ? 'Wallet disconnected or changed. Your key is still here. Reconnect its owner.' : 'Wallet disconnected or changed. Connect your wallet again.');
  }
  function stopWaiting() {
    if (!runPending.current) return;
    invalidateWallet();
    setError('');
    setNotice('Stopped waiting. Close any open wallet prompt before reconnecting. Signed or submitted requests are not cancelled.');
  }
  function bindProvider(p: WalletConnection) {
    unsubscribe.current?.(); provider.current = p;
    unsubscribe.current = p.subscribe(invalidateWallet);
  }
  async function loadAccounts(n: Network, wallet: string, version: number, target?: string) {
    ensureContext(version, wallet);
    const root = await readAccount(n, wallet); ensureContext(version, wallet); assertOwner(root, wallet, wallet);
    const list = [wallet, ...(root.subAccounts ?? []).map(s => s.pubkey)].filter((v, i, a) => a.indexOf(v) === i);
    const selected = target ?? wallet;
    if (!list.includes(selected) && root.subAccounts !== null) throw new BulkError('The selected account does not belong to this wallet.');
    const info = selected === wallet ? root : await readAccount(n, selected);
    ensureContext(version, wallet); assertOwner(info, selected, wallet);
    if (!list.includes(selected)) list.push(selected);
    setAccounts(list); setAccount(selected); setAccountInfo(info);
  }
  function chooseWallet() {
    if (busyRef.current) return;
    setWallets(availableWallets()); setDialog('wallet');
  }
  async function activateConnection(p: WalletConnection, version: number) {
    ensureContext(version);
    const wallet = p.publicKey?.toString();
    if (!wallet) throw new BulkError('Wallet account is no longer available. Connect again.');
    if (keyRef.current && wallet !== keyRef.current.owner) throw new BulkError('This key belongs to another wallet account. Select its owner in your wallet.');
    if (subaccountOwner && wallet !== subaccountOwner) throw new BulkError('Reconnect the wallet that signed the subaccount request.');
    bindProvider(p);
    setOwner(wallet); setWalletName(p.name); setAccounts([]); setAccountInfo(null); setBusy('Loading BULK accounts…');
    await loadAccounts(network, wallet, version, keyRef.current?.account);
  }
  function connect(option: WalletOption) { closeDialog(); void run(`Connecting ${option.name}…`, async version => {
    unsubscribe.current?.(); unsubscribe.current = null; provider.current = null;
    setOwner(''); setWalletName(''); setAccounts([]); setAccountInfo(null);
    let connections: WalletConnection[];
    try { connections = await option.connect(); } catch (e) { throw connectionError(e, option.name); }
    ensureContext(version);
    const expectedOwner = keyRef.current?.owner || subaccountOwner;
    const eligible = expectedOwner ? connections.filter(c => c.publicKey?.toString() === expectedOwner) : connections;
    if (!eligible.length) throw new BulkError('Select the account that owns this key in your wallet, then connect again.');
    if (eligible.length > 1) { setWalletAccounts(eligible); setDialog('wallet-account'); return; }
    await activateConnection(eligible[0], version);
  }); }
  function changeNetwork(value: Network) {
    if (key || subaccountOwner || busyRef.current || value === network) return;
    epoch.current++; setNetwork(value); setAccounts([]); setAccount(''); setAccountInfo(null); setError('');
    if (owner) void run('Loading accounts…', current => loadAccounts(value, owner, current));
  }
  function selectAccount(value: string) {
    if (key || subaccountOwner || busyRef.current || value === account) return;
    epoch.current++; setAccount(value); setAccountInfo(null); setMasterScopeAccepted(false);
    void run('Checking account…', async version => { const info = await readAccount(network, value); ensureContext(version, owner); assertOwner(info, value, owner); setAccountInfo(info); });
  }
  function createKey() { void run('Creating key…', async version => {
    if (!owner || !accountInfo || key || subaccountOwner) return;
    registrationModeForWallet(provider.current?.name ?? '', account, owner);
    ensureContext(version, owner); assertOwner(accountInfo, account, owner);
    const generated = await generateKey(network, account, owner);
    ensureContext(version, owner); setKey(generated); setSubmission(null); setHistory([]); setImportedKeyOnly(false); setSaved(false); setMasterScopeAccepted(false); setStage('created'); setShowSecret(false);
    setNotice('Key created. Save key backup before registering.');
  }); }
  async function checkRegistration(k: AgentKey, version: number, intent: AgentOperation | null, attempts = 1): Promise<boolean> {
    let unavailable = false;
    for (let i = 0; i < attempts; i++) {
      if (i) await new Promise(resolve => setTimeout(resolve, 1200));
      const info = await readAccount(k.network, k.account); ensureContext(version);
      assertOwner(info, k.account, k.owner); setAccountInfo(info);
      const status = readbackState(info, k.publicKey, intent);
      unavailable = info.authorizedAgentWallets === null;
      if (status === 'active') {
        setStage('active'); setNotice('Registration confirmed by BULK.'); return true;
      }
      if (status === 'revoked') {
        setStage('revoked'); setNotice('BULK currently does not list this key on the selected account. This does not cancel an earlier signed registration request. Keep your latest backup; do not replay old registration files.'); return true;
      }
      if (status === 'absent') {
        if (stageRef.current !== 'created') setStage('absent');
        setNotice('Key not found. A previous request may still be pending.'); return false;
      }
    }
    if (intent || stageRef.current !== 'created') setStage('pending');
    setNotice(unavailable ? `BULK did not return the agent list. Status is unconfirmed. ${intent ? 'Save an updated backup' : 'Keep your backup'} and check again.` : intent === 'revoke'
      ? 'Key is still active. Check again or retry the revoke request.'
      : 'Not confirmed yet. Save an updated backup to recover this request later.');
    return false;
  }
  async function send(k: AgentKey, attempt: Submission, version: number) {
    ensureContext(version, k.owner);
    if (submissionRef.current !== attempt) throw new BulkError('Action changed. Request not sent.');
    await validateSubmission(k, attempt); ensureContext(version, k.owner);
    setStage('submitting');
    let result: 'accepted' | 'rejected' | 'unknown' = 'unknown';
    try { result = await submitRegistration(k.network, attempt.request); } catch { /* Never infer rejection from transport failure. */ }
    ensureContext(version); setStage('pending');
    // A duplicate/error reply does not prove what happened to an earlier identical request.
    const confirmed = await checkRegistration(k, version, attempt.operation, result === 'accepted' ? 3 : 1);
    ensureContext(version);
    if (!confirmed && result === 'rejected') setError('BULK rejected this request. Registration is not confirmed. Keep the signed backup and check status before retrying.');
  }
  function authorize(operation: AgentOperation) { void run(operation === 'register' ? 'Preparing registration…' : 'Preparing revoke…', async version => {
    const canRevoke = stageRef.current === 'active' || stageRef.current === 'pending';
    if (!key || !owner || (operation === 'register' ? (!saved || stageRef.current !== 'created' || submissionRef.current) : !canRevoke)) return;
    if (operation === 'register' && key.account === key.owner && !masterScopeAccepted) throw new BulkError('Confirm that this key will cover your main account and all subaccounts.');
    const signatureMode = registrationModeForWallet(provider.current?.name ?? '', key.account, key.owner);
    const previousStage = stageRef.current;
    beforeSigning.current = previousStage;
    const nextHistory = appendSubmissionHistory(history, submissionRef.current);
    let prepared: Awaited<ReturnType<typeof prepareRegistration>> | undefined;
    let step: AuthorizationStep = 'account';
    try {
      ensureContext(version, key.owner);
      const latest = await readAccount(key.network, key.account); ensureContext(version, key.owner); assertOwner(latest, key.account, key.owner);
      const present = agentMembership(latest, key.publicKey);
      if (operation === 'register' && present === true) { setStage('active'); setNotice('This key is already registered.'); return; }
      if (operation === 'revoke' && present === false) { setStage('absent'); setNotice('Key is already absent. No revoke request was sent.'); return; }
      step = 'prepare'; setStage('signing');
      prepared = await prepareRegistration(key, operation); ensureContext(version, key.owner);
      step = 'wallet';
      const message = registrationMessage(prepared, key, operation, signatureMode);
      const signed = await signWithWallet(provider.current!, message, signatureMode === 'base58' ? 'utf8' : 'hex'); ensureContext(version, key.owner);
      if (signed.publicKey && signed.publicKey.toString() !== key.owner) throw new BulkError('A different wallet signed the request.');
      step = 'verify';
      const request = await finalizeRegistration(prepared, new Uint8Array(signed.signature), key, operation, signatureMode); ensureContext(version, key.owner);
      // Previous signatures remain valid evidence; retries use only the current request.
      const attempt = { operation, request, signatureMode };
      exportBackup(key, attempt, nextHistory); // Check recoverability before committing the signed request.
      setHistory(nextHistory); setSubmission(attempt);
      setStage('signed'); setNotice('Signed, not sent. Save signed request backup above before submitting.');
    } catch (e) {
      if (epoch.current === version) setStage(previousStage);
      throw authorizationError(e, step, provider.current?.name);
    } finally { prepared?.free(); }
  }); }
  function submitSigned() { void run('Submitting signed request…', async version => {
    const attempt = submissionRef.current;
    if (!key || !attempt || stageRef.current !== 'signed' || !recoverySaved) return;
    await send(key, attempt, version);
  }); }
  function retry() { void run('Retrying original request…', async version => {
    const attempt = submissionRef.current;
    if (!key || !attempt || stageRef.current !== 'pending') return;
    ensureContext(version, key.owner);
    if (await checkRegistration(key, version, attempt.operation)) return;
    // No new nonce/signature: the documented nonce-once rule prevents two distinct authorizations.
    await send(key, attempt, version);
  }); }
  function verify() { void run('Checking status…', async version => {
    if (key) await checkRegistration(key, version, submissionRef.current?.operation ?? null);
  }); }
  function saveFile(text: string, name: string) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function downloadKey() {
    if (!key || busyRef.current) return;
    saveFile(exportBackup(key, submissionRef.current, history), `bulk-${key.network}-${key.publicKey.slice(0, 8)}.json`);
    setNotice(submissionRef.current ? 'JSON downloaded with your key and signed request history. Keep it private.' : 'JSON downloaded. Keep it private and confirm you saved your key.');
  }
  async function vaultAction() {
    if (window.self !== window.top) { setEmbedded(true); return; }
    if (busyRef.current) return;
    busyRef.current = true; setBusy(dialog === 'export' ? 'Encrypting backup…' : 'Opening backup…'); setDialogError('');
    try {
      if (dialog === 'export' && key) {
        if (password !== confirmPassword) throw new BulkError('Passwords do not match.');
        const encrypted = await encryptVault(key, password, submissionRef.current, history);
        saveFile(encrypted, `bulk-${key.network}-${key.publicKey.slice(0, 8)}.encrypted.json`);
        closeDialog(); setNotice('Backup downloaded. Keep your password separately; it cannot be recovered.');
      } else if (dialog === 'import' && !key) {
        if (subaccountOwner) throw new BulkError('Finish the pending subaccount request before importing an agent key.');
        if (!importKind) throw new BulkError('Choose JSON backup or encrypted backup.');
        if (!file) throw new BulkError('Choose a backup file.');
        if (file.size > MAX_VAULT_BYTES) throw new BulkError('Key file too large. Maximum size: 32 KB.');
        const contents = await file.text();
        let format: unknown;
        try { format = JSON.parse(contents)?.format; } catch { throw new BulkError('Could not read the key JSON file.'); }
        if (importKind === 'json' && format === 'bulk-agent-vault-v1') throw new BulkError('This file is encrypted. Choose Encrypted backup and enter its password.');
        if (importKind === 'encrypted' && (format === 'bulk-agent-key-v1' || format === 'bulk-agent-backup-v1' || format === 'bulk-agent-backup-v2')) throw new BulkError('This file is not encrypted. Choose JSON backup; no password is needed.');
        const backup = await decryptVault(contents, password, importKind === 'json');
        await validateKeypair(backup.key);
        for (const previous of backup.history) await validateSubmission(backup.key, previous);
        if (backup.submission) await validateSubmission(backup.key, backup.submission);
        // Commit only after every local validation passes. Imported status is never authoritative.
        epoch.current++; unsubscribe.current?.(); unsubscribe.current = null; provider.current = null;
        setOwner(''); setWalletName(''); setAccounts([]); setAccountInfo(null); setNetwork(backup.key.network); setAccount(backup.key.account);
        setKey(backup.key); setSubmission(backup.submission); setHistory(backup.history); setImportedKeyOnly(!backup.submission && backup.history.length === 0); setRecoverySaved(!!backup.submission); setSaved(true); setMasterScopeAccepted(false); setShowSecret(false);
        setStage('pending'); closeDialog();
        setNotice('Key imported. Connect the owner wallet below, then check status to manage access.');
      }
    } catch (e) { setDialogError(friendlyError(e)); }
    finally { busyRef.current = false; setBusy(''); }
  }
  function clearKey() {
    epoch.current++; setKey(null); setSubmission(null); setHistory([]); setImportedKeyOnly(false); setSaved(false); setMasterScopeAccepted(false); setShowSecret(false); setStage('created'); setAccountInfo(null); setAccounts([]); setAccount('');
    closeDialog(); setNotice('Key cleared from this page. Its BULK access is unchanged.');
  }
  const walletReady = !!owner && (!key || owner === key.owner);
  const phantomSubaccount = isPhantomWallet(walletName) && !!account && !!owner && account !== owner;
  const revokeDisabledReason = !walletReady ? 'Connect the owner wallet to revoke access.' : phantomSubaccount ? 'Phantom cannot revoke subaccount-only keys here. Connect Backpack with the same owner address.' : busy ? 'Wait for the current action to finish before revoking access.' : '';
  const canRegister = !!key && saved && walletReady && !phantomSubaccount && (key.account !== key.owner || masterScopeAccepted) && stage === 'created' && !submission && !busy;
  const networkLockReason = key ? 'Network locked to this key. Save your backup, then use More options to clear the key and switch.' : subaccountOwner ? 'Finish or save and close the pending subaccount request before switching networks.' : busy ? 'Wait for the current action to finish before switching networks.' : '';
  const downloadLabel = stage === 'created' ? 'Save key backup' : stage === 'signed' ? 'Save signed request backup' : 'Download latest backup';
  const currentStep = stage === 'created' ? saved ? 1 : 0 : stage === 'signing' ? 1 : stage === 'signed' ? recoverySaved ? 3 : 2 : 3;
  if (embedded) return <main className="shell"><h1>Open Keygen in its own tab</h1><p>Key and wallet actions are disabled inside embedded frames.</p></main>;
  return <main className="shell">
    <header className="topbar"><h1>BULK <span>Keygen</span></h1><a className="quiet-link" href="https://docs.bulk.trade/api-reference/manageAgentWallet" target="_blank" rel="noreferrer">Docs <ArrowUpRight size={14}/></a></header>
    <LocalVersion/>
    <section className="card" aria-label="Agent key manager">
      <div className="setup stack">
        <div className="wallet-guidance"><p><strong>Backpack recommended</strong></p><p className="hint">Create subaccounts and their agent keys. Phantom supports main-account agent keys only.</p></div>
        <NetworkSwitcher value={network} onChange={changeNetwork} lockedReason={networkLockReason}/>
        {owner ? <div className="wallet-row"><div><span className="label" title="Previously approved sites may reconnect without a new approval prompt.">Connected · {walletName}</span><code title={owner}>{shortKey(owner)}</code></div><button className="btn text" aria-label="Change wallet" disabled={!!busy} onClick={chooseWallet}>Change</button></div> : <button className="btn primary full" onClick={chooseWallet} disabled={!!busy}><Wallet size={17}/> Connect wallet</button>}
        {accounts.length > 0 ? <div className="field"><label id="account-label" className="label">Account</label><Select value={account} onValueChange={v => v && selectAccount(v)} disabled={!!key || !!subaccountOwner || !!busy}><SelectTrigger className="account-select" aria-labelledby="account-label"><SelectValue>{account === owner ? 'Main account' : 'Subaccount'} · {shortKey(account)}</SelectValue></SelectTrigger><SelectContent>{accounts.map(a => <SelectItem key={a} value={a}>{a === owner ? 'Main account' : 'Subaccount'} · {shortKey(a)}</SelectItem>)}</SelectContent></Select></div> : key ? <div className="wallet-row"><span className="label">Account</span><code title={key.account}>{shortKey(key.account)}</code></div> : owner ? <button className="btn full" disabled={!!busy} onClick={() => void run('Loading accounts…', v => loadAccounts(network, owner, v))}>Load accounts</button> : <p className="hint">Connect the owner wallet to create or select a BULK subaccount.</p>}
        <SubaccountCreator network={network} owner={owner} hasKey={!!key} busy={!!busy} wallet={() => provider.current} run={run} onStopWaiting={stopWaiting} ensureContext={ensureContext} onPendingChange={setSubaccountOwner} onVerified={(address, info) => { setAccounts(current => Array.from(new Set([...current, address]))); setAccount(address); setAccountInfo(info); setNotice('Subaccount selected. Create its agent key below.'); }}/>
        {accountInfo?.kind === 'MasterEOA' && <p className="hint account-note">Main account keys also cover all subaccounts.</p>}
        {phantomSubaccount && <output className="hint account-note">{PHANTOM_SUBACCOUNT_MESSAGE}</output>}
        {accountInfo?.kind === 'MasterEOA' && accountInfo.subAccounts === null && <p className="hint">BULK did not return a subaccount list. Showing your main account.</p>}
      </div>
      <div className="key-section stack">
        {error && <div role="alert" className="message error">{error}</div>}
        {notice && <div role="status" className="message">{notice}</div>}
          {!key ? <><button className="btn full" onClick={createKey} disabled={!accountInfo || !walletReady || phantomSubaccount || !!subaccountOwner || !!busy}><KeyRound size={17}/> Create agent key</button><button className="btn text full" onClick={() => setDialog('import')} disabled={!!subaccountOwner || !!busy}><Upload size={16}/> Import saved key</button></> : <>
          <div className="row between"><h2>Agent key</h2><span className={`status ${stage}`}>{labels[stage]}</span></div>
          {!walletReady && <section className="owner-connection" aria-label="Owner wallet required"><strong>Wallet not connected</strong><p className="hint">Importing a backup does not connect your wallet. Connect the owner below to manage access.</p><code>{key.owner}</code><button className="btn primary full" disabled={!!busy} onClick={chooseWallet}><Wallet size={17}/> Connect owner wallet</button></section>}
          {history.length > 0 && <p className="hint">Your backup includes {history.length} earlier signed {history.length === 1 ? 'request' : 'requests'}. Keep the latest file; older signatures are not cancelled.</p>}
          {importedKeyOnly && !submission && <section className="stack" aria-label="Key-only backup"><p className="hint">This file has your key but no signed registration request. Check status to manage existing access. To finish a registration you started earlier, import its signed request backup.</p>{stage === 'absent' && <><p className="hint">No registration is listed. If you never signed a request for this key, clear it and create a new key.</p><button className="btn full" disabled={!!busy} onClick={() => setDialog('clear')}>Clear key to start again</button></>}</section>}
          {walletReady && stage === 'pending' && <p className="hint">Check status to confirm whether this key is active before managing access.</p>}
          {submission?.operation !== 'revoke' && ['created', 'signing', 'signed', 'submitting'].includes(stage) && <nav className="key-steps" aria-label="Registration progress">{['Save key', 'Sign', 'Save request', 'Submit'].map((step, i) => <span key={step} aria-current={currentStep === i ? 'step' : undefined}>{i + 1}. {step}</span>)}</nav>}
          {stage === 'created' && !importedKeyOnly && <p className="hint">Save this key first. After signing, save the updated backup to resume registration if you close the page.</p>}
          <div className="field"><span className="label">Public key</span><div className="public-key"><code>{key.publicKey}</code><CopyKeyButton value={key.publicKey} label="Copy public key"/></div></div>
          <div className="field"><div className="row between"><span className="label">Private key</span><div className="row"><button className="btn icon" aria-label={showSecret ? 'Hide private key' : 'Show private key'} onClick={() => setShowSecret(v => !v)}>{showSecret ? <EyeOff size={16}/> : <Eye size={16}/>}</button><CopyKeyButton value={key.secretKey} label="Copy private key"/></div></div><code className="key-value">{showSecret ? key.secretKey : '••••••••••••••••••••••••••••••••'}</code></div>
          <button className={`btn ${stage === 'created' && !saved || stage === 'signed' && !recoverySaved ? 'primary' : ''} full`} disabled={!!busy} onClick={downloadKey}><Download size={17}/> {downloadLabel}</button>
          <p className="hint">JSON backup · contains your private key. Keep it private.</p>
          {stage === 'created' && <><label className="checkrow" htmlFor="key-saved"><Checkbox id="key-saved" checked={saved} onCheckedChange={v => setSaved(v === true)} disabled={!!busy}/><span>I saved my key and can restore it.</span></label>{key.account === key.owner && <label className="checkrow" htmlFor="master-scope"><Checkbox id="master-scope" checked={masterScopeAccepted} onCheckedChange={v => setMasterScopeAccepted(v === true)} disabled={!!busy}/><span>I authorize this key for my main account and all its subaccounts.</span></label>}<button className="btn primary full" onClick={() => authorize('register')} disabled={!canRegister}><Wallet size={17}/> Sign registration</button></>}
          {stage === 'signed' && <><p className="hint">Save signed request backup above, then submit this exact request. Your earlier backup does not include this signature.</p><label className="checkrow" htmlFor="request-saved"><Checkbox id="request-saved" checked={recoverySaved} onCheckedChange={v => setRecoverySaved(v === true)} disabled={!!busy}/><span>I saved the updated backup containing this signed request.</span></label><button className="btn primary full" onClick={submitSigned} disabled={!!busy || !walletReady || !recoverySaved}>Submit {submission?.operation === 'revoke' ? 'revoke' : 'registration'}</button></>}
          {(stage === 'active' || stage === 'pending') && <><div className="active-actions"><button className="btn" disabled={!!busy} onClick={verify}><RefreshCw size={16}/> Check status</button><button className="btn danger" disabled={!!revokeDisabledReason} aria-describedby={revokeDisabledReason ? 'revoke-disabled-reason' : undefined} onClick={() => setDialog('revoke')}><Ban size={16}/>{stage === 'pending' && submission?.operation === 'revoke' ? 'Sign a new revoke request' : 'Revoke access'}</button></div>{revokeDisabledReason && <p id="revoke-disabled-reason" className="hint">{revokeDisabledReason}</p>}</>}
          {stage === 'absent' && <button className="btn full" disabled={!!busy} onClick={verify}><RefreshCw size={16}/> Check status</button>}
          {stage === 'absent' && <p className="hint">For a pending request, import a backup saved after signing. Imported keys cannot be registered with a new request.</p>}
          {stage === 'revoked' && <p className="hint">BULK does not currently list this key on the selected account. Save an updated backup. Do not resubmit older registration requests.</p>}
          <Collapsible className="more-options">
            <CollapsibleTrigger className="more-trigger">More options <ChevronDown size={15}/></CollapsibleTrigger>
            <CollapsibleContent><div className="stack more-content">
              <button className="btn full" disabled={!!busy} onClick={() => setDialog('export')}><LockKeyhole size={17}/> Save encrypted backup</button>
              <button className="btn full" disabled={!!busy} onClick={() => setDialog('plaintext')}><Download size={16}/> Export JSON for bot</button>
              <p className="hint">Bot JSON contains only the key configuration. The main backup button includes recovery details.</p>
              {stage !== 'active' && stage !== 'pending' && stage !== 'absent' && stage !== 'signed' && <button className="btn full" disabled={!!busy} onClick={verify}><RefreshCw size={16}/> Check status</button>}
              {stage === 'pending' && submission && <><p className="hint">Retry only if you still want to {submission.operation === 'revoke' ? 'revoke access' : 'register this key'} and have not changed its access elsewhere. This resends the original signed request.</p><button className="btn full" disabled={!!busy || !walletReady} onClick={retry}><RefreshCw size={16}/> Retry original request</button></>}
              <button className="btn text full" disabled={!!busy} onClick={() => setDialog('clear')}><Trash2 size={15}/> Clear key from page</button>
            </div></CollapsibleContent>
          </Collapsible>
        </>}
        {busy && <div role="status" className="busy"><LoaderCircle size={16} className="spin"/>{stage === 'signing' ? `Confirm in ${walletName || 'your wallet'}…` : busy}</div>}
        {canStopWaiting && <button className="btn text full" onClick={stopWaiting}>Stop waiting</button>}
      </div>
    </section>
    <footer><a href="https://github.com/0xJaehaerys/bulk-keygen" target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, verticalAlign: 'middle' }}><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>Source code</a> · Not affiliated with BULK</footer>
    <Dialog open={dialog === 'wallet' || dialog === 'wallet-account'} onOpenChange={open => { if (!open && !busyRef.current) closeDialog(); }}>
      <DialogContent className="vault-dialog">
        <DialogTitle>{dialog === 'wallet-account' ? 'Choose wallet account' : 'Connect wallet'}</DialogTitle>
        <DialogDescription>{dialog === 'wallet-account' ? 'Select the account that owns your BULK account.' : 'Backpack is recommended for subaccounts and agent keys. Phantom supports main-account agent keys only in this tool.'}</DialogDescription>
        <div className="stack">
          {dialog === 'wallet-account' ? walletAccounts.map(connection => <button key={`${connection.id}:${connection.publicKey?.toString()}`} className="btn full" disabled={!!busy || !connection.publicKey} title={connection.publicKey?.toString()} onClick={() => { closeDialog(); void run('Loading BULK accounts…', version => activateConnection(connection, version)); }}><code>{connection.publicKey ? shortKey(connection.publicKey.toString()) : 'Unavailable'}</code></button>) : wallets.map(option => <button key={option.id} className="btn full wallet-option" aria-label={option.name} disabled={!!busy} onClick={() => connect(option)}><Wallet size={17}/> {option.name}{option.name.toLowerCase() === 'backpack' && <span className="recommendation">Recommended</span>}{option.name.toLowerCase() === 'phantom' && <span className="wallet-limit">Main account only</span>}</button>)}
          {dialog === 'wallet' && wallets.length === 0 && <><p className="hint">No compatible wallet found. Install or enable Backpack in this browser, then refresh the list.</p><button className="btn full" onClick={() => setWallets(availableWallets())}>Refresh wallets</button></>}
          <a className="quiet-link" href="https://backpack.app/" target="_blank" rel="noreferrer">Get Backpack from its official website ↗</a><p className="hint">Connect the owner of your BULK account. Mobile and hardware wallets may not support message signing. Email login is not supported.</p>
          <button className="btn text full" onClick={closeDialog}>Cancel</button>
        </div>
      </DialogContent>
    </Dialog>
    <Dialog open={dialog === 'export' || dialog === 'import'} onOpenChange={open => { if (!open && !busyRef.current) closeDialog(); }}>
      <DialogContent className="vault-dialog" showCloseButton={!busy}>
        <DialogTitle>{dialog === 'export' ? 'Save encrypted backup' : 'Import saved key'}</DialogTitle>
        <DialogDescription>{dialog === 'export' ? 'Choose a unique passphrase. Keep it separately; we cannot recover it.' : 'Use your latest backup. It is opened locally and never submitted automatically.'}</DialogDescription>
        <form className="stack" onSubmit={event => { event.preventDefault(); void vaultAction(); }}>
          {dialog === 'import' && <><div className="backup-kind" role="group" aria-label="Backup type"><button className="btn" type="button" aria-pressed={importKind === 'json'} disabled={!!busy} onClick={() => { setImportKind('json'); setPassword(''); setDialogError(''); }}>JSON backup</button><button className="btn" type="button" aria-pressed={importKind === 'encrypted'} disabled={!!busy} onClick={() => { setImportKind('encrypted'); setPassword(''); setDialogError(''); }}>Encrypted backup</button></div><p className="hint">{importKind === 'json' ? 'You chose to open an unencrypted JSON file. No password needed; the file contains your private key.' : importKind === 'encrypted' ? 'Enter the password you chose when saving this encrypted backup.' : 'Choose the type you saved. The main backup button downloads JSON without a password.'}</p></>}
          {dialog === 'import' && <label className="field">Backup file<Input type="file" accept=".json,application/json" disabled={!!busy} onChange={e => setFile(e.target.files?.[0] ?? null)}/></label>}
          {(dialog === 'export' || importKind === 'encrypted') && <label className="field">{dialog === 'export' ? 'Password · 12+ characters' : 'Backup password'}<Input type="password" value={password} maxLength={1024} autoComplete={dialog === 'export' ? 'new-password' : 'off'} disabled={!!busy} onChange={e => setPassword(e.target.value)}/></label>}
          {dialog === 'export' && <label className="field">Confirm password<Input type="password" value={confirmPassword} maxLength={1024} autoComplete="new-password" disabled={!!busy} onChange={e => setConfirmPassword(e.target.value)}/></label>}

          {dialogError && <div role="alert" className="message error">{dialogError}</div>}
          <button className="btn primary full" type="submit" disabled={!!busy || dialog === 'import' && !importKind}>{busy && <LoaderCircle className="spin" size={17}/>} {busy || (dialog === 'export' ? 'Encrypt & download' : 'Import key')}</button>
          <button className="btn text full" type="button" disabled={!!busy} onClick={closeDialog}>Cancel</button>
        </form>
      </DialogContent>
    </Dialog>
    <AlertDialog open={dialog === 'plaintext' || dialog === 'revoke' || dialog === 'clear'} onOpenChange={open => { if (!open) closeDialog(); }}>
      <AlertDialogContent className="vault-dialog">
        <AlertDialogTitle>{dialog === 'revoke' ? 'Revoke this key?' : dialog === 'clear' ? 'Clear key from page?' : 'Export unencrypted key?'}</AlertDialogTitle>
        <AlertDialogDescription>{dialog === 'revoke' ? 'Your wallet will sign a request to remove this key from the selected account. Check its status after submission. Open positions stay open. Earlier signed registration requests are not cancelled by this action.' : dialog === 'clear' ? 'You will need your backup to restore this key. Clearing the page does not revoke BULK access.' : 'Anyone with this file can use your agent key. Only export it for your bot; keep it out of chats and shared folders.'}</AlertDialogDescription>
        {key && <code className="key-value">{NETWORKS[key.network].label} · {shortKey(key.account)}{'\n'}Agent: {key.publicKey}</code>}
        {dialog !== 'revoke' && <label className="checkrow"><Checkbox checked={acknowledged} onCheckedChange={v => setAcknowledged(v === true)}/><span>{dialog === 'clear' ? 'I have an up-to-date backup, including the last request.' : 'I understand this file contains an unencrypted private key.'}</span></label>}
        <button className="btn danger full" disabled={dialog !== 'revoke' && !acknowledged} onClick={() => {
          if (dialog === 'revoke') { closeDialog(); authorize('revoke'); }
          else if (dialog === 'clear') clearKey();
          else if (key) { saveFile(exportKey(key), `bulk-${key.network}-${key.publicKey.slice(0, 8)}.plaintext.json`); closeDialog(); setNotice('Bot JSON exported. Use the main backup button to save the latest recovery request.'); }
        }}>{dialog === 'revoke' ? 'Sign revoke request' : dialog === 'clear' ? 'Clear key' : 'Export unencrypted JSON'}</button>
        <button className="btn text full" onClick={closeDialog}>Cancel</button>
      </AlertDialogContent>
    </AlertDialog>
  </main>;
}
