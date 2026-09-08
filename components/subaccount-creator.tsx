'use client';
import { useEffect, useRef, useState } from 'react';
import { Download, Plus, RefreshCw, Upload } from 'lucide-react';
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { BulkError, NETWORKS, assertOwner, friendlyError, readAccount, shortKey } from '@/lib/bulk';
import type { FullAccount, Network } from '@/lib/bulk';
import { exportSubaccountRequest, finalizeSubaccount, importSubaccountRequest, prepareSubaccount, subaccountName, submitSubaccount, verifySubaccount } from '@/lib/subaccounts';
import type { SubaccountRequest } from '@/lib/subaccounts';
import { authorizationError, signWithWallet, isPhantomWallet } from '@/lib/wallet';
import type { AuthorizationStep } from '@/lib/wallet';
import type { WalletConnection } from '@/lib/wallet-providers';

type Phase = 'form' | 'signed' | 'pending' | 'confirmed';
interface Props {
  network: Network; owner: string; hasKey: boolean; busy: boolean;
  wallet: () => WalletConnection | null;
  run: (label: string, task: (version: number) => Promise<void>) => Promise<void>;
  ensureContext: (version: number, owner?: string) => void;
  onPendingChange: (owner: string) => void;
  onVerified: (address: string, info: FullAccount) => void;
  onStopWaiting?: () => void;
}
export function SubaccountCreator(props: Props) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [attempt, setAttemptState] = useState<SubaccountRequest | null>(null);
  const [phase, setPhase] = useState<Phase>('form');
  const [saved, setSaved] = useState(false);
  const [address, setAddress] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [closeSaved, setCloseSaved] = useState(false);
  const attemptRef = useRef<SubaccountRequest | null>(null);
  const phaseRef = useRef<Phase>('form');
  const receiptTrusted = useRef(false);
  const revision = useRef(0);
  const closeSavedFor = useRef<SubaccountRequest | null>(null);
  const latestProps = useRef(props);
  latestProps.current = props;
  function update(value: SubaccountRequest | null, next: Phase) {
    attemptRef.current = value; phaseRef.current = next; setAttemptState(value); setPhase(next);
    closeSavedFor.current = null; setCloseSaved(false);
    props.onPendingChange(value && next !== 'confirmed' ? value.owner : '');
  }
  useEffect(() => {
    const preventLoss = (event: BeforeUnloadEvent) => {
      if (attemptRef.current && phaseRef.current !== 'confirmed') { event.preventDefault(); event.returnValue = ''; }
    };
    window.addEventListener('beforeunload', preventLoss);
    return () => { revision.current++; window.removeEventListener('beforeunload', preventLoss); };
  }, []);
  function execute(label: string, task: (version: number, localRevision: number) => Promise<void>) {
    if (latestProps.current.busy) return;
    const localRevision = revision.current;
    setError(''); setNotice('');
    void props.run(label, async version => {
      try { await task(version, localRevision); } catch (e) {
        if (localRevision !== revision.current) return;
        try { props.ensureContext(version); } catch { return; }
        setError(friendlyError(e));
      }
    });
  }
  function checkContext(version: number, localRevision: number, value?: SubaccountRequest) {
    props.ensureContext(version, value?.owner ?? props.owner);
    if (localRevision !== revision.current || latestProps.current.hasKey || (value && (value.network !== latestProps.current.network || attemptRef.current?.request !== value.request))) throw new BulkError('Account context changed. Keep the saved request.');
  }
  function resetRequest() {
    revision.current++;
    update(null, 'form'); receiptTrusted.current = false;
    setName(''); setAddress(''); setSaved(false); setError(''); setNotice(''); setOpen(false);
  }
  function closeRequest() {
    if (latestProps.current.busy || !attempt || attemptRef.current !== attempt || closeSavedFor.current !== attempt || !['signed', 'pending'].includes(phaseRef.current)) return;
    resetRequest();
  }
  function signCreation() {
    if (attemptRef.current || props.hasKey || !props.owner) return;
    execute('Preparing subaccount…', async (version, localRevision) => {
      let prepared: Awaited<ReturnType<typeof prepareSubaccount>> | undefined;
      let step: AuthorizationStep = 'account';
      try {
        if (isPhantomWallet(props.wallet()?.name ?? '')) throw new BulkError('Phantom cannot create subaccounts here. Use Backpack with the same owner address. Phantom supports main-account agent keys only.');
        const selectedName = subaccountName(name.trim());
        checkContext(version, localRevision);
        const master = await readAccount(props.network, props.owner);
        checkContext(version, localRevision); assertOwner(master, props.owner, props.owner);
        if (master.subAccounts && master.subAccounts.length >= 64) throw new BulkError('BULK allows up to 64 subaccounts per main account.');
        step = 'prepare'; prepared = await prepareSubaccount(props.network, props.owner, selectedName); checkContext(version, localRevision);
        step = 'wallet'; const signed = await signWithWallet(props.wallet()!, prepared.messageBytes); checkContext(version, localRevision);
        if (signed.publicKey && signed.publicKey.toString() !== props.owner) throw new BulkError('A different wallet signed the request.');
        step = 'verify'; const request = await finalizeSubaccount(prepared, new Uint8Array(signed.signature), props.owner, selectedName); checkContext(version, localRevision);
        update({ format: 'bulk-subaccount-request-v1', network: props.network, owner: props.owner, name: selectedName, request, address: null }, 'signed');
        setSaved(false); setNotice('Signed, not sent. Save the request before creating your subaccount.');
      } catch (e) {
        const issue = authorizationError(e, step, props.wallet()?.name);
        throw new BulkError(issue.message.replaceAll(' Your key is still here.', ''));
      } finally { prepared?.free(); }
    });
  }
  function download() {
    const value = attemptRef.current;
    if (!value || window.self !== window.top) return;
    const url = URL.createObjectURL(new Blob([exportSubaccountRequest(value)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = `bulk-${value.network}-create-${value.name}.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function resolveAddress(value: SubaccountRequest, target: string, version: number, localRevision: number) {
    checkContext(version, localRevision, value);
    const info = await verifySubaccount(value, target, undefined, !receiptTrusted.current); checkContext(version, localRevision, value);
    const resolved = { ...value, address: target };
    update(resolved, 'confirmed'); setAddress(target); props.onVerified(target, info);
    setNotice('Subaccount verified and selected. You can now create its agent key.');
  }
  function submit() {
    const value = attemptRef.current;
    if (!value || value !== attempt || !saved || !['signed', 'pending'].includes(phaseRef.current)) return;
    execute('Creating subaccount…', async (version, localRevision) => {
      checkContext(version, localRevision, value);
      const master = await readAccount(value.network, value.owner); checkContext(version, localRevision, value); assertOwner(master, value.owner, value.owner);
      // An address already known for this attempt needs readback, not another write.
      if (receiptTrusted.current && value.address) { await resolveAddress(value, value.address, version, localRevision); return; }
      update(value, 'pending');
      let returnedAddress: string | null = null;
      try { returnedAddress = await submitSubaccount(value, undefined, () => checkContext(version, localRevision, value)); } catch { /* Transport failures never prove rejection. */ }
      let retained = value;
      if (returnedAddress && localRevision === revision.current && attemptRef.current?.request === value.request) {
        // Keep a receipt after disconnect only while this exact request remains on the page.
        retained = { ...value, address: returnedAddress }; receiptTrusted.current = true; update(retained, 'pending'); setAddress(returnedAddress);
      }
      checkContext(version, localRevision, retained);
      if (retained.address) await resolveAddress(retained, retained.address, version, localRevision);
      else setNotice('Creation is unconfirmed. Keep this request. Check BULK or retry this same request; do not sign a replacement.');
    });
  }
  function checkStatus() {
    const value = attemptRef.current;
    if (!value || value !== attempt) return;
    execute('Checking subaccount…', async (version, localRevision) => {
      const target = receiptTrusted.current && value.address ? value.address : address.trim();
      if (!target) throw new BulkError('Paste the subaccount public address from BULK to check it.');
      await resolveAddress(value, target, version, localRevision);
    });
  }
  function restore(file: File | undefined) {
    if (!file || attemptRef.current || props.hasKey) return;
    execute('Opening creation request…', async (version, localRevision) => {
      if (file.size > 8192) throw new BulkError('Creation request file too large. Maximum size: 8 KB.');
      const restored = await importSubaccountRequest(await file.text()); checkContext(version, localRevision);
      if (restored.network !== props.network) throw new BulkError(`Select ${NETWORKS[restored.network].label} before opening this request.`);
      if (restored.owner !== props.owner) throw new BulkError('Connect the main wallet that signed this request.');
      receiptTrusted.current = false; update(restored, 'pending'); setSaved(true); setAddress(restored.address ?? '');
      setNotice('Request restored. Nothing was sent. Check its status before retrying.');
    });
  }
  if ((props.hasKey || !props.owner) && !attempt) return null;
  const ready = !!props.owner && (!attempt || props.owner === attempt.owner) && !props.hasKey;
  return <>
    <button className="btn text full" disabled={props.busy} onClick={() => setOpen(true)}><Plus size={16}/>{attempt ? phase === 'confirmed' ? 'Subaccount details' : 'Continue subaccount creation' : 'Create subaccount'}</button>
    <Dialog open={open} onOpenChange={value => { if (!props.busy) setOpen(value); }}>
      <DialogContent className="vault-dialog" showCloseButton={!props.busy}>
        <DialogTitle>{attempt ? 'Subaccount creation' : 'Create subaccount'}</DialogTitle>
        <DialogDescription>{attempt ? `${NETWORKS[attempt.network].label} · ${attempt.name} · Owner ${shortKey(attempt.owner)}` : 'Create an empty BULK subaccount. Your main wallet signs the request. No funds are transferred.'}</DialogDescription>
        <div className="stack">
          {!attempt ? <>
            {isPhantomWallet(props.wallet()?.name ?? '') && <p className="hint account-note">Phantom cannot create subaccounts here. Switch to Backpack with the same owner address to create a subaccount and its agent key.</p>}
            <form className="stack" onSubmit={event => { event.preventDefault(); signCreation(); }}>
              <label className="field">Name<Input value={name} maxLength={32} placeholder="my-bot" autoComplete="off" pattern={'[A-Za-z0-9_\\-]{1,32}'} required disabled={props.busy} onChange={event => setName(event.target.value)}/></label>
              <p className="hint">1–32 letters, numbers, hyphens or underscores.</p>
              <button className="btn primary full" type="submit" disabled={props.busy || !ready || isPhantomWallet(props.wallet()?.name ?? '')}>Sign creation request</button>
            </form>
            <label className="field"><span><Upload size={14} className="inline"/> Resume a saved creation request</span><Input type="file" accept=".json,application/json" disabled={props.busy || !ready} onChange={event => { restore(event.target.files?.[0]); event.target.value = ''; }}/></label>
          </> : <>
            <p className="hint">{phase === 'signed' ? 'Signed · not sent' : phase === 'confirmed' ? 'Subaccount verified' : 'Status unconfirmed'}</p>
            {attempt.address && <code className="key-value">{attempt.address}</code>}
            <button className="btn full" onClick={download}><Download size={16}/> Save creation request</button>
            <p className="hint">Keep this file to resume after closing the page. It contains a signed creation request, not a private key.</p>
            {phase === 'signed' && <label className="checkrow"><Checkbox checked={saved} disabled={props.busy} onCheckedChange={value => setSaved(value === true)}/><span>I saved this request.</span></label>}
            {phase === 'pending' && !receiptTrusted.current && <label className="field">Subaccount address, if already created<Input value={address} autoComplete="off" placeholder="Public address from BULK" disabled={props.busy} onChange={event => setAddress(event.target.value)}/></label>}
            {phase === 'pending' && <button className="btn full" disabled={props.busy || !ready} onClick={checkStatus}><RefreshCw size={16}/> Check subaccount</button>}
            {phase !== 'confirmed' && !receiptTrusted.current && <button className="btn primary full" disabled={props.busy || !ready || !saved} onClick={submit}>{phase === 'signed' ? 'Create subaccount' : 'Retry original request'}</button>}
            {!ready && phase !== 'confirmed' && <p className="hint">Reconnect the owner wallet to continue. Your request is still here.</p>}
            {phase === 'confirmed' && <button className="btn primary full" disabled={props.busy} onClick={() => { if (!latestProps.current.busy && attemptRef.current === attempt && phaseRef.current === 'confirmed') resetRequest(); }}>Continue to agent key</button>}
            {(phase === 'signed' || phase === 'pending') && <details className="guide-details"><summary>Close this request from the page</summary><div className="stack guide-detail-body">
              <p className="hint">Save the latest creation request first. Closing it here does not cancel its signature or a submitted request. Restore the file to check status or retry the same request; do not sign a replacement.</p>
              <label className="checkrow"><Checkbox checked={closeSaved} disabled={props.busy} onCheckedChange={value => { if (latestProps.current.busy || attemptRef.current !== attempt) return; closeSavedFor.current = value === true ? attempt : null; setCloseSaved(value === true); }}/><span>I saved the latest creation request and can restore it.</span></label>
              <button className="btn full" disabled={props.busy || !closeSaved} onClick={closeRequest}>Close request from page</button>
            </div></details>}
          </>}
          {notice && <p role="status" className="message">{notice}</p>}
          {error && <p role="alert" className="message error">{error}</p>}
          {props.busy && <><p role="status" className="hint">Complete any open wallet request, then wait for BULK.</p>{props.onStopWaiting && <><button className="btn full" type="button" onClick={props.onStopWaiting}>Stop waiting</button><p className="hint">Stopping the wait does not cancel a signed or submitted request.</p></>}</>}
          <button className="btn text full" disabled={props.busy} onClick={() => setOpen(false)}>Close</button>
        </div>
      </DialogContent>
    </Dialog>
  </>;
}
