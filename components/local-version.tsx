'use client';
import { useEffect, useState } from 'react';
import { Check, Copy, Download, Monitor, ShieldCheck } from 'lucide-react';
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AGENT_SETUP_GUIDE, NODE_PREFIX } from '@/lib/local-guide';

export function LocalVersion() {
  const [local, setLocal] = useState(false);
  const [open, setOpen] = useState(false);
  const [os, setOs] = useState('macos');
  const [copied, setCopied] = useState('');
  const [copyError, setCopyError] = useState('');
  useEffect(() => {
    setLocal(['127.0.0.1', 'localhost', '[::1]'].includes(window.location.hostname));
    const ua = navigator.userAgent;
    setOs(/Android|iPhone|iPad|iPod/.test(ua) || (/Mac/.test(ua) && navigator.maxTouchPoints > 1) ? 'mobile' : /Win/.test(ua) ? 'windows' : /Linux/.test(ua) ? 'linux' : 'macos');
  }, []);
  async function copy(value: string, label: string) {
    try { await navigator.clipboard.writeText(value); setCopied(label); setCopyError(''); }
    catch { setCopied(''); setCopyError('Clipboard unavailable. Select and copy the text below.'); }
  }
  return <>
    <section className="local-version" aria-label="Local version">
      <div className="local-heading"><Monitor size={18}/><h2>{local ? 'Running locally' : 'Run locally'}</h2><span className="recommendation">{local ? 'On this device' : 'Recommended'}</span></div>
      <p className="hint">{local ? 'This saved copy runs on your computer. No automatic code updates.' : 'Use a saved copy on your computer to reduce reliance on hosted code.'}</p>
      <div className="local-actions">
        {!local && <a className="btn" href="/downloads/bulk-keygen-local.zip" download="bulk-keygen-local.zip"><Download size={16}/> Download ZIP</a>}
        <button className="btn text" onClick={() => setOpen(true)}>{local ? 'Setup & safety guide' : 'Setup guide'} <span aria-hidden="true">↗</span></button>
      </div>
      {!local && <p className="hint">macOS · Windows · Linux · Node.js 24+ required</p>}
    </section>
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="vault-dialog local-dialog">
        <DialogTitle>Run BULK Keygen locally</DialogTitle>
        <DialogDescription>Open Terminal anywhere. Type node, add a space, and drag START.mjs into the window. No folder commands. Node.js 24+ is required.</DialogDescription>
        <Tabs value={os} onValueChange={value => { setOs(String(value)); setCopied(''); setCopyError(''); }}>
          <TabsList className="os-tabs" aria-label="Operating system">
            <TabsTrigger value="macos">macOS</TabsTrigger><TabsTrigger value="windows">Windows</TabsTrigger><TabsTrigger value="linux">Linux</TabsTrigger><TabsTrigger value="mobile">Mobile</TabsTrigger>
          </TabsList>
          <TabsContent value="macos" className="guide-content">
            <ol><li>Install <a href="https://nodejs.org/en/download" target="_blank" rel="noreferrer">Node.js 24+ from nodejs.org</a> if needed. Choose the macOS installer for your Mac.</li><li>{local ? 'Use the folder containing this extracted local app.' : 'Download the ZIP below. Double-click to extract it into a new folder.'}</li><li>Press ⌘ Space, type Terminal, and press Return. It can open in any folder.</li><li>Type <code>node</code> plus one space. Drag the <strong>START.mjs file</strong> into the terminal input area, then press Enter.</li></ol>
            <p className="hint">No .command launcher is needed. This ZIP is not a notarized Mac app. Leave Gatekeeper enabled.</p>
          </TabsContent>
          <TabsContent value="windows" className="guide-content">
            <ol><li>Install <a href="https://nodejs.org/en/download" target="_blank" rel="noreferrer">Node.js 24+ from nodejs.org</a> if needed, then reopen your terminal.</li><li>Right-click the downloaded ZIP → Extract All. Open the extracted <code>bulk-keygen-local</code> folder.</li><li>Open Windows Terminal with a PowerShell or Command Prompt tab. Use a normal window, not Administrator or WSL.</li><li>Type <code>node</code> plus one space. Drag the <strong>START.mjs file</strong> into the terminal input area, then press Enter.</li></ol>
            <p className="hint">If dragging does not work, Shift-right-click START.mjs → Copy as path, then paste after node and a space. Keep the path quotes. No PowerShell policy changes are needed.</p>
          </TabsContent>
          <TabsContent value="linux" className="guide-content">
            <ol><li>Install <a href="https://nodejs.org/en/download" target="_blank" rel="noreferrer">Node.js 24+</a> using a trusted package source. Check with <code>node --version</code>.</li><li>Extract the ZIP into a new folder.</li><li>Open your terminal. You do not need to change its current folder.</li><li>Type <code>node</code> plus one space. Drag the <strong>START.mjs file</strong> into the terminal input area, then press Enter.</li></ol>
            <p className="hint">If your terminal does not accept dragged files, open the extracted folder with Open in Terminal and run node START.mjs. No sudo or npm install is needed.</p>
          </TabsContent>
          <TabsContent value="mobile" className="guide-content stack">
            <p>The local ZIP is for a desktop computer. It is not an iPhone or Android app.</p>
            <p className="hint">For local use, download it on macOS, Windows or Linux. Keep the server private to that computer; do not expose it to your phone over Wi-Fi.</p>
            <p className="hint">Mobile wallet signing has not been verified. Opening this site in a wallet’s own browser may work; ordinary Safari/Chrome wallet handoff is not implemented. Phantom’s subaccount restriction still applies in this tool.</p>
          </TabsContent>
        </Tabs>
        {os !== 'mobile' && <div className="stack guide-launch">
          <div className="command-line"><code>node </code><span className="hint">+ drag START.mjs here</span><button className="btn icon" aria-label="Copy node and a space" onClick={() => void copy(NODE_PREFIX, 'command')}>{copied === 'command' ? <Check size={16}/> : <Copy size={16}/>}</button></div>
          <p className="hint">The copy button copies node and its trailing space. Drag the file next, then press Enter. Open the exact printed <code>127.0.0.1</code> URL in your desktop browser with Backpack. Keep Terminal open; Ctrl+C stops the app.</p>
          {!local && <a className="btn primary full" href="/downloads/bulk-keygen-local.zip" download="bulk-keygen-local.zip"><Download size={16}/> Download ZIP</a>}
          <p className="hint">START-HERE.html inside the ZIP repeats these steps offline. Keep START.mjs with the scripts and dist folders. The ZIP does not contain your keys or wallet session. Save an existing key before leaving its page. Generate a new key in the local copy, or restore your latest saved backup yourself.</p>
        </div>}
        <div className="guide-wallets"><strong>Use Backpack for subaccounts.</strong><p className="hint">Create subaccounts and their agent keys with Backpack on desktop. Phantom supports main-account agent keys only; those also cover all subaccounts. Connect the owner address of the intended BULK account.</p><a href="https://backpack.app/" target="_blank" rel="noreferrer">Get Backpack from its official website ↗</a></div>
        <details className="guide-details"><summary>Let an AI agent help with setup</summary><div className="stack guide-detail-body">
          <p className="hint">Copy these instructions into your agent chat. They contain setup guidance only, never your wallet or key data. The agent can explain the steps; you keep control of secrets and wallet approvals.</p>
          <button className="btn full" onClick={() => void copy(AGENT_SETUP_GUIDE, 'agent')}>{copied === 'agent' ? <Check size={16}/> : <Copy size={16}/>} {copied === 'agent' ? 'Instructions copied' : 'Copy instructions for an agent'}</button>
          <textarea className="agent-guide-text" aria-label="Agent setup instructions" readOnly value={AGENT_SETUP_GUIDE}/>
          <a className="quiet-link" href="/guides/agent-setup.txt" download="BULK-AGENT-SETUP.txt">Download agent instructions</a>
          <p className="hint">Never share your seed phrase, private key, backup file, backup password or signed requests with an agent.</p>
        </div></details>
        <details className="guide-details"><summary><ShieldCheck size={16}/> What local use protects</summary><div className="stack guide-detail-body">
          <p className="hint">Your agent private key is generated and handled on your device. This app sends public account data and signed requests directly to BULK, not your private key. It has no analytics, automatic key storage or automatic code updates.</p>
          <p className="hint">A saved copy avoids future changes to the hosted page. You still need to trust the initial download, bundled code, browser extensions and your computer.</p>
          <p className="hint">Plain JSON contains a usable private key. Store it privately, outside shared or synced folders. An encrypted backup protects the saved file; it cannot protect a key once unlocked by malicious software. Save the latest recovery file after signing. Clearing the page does not revoke access.</p>
          <p className="hint">Use a dedicated subaccount to limit scope. The browser setup needs account lookup; fully offline generation is available in the CLI described in README-LOCAL.md. Registering any key still needs BULK.</p>
        </div></details>
        <details className="guide-details"><summary>Verify the download & troubleshoot</summary><div className="stack guide-detail-body">
          {!local && <a className="quiet-link" href="/downloads/bulk-keygen-local.zip.sha256" download>Download ZIP checksum</a>}
          <p className="hint">Before extracting, compare the ZIP with its published SHA-256 checksum. In the folder containing both files:</p>
          <p className="hint">macOS: <code>shasum -a 256 -c bulk-keygen-local.zip.sha256</code><br/>Linux: <code>sha256sum -c bulk-keygen-local.zip.sha256</code><br/>Windows PowerShell: <code>Get-FileHash .\bulk-keygen-local.zip -Algorithm SHA256</code>, then compare with the checksum file.</p>
          <p className="hint">A checksum from this same site detects changed downloads, but cannot prove safety if the site itself was compromised.</p>
          <p className="hint">“node not found”: install Node.js, then reopen Terminal. “Cannot find module”: extract the entire ZIP and drag START.mjs again; do not move that file out on its own. Ports busy: add a space and <code>3030</code> after the dragged file path. Never stop unrelated apps to free a port.</p>
          <p className="hint">Wallet missing: open the printed URL in the desktop browser with your wallet extension installed, enable and unlock the extension, then use Connect wallet. Old Mac launcher blocked: use the Node command above. Keep Gatekeeper, SmartScreen and wallet checks enabled.</p>
        </div></details>
        <p role="status" className="hint">{copyError || (copied === 'command' ? 'node + space copied. Now drag START.mjs into Terminal, then press Enter.' : copied === 'agent' ? 'Setup instructions copied. No key data included.' : '')}</p>
      </DialogContent>
    </Dialog>
  </>;
}
