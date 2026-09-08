import { open, rename, unlink, mkdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, createPublicKey, sign, randomUUID } from 'node:crypto';
import init, { WasmKeypair, prepareAgentWallet } from 'bulk-keychain-wasm';
import bs58 from 'bs58';
import { BulkError, NETWORKS, publicKeyBytes, assertOwner, assertAgentAction, readAccount, readbackState, submitRegistration } from '../lib/bulk.ts';
import { decryptVault, exportBackup, MAX_VAULT_BYTES } from '../lib/vault.ts';
import { finalizeRegistration } from '../lib/crypto.ts';

let initialized;
async function sdk() {
  initialized ??= (async () => {
    const file = await open(new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url));
    try { await init({ module_or_path: await file.readFile() }); } finally { await file.close(); }
  })();
  return initialized;
}

async function readPrivate(path, limit = MAX_VAULT_BYTES) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > limit) throw new BulkError('Expected a small regular key file.');
    if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid())) throw new BulkError('Key file must belong to you and be private. Run chmod 600 on that file.');
    const bytes = Buffer.alloc(limit + 1);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead > limit) { bytes.fill(0); throw new BulkError('Key file is too large.'); }
    try { return bytes.subarray(0, bytesRead).toString('utf8'); } finally { bytes.fill(0); }
  } finally { await file.close(); }
}
async function writeNew(path, text) {
  await mkdir(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(text + '\n'); await file.sync(); }
  catch (error) { await file.close(); await unlink(path).catch(() => {}); throw error; }
  finally { await file.close(); }
}
async function updateBackup(path, original, text) {
  if (await readPrivate(path) !== original) throw new BulkError('Key file changed. Nothing was signed for submission.');
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeNew(temporary, text);
    if (await readPrivate(path) !== original) throw new BulkError('Key file changed. Recovery update cancelled.');
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}
async function loadBackup(path) {
  const original = await readPrivate(path);
  const backup = await decryptVault(original, '', true);
  await sdk();
  const bytes = bs58.decode(backup.key.secretKey);
  const pair = WasmKeypair.fromBytes(bytes.slice(0, 32));
  try {
    if (pair.pubkey !== backup.key.publicKey || pair.toBase58() !== backup.key.secretKey) throw new BulkError('Agent keypair does not match its public key.');
  } finally { pair.free(); bytes.fill(0); }
  if (backup.submission) await verifyRequest(backup);
  return { backup, original };
}
async function prepare(key, operation, nonce) {
  await sdk();
  const prepared = prepareAgentWallet(key.publicKey, operation === 'revoke', { signatureDomain: NETWORKS[key.network].domain, account: key.account, signer: key.owner, ...(nonce ? { nonce } : {}) });
  try {
    assertAgentAction(prepared.actions, key.publicKey, operation);
    if (prepared.account !== key.account || prepared.signer !== key.owner || prepared.messageBytes.at(-1) !== (key.network === 'mainnet' ? 1 : 2)) throw new BulkError('Invalid signing context.');
    return prepared;
  } catch (error) { prepared.free(); throw error; }
}
async function verifyRequest({ key, submission }) {
  const prepared = await prepare(key, submission.operation, submission.request.nonce);
  try { await finalizeRegistration(prepared, bs58.decode(submission.request.signature), key, submission.operation, submission.signatureMode); }
  finally { prepared.free(); }
}
async function ownerSigner(path, expectedOwner) {
  const text = (await readPrivate(path, 8192)).trim();
  let bytes;
  try {
    if (text.startsWith('[')) {
      const values = JSON.parse(text);
      if (!Array.isArray(values) || values.length !== 64 || values.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw Error();
      bytes = Uint8Array.from(values);
    } else bytes = bs58.decode(text);
    if (bytes.length !== 64) throw Error();
  } catch { throw new BulkError('Owner file must contain a 64-byte Solana JSON keypair or base58 keypair.'); }
  try {
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), bytes.slice(0, 32)]), format: 'der', type: 'pkcs8' });
    const publicBytes = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32));
    if (bs58.encode(publicBytes) !== expectedOwner || !Buffer.from(bytes.slice(32)).equals(Buffer.from(publicBytes))) throw new BulkError('The owner keypair does not match this BULK wallet.');
    return privateKey;
  } finally { bytes.fill(0); }
}

const usage = `BULK local keygen · Node.js 24+

Offline generation (no browser, wallet secret, or network request):
  npm run keygen -- generate --owner PUBLIC_ADDRESS --network testnet --out ./keys/agent.json
  Add --account SUBACCOUNT_PUBLIC_ADDRESS to target a subaccount.

Offline signing with an existing local owner keypair file:
  npm run keygen -- sign-register --file ./keys/agent.json --owner-keypair /path/to/owner.json
  npm run keygen -- sign-revoke --file ./keys/agent.json --owner-keypair /path/to/owner.json
  These commands save the signed request back to the agent file. They do not submit it.

Online, explicit submission of the saved request (one attempt only):
  npm run keygen -- submit --file ./keys/agent.json --confirm-network testnet
  npm run keygen -- status --file ./keys/agent.json

Only file paths are accepted for secrets. Key files must have permissions 600.
Use a local owner keypair only if you already manage one. Phantom cannot sign from this CLI.
Keep the latest agent file: a copy made before signing has no request to retry.
`;

export async function runCli(args, { fetcher = fetch, output = text => process.stdout.write(text + '\n') } = {}) {
  const [command, ...rest] = args;
  if (!command || command === 'help' || command === '--help') { output(usage); return; }
  const allowed = {
    generate: ['owner', 'account', 'network', 'out'],
    'sign-register': ['file', 'owner-keypair'],
    'sign-revoke': ['file', 'owner-keypair'],
    submit: ['file', 'confirm-network'],
    status: ['file'],
  };
  if (!allowed[command]) throw new BulkError('Unknown command. Run npm run keygen -- help.');
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i].startsWith('--') ? rest[i].slice(2) : '';
    if (!allowed[command].includes(name) || options[name] !== undefined || !rest[i + 1] || rest[i + 1].startsWith('--')) throw new BulkError('Invalid or duplicate option. Run npm run keygen -- help.');
    options[name] = rest[i + 1];
  }
  function required(name) { if (!options[name]) throw new BulkError(`Missing --${name}.`); return options[name]; }
  if (command === 'generate') {
    const owner = required('owner'), account = options.account ?? owner, network = options.network ?? 'testnet', out = required('out');
    publicKeyBytes(owner); publicKeyBytes(account);
    if (network !== 'testnet' && network !== 'mainnet') throw new BulkError('Network must be testnet or mainnet.');
    await sdk(); const pair = new WasmKeypair();
    try {
      const key = { owner, account, network, publicKey: pair.pubkey, secretKey: pair.toBase58(), createdAt: new Date().toISOString() };
      await writeNew(out, exportBackup(key));
      output(JSON.stringify({ network, owner, account, agentPublicKey: key.publicKey, state: 'not_registered', saved: resolve(out) }));
    } finally { pair.free(); }
    return;
  }
  const path = required('file');
  const lock = `${path}.lock`;
  let lockFile;
  try { lockFile = await open(lock, 'wx', 0o600); }
  catch (error) { if (error?.code === 'EEXIST') throw new BulkError('This key file is locked by another operation. Do not retry concurrently.'); throw error; }
  try {
  const { backup, original } = await loadBackup(path);
  const { key } = backup;
  if (command.startsWith('sign-')) {
    const operation = command === 'sign-register' ? 'register' : 'revoke';
    if (operation === 'register' && backup.submission) throw new BulkError('A request already exists. Submit that exact request or sign a revoke; do not create another registration.');
    const signer = await ownerSigner(required('owner-keypair'), key.owner);
    const prepared = await prepare(key, operation);
    try {
      const request = await finalizeRegistration(prepared, new Uint8Array(sign(null, prepared.messageBytes, signer)), key, operation);
      await updateBackup(path, original, exportBackup(key, { operation, request }));
      output(JSON.stringify({ network: key.network, account: key.account, agentPublicKey: key.publicKey, operation, state: 'signed_not_submitted', saved: resolve(path) }));
    } finally { prepared.free(); }
    return;
  }
  if (command === 'submit') {
    if (required('confirm-network') !== key.network) throw new BulkError('Network confirmation does not match the saved key.');
    if (!backup.submission) throw new BulkError('No signed request exists. Sign locally first.');
  }
  const info = await readAccount(key.network, key.account, fetcher);
  assertOwner(info, key.account, key.owner);
  if (command === 'status') {
    output(JSON.stringify({ network: key.network, agentPublicKey: key.publicKey, status: readbackState(info, key.publicKey, backup.submission?.operation ?? null) })); return;
  }
  const current = readbackState(info, key.publicKey, backup.submission.operation);
  if (current === 'active' || current === 'revoked') { output(JSON.stringify({ status: current, sent: false })); return; }
  let result = 'unknown';
  try { result = await submitRegistration(key.network, backup.submission.request, fetcher); } catch { /* Preserve request for explicit retry. */ }
  let status = 'pending';
  try {
    const fresh = await readAccount(key.network, key.account, fetcher); assertOwner(fresh, key.account, key.owner);
    status = readbackState(fresh, key.publicKey, backup.submission.operation);
  } catch { /* Transport failure never proves rejection or absence. */ }
  output(JSON.stringify({ network: key.network, requestResult: result, status, sent: true, recoveryFile: resolve(path) }));
  } finally { await lockFile.close(); await unlink(lock); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli(process.argv.slice(2)).catch(error => {
    const message = error instanceof BulkError ? error.message : error?.code === 'EEXIST' ? 'Output file already exists; choose a new path.' : error?.code === 'ENOENT' ? 'File not found. Check the file path.' : 'Local operation failed. Check the input files; no private key was printed.';
    process.stderr.write(message + '\n'); process.exitCode = 1;
  });
}
