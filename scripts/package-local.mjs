import { cp, mkdir, mkdtemp, readFile, writeFile, rm, rename, readdir, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { resolve, join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { AGENT_SETUP_GUIDE } from '../lib/local-guide.ts';

// Deliberately package application files only, never the workspace or user exports.
export const LOCAL_FILES = [
  'lib/bulk.ts', 'lib/crypto.ts', 'lib/vault.ts', 'scripts/keygen.mjs',
  'scripts/serve-local.mjs', 'START.mjs', 'START-HERE.html', 'README-LOCAL.md',
  'licenses/bulk-keychain-MIT.txt', 'licenses/shadcn-MIT.txt', 'LICENSE',
  ...['bs58', 'base-x'].flatMap(name => ['package.json', 'src/esm/index.js', 'src/cjs/index.cjs', 'src/cjs/index.d.ts'].map(file => `node_modules/${name}/${file}`)),
  'node_modules/bs58/LICENSE', 'node_modules/base-x/LICENSE.md',
  ...['package.json', 'bulk_keychain_wasm.js', 'bulk_keychain_wasm_bg.wasm'].map(file => `node_modules/bulk-keychain-wasm/${file}`),
];
const PUBLIC_FILES = ['index.html', 'favicon.svg', '_headers', 'licenses/wallet-standard-APACHE-2.0.txt', 'licenses/THIRD-PARTY-NOTICES.txt'];

async function copyFile(from, to, optional = false) {
  let info;
  try { info = await lstat(from); } catch (error) { if (optional && error.code === 'ENOENT') return; throw error; }
  if (!info.isFile() || await realpath(from) !== from) throw new Error(`Package input must be a regular file without symlinks: ${from}`);
  await mkdir(dirname(to), { recursive: true });
  await cp(from, to);
}

async function copyAssets(from, to) {
  if (!(await lstat(from)).isDirectory() || await realpath(from) !== from) throw new Error('Static assets must be a real directory without symlinks.');
  for (const entry of await readdir(from, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) throw new Error('Unexpected hidden file in static assets.');
    const source = join(from, entry.name), target = join(to, entry.name);
    if (entry.isDirectory()) await copyAssets(source, target);
    else if (entry.isFile() && ['.js', '.css', '.wasm'].includes(extname(entry.name))) await copyFile(source, target);
    else throw new Error(`Unexpected static asset: ${entry.name}`);
  }
}

export async function packageLocal(project = fileURLToPath(new URL('../', import.meta.url))) {
  project = await realpath(project);
  const temporary = await mkdtemp(join(tmpdir(), 'bulk-local-package-'));
  const stage = join(temporary, 'bulk-keygen-local');
  const target = resolve(project, 'outputs/bulk-keygen-local.zip');
  try {
    await mkdir(stage);
    for (const name of LOCAL_FILES) await copyFile(join(project, name), join(stage, name));
    // No recursive dist/client copy: previous downloads, keys and hosting metadata stay out.
    for (const name of PUBLIC_FILES) await copyFile(join(project, 'dist/client', name), join(stage, 'dist/client', name), name !== 'index.html');
    await copyAssets(join(project, 'dist/client/assets'), join(stage, 'dist/client/assets'));
    // A single public template feeds the copy button and both downloadable guides.
    // It is never populated from a user's key, wallet, or recovery state.
    await writeFile(join(stage, 'AGENT-SETUP.txt'), AGENT_SETUP_GUIDE);
    await mkdir(join(stage, 'dist/client/guides'), { recursive: true });
    await writeFile(join(stage, 'dist/client/guides/agent-setup.txt'), AGENT_SETUP_GUIDE);
    await writeFile(join(stage, 'package.json'), JSON.stringify({ name: 'bulk-keygen-local', private: true, type: 'module', engines: { node: '>=24' }, scripts: { start: 'node START.mjs', local: 'node START.mjs', keygen: 'node scripts/keygen.mjs' } }, null, 2));
    await writeFile(join(stage, '.gitignore'), 'keys/\n.env*\n*.pem\n');
    execFileSync('zip', ['-q', '-r', join(temporary, 'package.zip'), 'bulk-keygen-local'], { cwd: temporary, env: { ...process.env, COPYFILE_DISABLE: '1' } });
    const bytes = await readFile(join(temporary, 'package.zip'));
    const checksum = createHash('sha256').update(bytes).digest('hex') + '  bulk-keygen-local.zip\n';
    await mkdir(dirname(target), { recursive: true });
    await rename(join(temporary, 'package.zip'), target);
    await writeFile(target + '.sha256', checksum);
    const downloads = join(project, 'dist/client/downloads');
    await mkdir(downloads, { recursive: true });
    await cp(target, join(downloads, 'bulk-keygen-local.zip'));
    await writeFile(join(downloads, 'bulk-keygen-local.zip.sha256'), checksum);
    await mkdir(join(project, 'dist/client/guides'), { recursive: true });
    await writeFile(join(project, 'dist/client/guides/agent-setup.txt'), AGENT_SETUP_GUIDE);
    return target;
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.stdout.write(await packageLocal() + '\n');
