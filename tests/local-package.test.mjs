import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { LOCAL_FILES, packageLocal } from '../scripts/package-local.mjs';
import { AGENT_SETUP_GUIDE } from '../lib/local-guide.ts';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'bulk-package-test-'));
  const files = [...LOCAL_FILES, 'dist/client/index.html', 'dist/client/assets/app.js'];
  for (const file of files) {
    await mkdir(dirname(join(root, file)), { recursive: true });
    await writeFile(join(root, file), `fixture: ${file}`);
  }
  return root;
}

test('download package excludes key exports, hosting metadata and previous downloads on repeated builds', async () => {
  const root = await fixture();
  try {
    for (const file of ['keys/agent.json', '.env.local', 'dist/client/agent.json', 'dist/client/.internal/hosting.json', 'dist/client/downloads/old.zip', 'node_modules/bs58/agent.json']) {
      await mkdir(dirname(join(root, file)), { recursive: true });
      await writeFile(join(root, file), 'synthetic-secret-sentinel');
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const archive = await packageLocal(root);
      const bytes = await readFile(archive);
      const entries = execFileSync('unzip', ['-Z1', archive], { encoding: 'utf8' });
      assert.doesNotMatch(entries, /(?:\/downloads\/|\/keys\/|\/\.internal\/|\.env|agent\.json)/);
      assert.match(entries, /bulk-keygen-local\/dist\/client\/assets\/app\.js/);
      assert.match(entries, /bulk-keygen-local\/scripts\/serve-local\.mjs/);
      assert.match(entries, /bulk-keygen-local\/START\.mjs/);
      assert.match(entries, /bulk-keygen-local\/START-HERE\.html/);
      assert.doesNotMatch(entries, /Start Local\.command/);
      for (const file of ['AGENT-SETUP.txt', 'dist/client/guides/agent-setup.txt']) {
        assert.equal(execFileSync('unzip', ['-p', archive, `bulk-keygen-local/${file}`], { encoding: 'utf8' }), AGENT_SETUP_GUIDE);
      }
      assert.equal(await readFile(join(root, 'dist/client/guides/agent-setup.txt'), 'utf8'), AGENT_SETUP_GUIDE);
      const config = JSON.parse(execFileSync('unzip', ['-p', archive, 'bulk-keygen-local/package.json'], { encoding: 'utf8' }));
      assert.equal(config.engines.node, '>=24');
      assert.equal(config.scripts.start, 'node START.mjs');
      assert.equal(execFileSync('unzip', ['-p', archive, 'bulk-keygen-local/dist/client/index.html'], { encoding: 'utf8' }), 'fixture: dist/client/index.html');
      assert.deepEqual(await readFile(join(root, 'dist/client/downloads/bulk-keygen-local.zip')), bytes);
      const checksum = createHash('sha256').update(bytes).digest('hex') + '  bulk-keygen-local.zip\n';
      assert.equal(await readFile(archive + '.sha256', 'utf8'), checksum);
      assert.equal(await readFile(join(root, 'dist/client/downloads/bulk-keygen-local.zip.sha256'), 'utf8'), checksum);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('package fails closed on symlinked inputs and unexpected static files', async () => {
  const root = await fixture();
  try {
    const asset = join(root, 'dist/client/assets/app.js');
    await rm(asset);
    await symlink(join(root, 'lib/bulk.ts'), asset);
    await assert.rejects(packageLocal(root), /Unexpected static asset/);
    await rm(asset);
    await writeFile(asset, 'fixture');
    const secret = join(root, 'dist/client/assets/agent.json');
    await writeFile(secret, 'synthetic-secret-sentinel');
    await assert.rejects(packageLocal(root), /Unexpected static asset/);
    await rm(secret);
    await rm(join(root, 'lib'), { recursive: true });
    await mkdir(join(root, 'actual-lib'));
    await writeFile(join(root, 'actual-lib/bulk.ts'), 'fixture');
    await symlink(join(root, 'actual-lib'), join(root, 'lib'));
    await assert.rejects(packageLocal(root), /without symlinks/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
