import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = 'dist/client';
const html = [];
function walk(dir) { for (const entry of readdirSync(dir, { withFileTypes: true })) { const p = join(dir, entry.name); if (entry.isDirectory()) walk(p); else if (p.endsWith('.html')) html.push(p); } }
walk(root);
if (!html.some(p => p === `${root}/index.html`)) throw new Error('Missing static index.html; refusing to package.');
const hashes = new Set();
for (const file of html) {
  const text = readFileSync(file, 'utf8');
  for (const match of text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/i.test(match[1]) && match[2]) hashes.add(`'sha256-${createHash('sha256').update(match[2]).digest('base64')}'`);
  }
}
const csp = ["default-src 'self'", `script-src 'self' 'wasm-unsafe-eval' ${[...hashes].sort().join(' ')}`, "style-src 'self' 'unsafe-inline'", "img-src 'self' data:", "font-src 'self' data:", "connect-src 'self' https://mainnet-api1.bulk.trade https://exchange-api.bulk.trade", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "worker-src 'none'"].join('; ');
// Apply CSP in HTML as well as HTTP headers for downloaded local copies.
const metaCsp = csp.replace("; frame-ancestors 'none'", '');
for (const file of html) {
  const text = readFileSync(file, 'utf8');
  if (!/<head>/i.test(text)) throw new Error(`Missing head in ${file}`);
  writeFileSync(file, text.replace(/<head>/i, `<head><meta http-equiv="Content-Security-Policy" content="${metaCsp}"><meta name="referrer" content="no-referrer">`));
}
writeFileSync(`${root}/_headers`, `/*\n  Content-Security-Policy: ${csp}\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Cache-Control: no-store\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n`);
console.log(`Static export verified: ${html.length} HTML pages, ${hashes.size} inline script hashes.`);

// Retain notices for copied UI code and the bundled WASM SDK.
for (const name of ["shadcn", "bulk-keychain"]) {
  appendFileSync(`${root}/licenses/THIRD-PARTY-NOTICES.txt`, `\n## ${name}\n\n` + readFileSync(`licenses/${name}-MIT.txt`, "utf8"));
}
