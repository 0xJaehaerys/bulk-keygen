# BULK Keygen

Generate, register and revoke BULK agent keys with a Solana wallet.

[Open app](https://bulk-keygen.up.railway.app)

## Run locally

Requires Node.js 24+ and `zip`.

```sh
npm ci
npm run build
npm run local
```

Open the local URL printed in the terminal. For development, run `npm run dev`.
A prebuilt local ZIP is available from the app; see [local setup](README-LOCAL.md).

## How it works

Connect your wallet, choose the network and account, generate a key and save its backup. Sign the registration, save the updated backup, then submit. Keys are generated on your device; only public account data and signed requests go to BULK. Encrypted backups are optional.

Backpack supports subaccount keys. Phantom supports main-account keys only, which also cover its subaccounts. Use the latest backup for recovery; never replay an old registration after revoking access.

## Code

- `app/`, `components/`: React interface.
- `lib/`: BULK requests, key generation, wallet signing and backups.
- `scripts/`: local CLI, static servers and ZIP packaging.
- `tests/`: protocol, recovery and UI flow tests.

`npm test` runs tests. `npm run typecheck` checks TypeScript. The build is static HTML, JS and WASM in `dist/client`. `npm start` serves it on `PORT` (default 8080).

[MIT](LICENSE). Third-party notices are included in the build and local ZIP.
