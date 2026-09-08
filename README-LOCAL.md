# Run BULK Keygen locally

Install [Node.js 24+](https://nodejs.org/en/download), download the local ZIP from the app and extract it into a new folder. The ZIP includes the built app and dependencies.

1. Open Terminal (macOS/Linux) or Windows Terminal.
2. Type `node `, then drag the extracted `START.mjs` file into the terminal.
3. Press Enter and open the printed local URL in the browser with your wallet extension.

Keep `START.mjs`, `scripts` and `dist` together. No npm install is needed. Keep the terminal open; Ctrl+C stops the app. If the default ports are busy, add `3030` after the script path.

Backpack supports subaccount keys. Phantom supports main-account keys only. Connect the original owner of your BULK account. Save your latest key backup before closing the page; plaintext JSON contains a private key. Account reads, registration and revocation require internet access.

## Command line

From the extracted folder:

```sh
node scripts/keygen.mjs help
node scripts/keygen.mjs generate --owner YOUR_PUBLIC_WALLET_ADDRESS --network testnet --out ./keys/agent.json
```

For a subaccount, add `--account YOUR_SUBACCOUNT_PUBLIC_ADDRESS`. Generation works offline and does not register the key. Use the CLI help for explicit signing, submission and recovery commands. Keep key files private and use the latest backup; do not replay an old registration after revoking access.
