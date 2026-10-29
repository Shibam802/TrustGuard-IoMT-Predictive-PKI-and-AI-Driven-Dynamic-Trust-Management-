# TrustGuard-IoMT — On-Chain Revocation Ledger (Blockchain Module)

Smart-contract-backed replacement for the off-chain hash-chained ledger
(`ledger/ledger.py`). Every certificate lifecycle event (ISSUE / ROTATE /
REVOKE / ESCALATE) is recorded as a real blockchain transaction instead
of a line in a local file.

See `../TrustGuard_Blockchain_Module_Report.docx` for the full course
submission write-up (purpose, architecture placement, technologies used,
and demonstration evidence).

## Setup

```bash
npm install
npx hardhat compile
```

If `npx hardhat compile` fails with a network/download error (this can
happen in sandboxed or restricted-network environments, since Hardhat
tries to download the Solidity compiler binary from
binaries.soliditylang.org), use the bundled fallback instead, which
compiles via the `solc` npm package (already installed from the npm
registry) and writes Hardhat-compatible artifacts directly:

```bash
node scripts/manual_compile.js
```

Then run everything with `--no-compile` so Hardhat uses those artifacts
rather than trying to recompile:

```bash
# Terminal 1 — local blockchain node
npx hardhat node

# Terminal 2 — deploy
npx hardhat run scripts/deploy.js --network localhost --no-compile

# Run the test suite
npx hardhat test --no-compile

# Run the Python demonstration (after installing web3.py: pip install web3)
cd python_client
python3 demo_chain.py
```

## Moving to a public testnet

`hardhat.config.js` has a commented example network block. To deploy to
a real testnet (e.g. Polygon Amoy, Ethereum Sepolia) instead of the local
Hardhat network:

1. Get an RPC URL (e.g. from Alchemy or Infura) for the testnet.
2. Create/fund a wallet with that testnet's faucet.
3. Add a network entry to `hardhat.config.js` with the RPC URL and the
   wallet's private key.
4. Run `npx hardhat run scripts/deploy.js --network <your-network-name>`.

No contract or Python client code changes are required — only configuration.

## Files

- `contracts/TrustGuardLedger.sol` — the smart contract
- `scripts/deploy.js` — deployment script (writes `python_client/deployment.json`)
- `scripts/manual_compile.js` — compiler fallback (see above)
- `test/TrustGuardLedger.test.js` — 10-test Hardhat/Chai suite
- `python_client/chain_ledger.py` — web3.py client (`ChainLedger` class)
- `python_client/demo_chain.py` — end-to-end demonstration script
