# TrustGuard-IoMT — complete project (backend + frontend + smart contract)

Predictive trust management for medical IoT devices, with every certificate event recorded on an
Ethereum-compatible smart contract (TrustGuardLedger) and a local SHA-256 hash chain.

## One-time setup
    pip install -r requirements.txt
    cd blockchain && npm install && npx hardhat compile && cd ..
    cd frontend   && npm install && cd ..
(If Hardhat cannot download the Solidity compiler: `node blockchain/scripts/manual_compile.js`, and add `--no-compile` to the hardhat commands.)

## Run the demo — 4 terminals, all from the `trustguard` folder
| # | Terminal | Command |
|---|----------|---------|
| 1 | Blockchain node | `cd blockchain` then `npx hardhat node`  (leave running) |
| 2 | Deploy contract | `cd blockchain` then `npx hardhat run scripts/deploy.js --network localhost` |
| 3 | Backend API | `python -m uvicorn server.app:app --port 8000` |
| 4 | Dashboard | `cd frontend` then `npm run dev`  -> open http://localhost:5173 |

Then in a 5th terminal start the simulated hospital devices:

    python run_fleet.py            # 8 devices, 2 of them attacked
    python run_fleet.py 10 80 0.3  # 10 devices, 80 steps, 0.3 s between steps

Watch the dashboard: trust curves fall, certificates rotate early (Tier 2), attacked devices are
revoked and quarantined (Tier 3), and each event appears in the ledger table with its block number, gas and
transaction hash. Click "Verify against blockchain" to cross-check the local ledger with the contract.
Restarting the Hardhat node wipes the chain: run the deploy command again, then restart the backend.

## Other commands
    python integration_demo.py                 # pipeline -> chain, printed evidence
    python blockchain/python_client/demo_chain.py
    cd blockchain && npx hardhat test          # 14 contract tests
    python -m pytest tests -q                  # bridge tests
    python evaluation/phase_eval.py            # reactive vs predictive evaluation
    python benchmarks/bench.py E1              # gas benchmark (E1..E7, one at a time)

## Layout
    server/app.py      FastAPI backend (/api/telemetry, devices, alerts, ledger, status, verify, reset)
    device_client.py, run_fleet.py   simulated devices
    frontend/          React + Vite dashboard (proxies /api to port 8000)
    ca/ trust_engine/ policy/ ledger/ data/   core pipeline
    blockchain/        contracts, deploy script, tests, python client
    evaluation/ benchmarks/                   experiments

Settings (environment variables): TG_TAU_C (30), TG_TAU_F (28), TG_WINDOW (10), TG_PERSIST (2 = two
consecutive low scores before quarantine), TG_RPC_URL (http://127.0.0.1:8545).
Contract address on a fresh local node: 0x5FbDB2315678afecb367f032d93F642f64180aa3 (a second deploy on the same node gets a new address; deployment.json always holds the current one).
