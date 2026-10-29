"""
chain_ledger.py -- Python client for the on-chain TrustGuardLedger smart
contract, using web3.py.

This is the blockchain-backed counterpart to ledger/ledger.py (the
off-chain hash-chained ledger from the pre-blockchain implementation).
Where that module hash-chains entries in a Python list, this module
writes each certificate lifecycle event as a REAL transaction to a
deployed smart contract, giving tamper-evidence via the blockchain itself
rather than an in-memory hash chain.

Usage (from the FastAPI backend, or standalone):

    from blockchain.python_client.chain_ledger import ChainLedger

    chain = ChainLedger()  # loads deployment.json automatically
    tx_hash = chain.record_event("ISSUE", "device_01", "cert_abc123", "Initial enrollment")
    print(chain.get_entry(0))
    print(chain.entry_count())

Requires a running blockchain node (local Hardhat node by default, or a
public testnet -- see deployment.json / hardhat.config.js for how to
point this at one instead).
"""

import json
from pathlib import Path

from web3 import Web3

DEPLOYMENT_PATH = Path(__file__).parent / "deployment.json"

EVENT_TYPES = ["ISSUE", "ROTATE", "REVOKE", "ESCALATE"]
EVENT_TYPE_TO_INT = {name: i for i, name in enumerate(EVENT_TYPES)}


class ChainLedger:
    def __init__(self, rpc_url: str = "http://127.0.0.1:8545", account_index: int = 0,
                 deployment_path: Path = DEPLOYMENT_PATH):
        if not deployment_path.exists():
            raise FileNotFoundError(
                f"{deployment_path} not found. Run `npx hardhat run scripts/deploy.js "
                f"--network localhost` first to deploy the contract."
            )

        with open(deployment_path) as f:
            deployment = json.load(f)

        self.address = Web3.to_checksum_address(deployment["address"])
        self.abi = deployment["abi"]

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(
                f"Could not connect to blockchain node at {rpc_url}. "
                f"Is `npx hardhat node` running?"
            )

        self.contract = self.w3.eth.contract(address=self.address, abi=self.abi)
        self.account = self.w3.eth.accounts[account_index]

    def record_event(self, event_type: str, device_id: str, cert_id: str, detail: str) -> dict:
        """
        Submits a real transaction recording a certificate lifecycle event
        on-chain. Returns the transaction receipt (includes tx hash, block
        number, gas used -- useful as submission evidence).
        """
        if event_type not in EVENT_TYPE_TO_INT:
            raise ValueError(f"event_type must be one of {EVENT_TYPES}")

        tx_hash = self.contract.functions.recordEvent(
            EVENT_TYPE_TO_INT[event_type], device_id, cert_id, detail
        ).transact({"from": self.account})

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return {
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "status": "success" if receipt.status == 1 else "failed",
        }

    def entry_count(self) -> int:
        return self.contract.functions.entryCount().call()

    def get_entry(self, index: int) -> dict:
        entry = self.contract.functions.getEntry(index).call()
        return {
            "index": entry[0],
            "event_type": EVENT_TYPES[entry[1]],
            "device_id": entry[2],
            "cert_id": entry[3],
            "detail": entry[4],
            "timestamp": entry[5],
            "recorded_by": entry[6],
        }

    def get_entries_for_device(self, device_id: str) -> list:
        entries = self.contract.functions.getEntriesForDevice(device_id).call()
        return [
            {
                "index": e[0],
                "event_type": EVENT_TYPES[e[1]],
                "device_id": e[2],
                "cert_id": e[3],
                "detail": e[4],
                "timestamp": e[5],
                "recorded_by": e[6],
            }
            for e in entries
        ]

    def all_entries(self) -> list:
        return [self.get_entry(i) for i in range(self.entry_count())]


class ChainLedgerCompact(ChainLedger):
    """Client for TrustGuardLedgerCompact (hashes in storage, text in event logs).

    Same record_event() as ChainLedger, so DualLedger can use either. Reading an
    entry returns hashes; use verify_entry() to prove a given text matches it.
    """
    def __init__(self, rpc_url="http://127.0.0.1:8545", account_index=0,
                 deployment_path=None):
        super().__init__(rpc_url, account_index,
                         deployment_path or Path(__file__).parent / "deployment_compact.json")

    def get_entry(self, index: int) -> dict:
        e = self.contract.functions.getEntry(index).call()
        return {"index": index, "timestamp": e[0], "event_type": EVENT_TYPES[e[1]],
                "recorded_by": e[2], "device_hash": e[3].hex(),
                "cert_hash": e[4].hex(), "detail_hash": e[5].hex()}

    def verify_entry(self, index: int, device_id: str, cert_id: str, detail: str) -> bool:
        return self.contract.functions.verifyEntry(index, device_id, cert_id, detail).call()

    def get_entries_for_device(self, device_id: str) -> list:
        """Rebuilt from EntryRecorded event logs (storage keeps only hashes)."""
        logs = self.contract.events.EntryRecorded().get_logs(from_block=0)
        return [{"index": l.args.index, "event_type": EVENT_TYPES[l.args.eventType],
                 "device_id": l.args.deviceId, "cert_id": l.args.certId, "detail": l.args.detail}
                for l in logs if l.args.deviceId == device_id]
