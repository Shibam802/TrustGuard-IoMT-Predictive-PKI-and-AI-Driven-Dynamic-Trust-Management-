"""
demo_chain.py -- Demonstrates the on-chain TrustGuardLedger working
end-to-end: records a realistic ISSUE -> ROTATE -> REVOKE certificate
lifecycle as real transactions on the local blockchain, then reads them
back to prove they were recorded correctly and immutably.

This is the evidence script for the course submission -- run it and the
printed output (transaction hashes, block numbers, gas costs, retrieved
entries) is the demonstration of the module's working status.

Run (with `npx hardhat node` already running in another terminal):
    python3 demo_chain.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from chain_ledger import ChainLedger


def main():
    print("=" * 72)
    print("TrustGuard-IoMT -- On-Chain Ledger Demonstration")
    print("=" * 72)

    chain = ChainLedger()
    print(f"Connected to blockchain node. Contract address: {chain.address}")
    print(f"Writing from account: {chain.account}")
    print(f"Entries currently on-chain: {chain.entry_count()}")
    print("-" * 72)

    # Simulate the same lifecycle simulate.py / the FastAPI backend would
    # trigger: a device gets enrolled, later gets a predictive rotation,
    # then a confirmed breach and revocation.
    device_id = "device_demo_chain"

    print(f"\n[1/3] Recording ISSUE event for {device_id}...")
    r1 = chain.record_event("ISSUE", device_id, "cert_a1b2c3", "Initial enrollment")
    print(f"  tx_hash     = {r1['tx_hash']}")
    print(f"  block       = {r1['block_number']}")
    print(f"  gas_used    = {r1['gas_used']}")
    print(f"  status      = {r1['status']}")

    print(f"\n[2/3] Recording ROTATE event for {device_id}...")
    r2 = chain.record_event(
        "ROTATE", device_id, "cert_d4e5f6",
        "Predictive escalation: trend slope=-3.2, forecasted_score=38.5 within 2.1 steps"
    )
    print(f"  tx_hash     = {r2['tx_hash']}")
    print(f"  block       = {r2['block_number']}")
    print(f"  gas_used    = {r2['gas_used']}")
    print(f"  status      = {r2['status']}")

    print(f"\n[3/3] Recording REVOKE event for {device_id}...")
    r3 = chain.record_event(
        "REVOKE", device_id, "cert_d4e5f6",
        "Confirmed breach: current_score=18.2 < threshold=30.0. Device quarantined."
    )
    print(f"  tx_hash     = {r3['tx_hash']}")
    print(f"  block       = {r3['block_number']}")
    print(f"  gas_used    = {r3['gas_used']}")
    print(f"  status      = {r3['status']}")

    print("-" * 72)
    print(f"\nTotal entries now on-chain: {chain.entry_count()}")

    print(f"\nReading back full on-chain history for {device_id}:")
    history = chain.get_entries_for_device(device_id)
    for entry in history:
        print(f"  [{entry['index']}] {entry['event_type']:8s} "
              f"cert={entry['cert_id']:14s} "
              f"by={entry['recorded_by'][:10]}... "
              f"@ block_time={entry['timestamp']}")
        print(f"      detail: {entry['detail']}")

    print("\n" + "=" * 72)
    print("Demonstration complete. All events above are real transactions")
    print("mined on the local blockchain -- not simulated or mocked.")
    print("=" * 72)


if __name__ == "__main__":
    main()
