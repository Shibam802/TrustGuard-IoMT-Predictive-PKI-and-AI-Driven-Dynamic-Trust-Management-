"""
bench.py -- DA-9 measurements on a local Hardhat node.
Usage: python bench.py <experiment>   (E1 E2 E3 E4 E5 E6) ; merges into results.json
"""
import sys, json, time, statistics as st, random
from pathlib import Path
from web3 import Web3
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/"blockchain"/"python_client"))
OUT = Path(__file__).parent/"results.json"
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545", request_kwargs={"timeout": 120}))
acc = w3.eth.accounts[0]
def art(name):
    return json.load(open(ROOT/"blockchain"/"artifacts"/"contracts"/f"{name}.sol"/f"{name}.json"))
def deploy(name):
    a = art(name); C = w3.eth.contract(abi=a["abi"], bytecode=a["bytecode"])
    rc = w3.eth.wait_for_transaction_receipt(C.constructor().transact({"from": acc}))
    return w3.eth.contract(address=rc.contractAddress, abi=a["abi"]), rc.gasUsed
def save(k, v):
    d = json.load(open(OUT)) if OUT.exists() else {}
    d[k] = v; json.dump(d, open(OUT, "w"), indent=1)
def rec(c, t, dev="device_01", cert="cert_a1b2c3", detail="x"):
    t0 = time.perf_counter()
    h = c.functions.recordEvent(t, dev, cert, detail).transact({"from": acc})
    rc = w3.eth.wait_for_transaction_receipt(h)
    return rc, time.perf_counter() - t0
def pct(xs, p): xs = sorted(xs); return xs[min(len(xs)-1, int(p*len(xs)))]

exp = sys.argv[1]
if exp == "E1":
    res = {}
    for name in ("TrustGuardLedger", "TrustGuardLedgerCompact"):
        c, dep = deploy(name); res[name] = {"deploy_gas": dep}
        for L in (0, 50, 100, 200):
            row = {}
            for t, tn in enumerate(("ISSUE", "ROTATE", "REVOKE", "ESCALATE")):
                g = [rec(c, t, f"device_{i:02d}", f"cert_{i:06x}", "d"*L)[0].gasUsed for i in range(5)]
                row[tn] = st.mean(g)
            res[name][f"len{L}"] = row
    save("E1", res); print(json.dumps(res, indent=1))
elif exp == "E2":
    c, _ = deploy("TrustGuardLedger"); res = {}
    lat = []; t0 = time.perf_counter()
    for i in range(100):
        lat.append(rec(c, 0, f"device_{i%8:02d}", f"cert_{i:06x}", "Initial enrollment")[1])
    tot = time.perf_counter()-t0
    res["automine"] = {"n": 100, "mean_ms": 1000*st.mean(lat), "p50_ms": 1000*pct(lat,.5), "p95_ms": 1000*pct(lat,.95),
                       "max_ms": 1000*max(lat), "tx_per_s": 100/tot}
    for ms in (1000, 2000):
        w3.provider.make_request("evm_setAutomine", [False]); w3.provider.make_request("evm_setIntervalMining", [ms])
        lat = [rec(c, 0, f"device_{i}", f"cert_{i}", "enroll")[1] for i in range(8)]
        res[f"interval_{ms}ms"] = {"n": 8, "mean_ms": 1000*st.mean(lat), "max_ms": 1000*max(lat)}
    w3.provider.make_request("evm_setIntervalMining", [0]); w3.provider.make_request("evm_setAutomine", [True])
    save("E2", res); print(json.dumps(res, indent=1))
elif exp == "E3":
    res = {}
    for name in ("TrustGuardLedger", "TrustGuardLedgerCompact"):
        c, _ = deploy(name)
        w3.provider.make_request("evm_setAutomine", [False])
        hs = [c.functions.recordEvent(1, f"device_{i%50:02d}", f"cert_{i:06x}", "Predictive escalation: slope=-3.2, forecast=38.5 within 2.1 steps").transact({"from": acc, "gas": 400000}) for i in range(150)]
        w3.provider.make_request("evm_mine", [])
        blk = w3.eth.get_block("latest")
        res[name] = {"sent": 150, "included_in_first_block": len(blk.transactions), "block_gas_used": blk.gasUsed, "block_gas_limit": blk.gasLimit}
        w3.provider.make_request("evm_mine", [])
        res[name]["second_block_txs"] = len(w3.eth.get_block("latest").transactions)
        w3.provider.make_request("evm_setAutomine", [True])
    save("E3", res); print(json.dumps(res, indent=1))
elif exp == "E4":
    c, _ = deploy("TrustGuardLedger"); res = {}; n = 0
    for target in (50, 200, 500):
        while n < target:
            c.functions.recordEvent(n % 4, f"device_{n%10:02d}", f"cert_{n:06x}", "Predictive escalation: slope=-3.2, forecast=38.5").transact({"from": acc}); n += 1
        def tm(f, k):
            xs = []
            for _ in range(k):
                t0 = time.perf_counter(); f(); xs.append(time.perf_counter()-t0)
            return 1000*st.mean(xs)
        res[target] = {
            "entryCount_ms": tm(lambda: c.functions.entryCount().call(), 20),
            "getEntry_ms": tm(lambda: c.functions.getEntry(random.randrange(target)).call(), 20),
            "getEntriesForDevice_ms": tm(lambda: c.functions.getEntriesForDevice("device_03").call(), 5),
            "full_audit_s": tm(lambda: [c.functions.getEntry(i).call() for i in range(target)], 1)/1000,
        }
    save("E4", res); print(json.dumps(res, indent=1))
elif exp == "E5":
    from ledger.ledger import RevocationLedger
    from ledger.chain_bridge import DualLedger
    from chain_ledger import ChainLedger
    import chain_ledger, json as _j
    # deploy fresh full contract and point ChainLedger at it
    c, _ = deploy("TrustGuardLedger")
    dep = _j.load(open(ROOT/"blockchain"/"python_client"/"deployment.json")); dep["address"] = c.address
    tmp = Path(__file__).parent/"_dep.json"; _j.dump(dep, open(tmp, "w"))
    res = {}
    def rewrite(L, k, detail):
        L.entries[k].detail = detail; prev = L.GENESIS_HASH
        for e in L.entries: e.prev_hash = prev; e.entry_hash = e.compute_hash(); prev = e.entry_hash
    off = RevocationLedger()
    for i in range(100): off.append("REVOKE" if i % 10 == 0 else "ISSUE", f"device_{i%10:02d}", f"cert_{i}", "original reason")
    dual = DualLedger(ChainLedger(deployment_path=tmp))
    for i in range(100): dual.append("REVOKE" if i % 10 == 0 else "ISSUE", f"device_{i%10:02d}", f"cert_{i}", "original reason")
    a = {"A_offchain_only": {}, "B_dualledger": {}}
    # attack 1: naive edit of one entry
    off.entries[40].detail = "edited"; a["A_offchain_only"]["naive_edit_detected"] = not off.verify_chain()
    dual.entries[40].detail = "edited"; a["B_dualledger"]["naive_edit_detected"] = not dual.verify_chain()
    # reset then attack 2: rewrite entry + recompute all hashes
    off.entries[40].detail = "original reason"; dual.entries[40].detail = "original reason"
    rewrite(off, 40, "benign (forged)"); rewrite(dual, 40, "benign (forged)")
    a["A_offchain_only"]["rewrite_detected"] = not off.verify_chain()
    a["B_dualledger"]["rewrite_detected_by_chain_check"] = not dual.verify_against_chain()
    a["B_dualledger"]["rewrite_detected_by_local_check_only"] = not dual.verify_chain()
    # attack 3: stranger writes to the contract; any mutator to edit old entry?
    stranger = w3.eth.accounts[5]
    try:
        c.functions.recordEvent(0, "evil", "evil", "evil").transact({"from": stranger}); a["stranger_write_blocked"] = False
    except Exception as e:
        a["stranger_write_blocked"] = "not an authorized" in str(e)
    muts = [f["name"] for f in c.abi if f.get("type") == "function" and f["stateMutability"] not in ("view", "pure")]
    a["state_changing_functions"] = muts
    res["tamper"] = a
    # append timing
    L = RevocationLedger(); t0 = time.perf_counter()
    for i in range(2000): L.append("ISSUE", "d", "c", "x")
    res["append_offchain_us"] = 1e6*(time.perf_counter()-t0)/2000
    D = DualLedger(ChainLedger(deployment_path=tmp)); t0 = time.perf_counter()
    for i in range(30): D.append("ISSUE", "d", "c", "x")
    res["append_dual_ms"] = 1000*(time.perf_counter()-t0)/30
    t0 = time.perf_counter(); ok = dual.verify_against_chain(); res["verify_100_entries_s"] = time.perf_counter()-t0; res["verify_ok_before_attack"] = None
    save("E5", res); print(json.dumps(res, indent=1)); tmp.unlink()
elif exp == "E6":
    c, _ = deploy("TrustGuardLedgerCompact")
    c.functions.recordEvent(2, "device_01", "cert_x", "Confirmed breach: score 18.2").transact({"from": acc})
    ok = c.functions.verifyEntry(0, "device_01", "cert_x", "Confirmed breach: score 18.2").call()
    bad = c.functions.verifyEntry(0, "device_01", "cert_x", "Confirmed breach: score 99.0").call()
    save("E6", {"verify_true": ok, "verify_forged": bad}); print(ok, bad)
if exp == "E7":
    from ledger.chain_bridge import DualLedger
    from chain_ledger import ChainLedger
    c, _ = deploy("TrustGuardLedger")
    dep = json.load(open(ROOT/"blockchain"/"python_client"/"deployment.json")); dep["address"] = c.address
    tmp = Path(__file__).parent/"_dep.json"; json.dump(dep, open(tmp, "w"))
    D = DualLedger(ChainLedger(deployment_path=tmp)); res = {}
    for i in range(100): D.append("ISSUE", f"device_{i%10:02d}", f"cert_{i}", "original reason")
    t0 = time.perf_counter(); ok = D.verify_against_chain(); res["verify_100_s"] = time.perf_counter()-t0; res["verify_ok_clean"] = ok
    save("E7", res); print(res); tmp.unlink()
