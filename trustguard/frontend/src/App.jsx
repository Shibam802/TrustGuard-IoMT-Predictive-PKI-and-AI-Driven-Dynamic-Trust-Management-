import React, { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ReferenceLine, ResponsiveContainer, Legend } from "recharts";

const API = "/api";
const COLORS = ["#2f6fed", "#1f9d55", "#d98e04", "#8e44ad", "#16a3b8", "#e0559b", "#6c757d", "#b5651d", "#2c3e50", "#7fb800"];
const short = (h, n = 10) => (h ? `${h.slice(0, n)}…${h.slice(-4)}` : "—");

async function get(path) { const r = await fetch(API + path); return r.json(); }

export default function App() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [ledger, setLedger] = useState([]);
  const [verify, setVerify] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [s, d, a, l] = await Promise.all([get("/status"), get("/devices"), get("/alerts"), get("/ledger")]);
        if (!alive) return;
        setStatus(s); setDevices(d); setAlerts(a); setLedger(l); setErr(false);
      } catch { if (alive) setErr(true); }
    };
    tick(); const id = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const runVerify = async () => { setVerify("…"); setVerify(await get("/verify")); };
  const reset = async () => { await fetch(API + "/reset", { method: "POST" }); setVerify(null); };

  // merge per-device histories into one chart series keyed by step
  const maxLen = Math.max(0, ...devices.map((d) => d.history.length));
  const chartData = Array.from({ length: maxLen }, (_, i) => {
    const row = { step: i };
    devices.forEach((d) => { const off = d.history.length ? d.history[0].t : 0; const h = d.history.find((p) => p.t === i); if (h) row[d.device_id] = h.score; });
    return row;
  });

  const quarantined = devices.filter((d) => d.status === "QUARANTINED").length;
  const rotated = devices.reduce((a, d) => a + d.rotations, 0);
  const onchain = ledger.filter((e) => e.on_chain).length;

  return (
    <div className="wrap">
      <header>
        <h1>TrustGuard-IoMT<small>Predictive trust management with an on-chain certificate audit ledger</small></h1>
        <div className="pills">
          <span className="pill"><i className={"dot " + (err ? "bad" : "ok")} />Backend {err ? "offline" : "online"}</span>
          <span className="pill"><i className={"dot " + (status?.chain_connected ? "ok" : "warn")} />
            Blockchain {status?.chain_connected ? "connected" : "not connected (events queued)"}</span>
          {status?.contract && <span className="pill mono">contract {short(status.contract, 8)}</span>}
          <span className="pill"><i className={"dot " + (status?.hash_chain_valid ? "ok" : "bad")} />Hash chain {status?.hash_chain_valid ? "valid" : "BROKEN"}</span>
        </div>
      </header>

      <div className="kpis">
        <div className="card kpi"><span>Devices</span><b>{devices.length}</b></div>
        <div className="card kpi"><span>Early rotations (Tier 2)</span><b style={{ color: "var(--warn)" }}>{rotated}</b></div>
        <div className="card kpi"><span>Quarantined (Tier 3)</span><b style={{ color: "var(--bad)" }}>{quarantined}</b></div>
        <div className="card kpi"><span>Ledger entries (local)</span><b>{status?.local_entries ?? 0}</b></div>
        <div className="card kpi"><span>Confirmed on-chain</span><b>{status?.onchain_entries ?? onchain}</b></div>
        <div className="card kpi"><span>Pending queue</span><b>{status?.pending ?? 0}</b></div>
      </div>

      <div className="grid">
        <div className="card">
          <h2>Live trust scores (0–100)</h2>
          <div style={{ height: 300 }}>
            <ResponsiveContainer>
              <LineChart data={chartData}>
                <XAxis dataKey="step" tick={{ fontSize: 11 }} /><YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip /><Legend wrapperStyle={{ fontSize: 11 }} />
                {status && <ReferenceLine y={status.thresholds.tau_c} stroke="#d64545" strokeDasharray="4 3" label={{ value: "Tier 3 threshold", fontSize: 10, fill: "#d64545", position: "insideTopRight" }} />}
                {devices.map((d, i) => <Line key={d.device_id} type="monotone" dataKey={d.device_id} stroke={COLORS[i % COLORS.length]} dot={false} strokeWidth={d.status === "QUARANTINED" ? 2.5 : 1.5} connectNulls />)}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <h2>Live alerts</h2>
          <div className="scroll" style={{ maxHeight: 300 }}>
            {alerts.length === 0 && <div className="muted">No alerts yet. Start the fleet: <span className="mono">python run_fleet.py</span></div>}
            {alerts.map((a, i) => (
              <div key={i} className={"alert " + (a.tier.includes("3") ? "t3" : "")}>
                <b>{a.device}</b> — {a.tier.includes("3") ? "CONFIRMED BREACH: revoked and quarantined" : "PREDICTED BREACH: certificate rotated early"}
                <small>{a.time} · score {a.score} · forecast {a.forecast}</small>
              </div>))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h2>Devices</h2>
        <div className="scroll"><table><thead><tr><th>Device</th><th>Status</th><th>Trust</th><th>Forecast</th><th>Tier</th><th>Rotations</th><th>Certificate</th></tr></thead>
          <tbody>{devices.map((d) => (
            <tr key={d.device_id}><td>{d.device_id}</td><td><span className={"badge b-" + d.status}>{d.status}</span></td>
              <td>{d.score ?? "—"}</td><td>{d.forecast ?? "—"}</td><td className="muted">{d.tier.replace("TIER_", "T").replace("_", " ")}</td>
              <td>{d.rotations}</td><td className="mono">{d.cert_id}</td></tr>))}</tbody></table></div>
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <h2 style={{ margin: 0 }}>Certificate audit ledger (smart contract + hash chain)</h2>
          <div className="row">
            {verify && verify !== "…" && <span className="pill"><i className={"dot " + (verify.in_sync ? "ok" : "bad")} />{verify.in_sync ? "Local ledger matches the blockchain" : "MISMATCH or chain unavailable"} ({verify.seconds}s)</span>}
            <button onClick={runVerify}>Verify against blockchain</button>
            <button className="ghost" onClick={reset}>Reset demo</button>
          </div>
        </div>
        <div className="scroll"><table><thead><tr><th>#</th><th>Event</th><th>Device</th><th>Certificate</th><th>Reason</th><th>On-chain</th><th>Block</th><th>Gas</th><th>Tx hash</th></tr></thead>
          <tbody>{[...ledger].reverse().map((e) => (
            <tr key={e.index}><td>{e.index}</td><td><span className={"badge b-" + e.event}>{e.event}</span></td><td>{e.device}</td>
              <td className="mono">{e.cert}</td><td>{e.detail}</td>
              <td>{e.on_chain ? "✔" : <span className="muted">queued</span>}</td><td>{e.block ?? "—"}</td><td>{e.gas?.toLocaleString() ?? "—"}</td>
              <td className="mono">{short(e.tx_hash)}</td></tr>))}</tbody></table></div>
      </div>
    </div>
  );
}
