// Overview: balance, staking status + start/stop, and recent activity (which is
// why LoveNode has no separate Transaction History screen).
import { useEffect, useState } from "react";
import {
  getStatus, getSummary, startStaking, stopStaking,
  type StakingStatus, type WalletSummary,
} from "../api";

function fmtDivi(sats: number): string {
  return (sats / 1e8).toLocaleString(undefined, { maximumFractionDigits: 4 });
}

export function Overview() {
  const [status, setStatus] = useState<StakingStatus | null>(null);
  const [summary, setSummary] = useState<WalletSummary | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    getStatus().then(setStatus).catch(() => {});
    getSummary().then(setSummary).catch(() => {});
  };
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const toggle = async () => {
    setBusy(true);
    try {
      if (status?.connected) await stopStaking();
      else await startStaking();
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const usd = summary?.usd_per_divi;
  const balDivi = summary ? summary.balance_sats / 1e8 : 0;

  return (
    <>
      <div className="card">
        <p className="h">Balance</p>
        <div className="balance">
          {summary ? fmtDivi(summary.balance_sats) : "—"}
          <span className="unit">DIVI</span>
        </div>
        {usd != null && <div className="sub">≈ ${(balDivi * usd).toFixed(2)} USD</div>}
      </div>

      <div className="card">
        <p className="h">Staking</p>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 12 }}>
          <span className={"dot-state " + (status?.connected ? "on" : "off")} />
          <span>{status?.headline ?? "Loading…"}</span>
        </div>
        <div style={{ display: "flex", gap: 16, marginBottom: 14 }}>
          <div><div className="sub">Eligible coins</div><b>{status?.eligible_coins ?? 0}</b></div>
          <div><div className="sub">Blocks won</div><b>{status?.blocks_won ?? 0}</b></div>
        </div>
        <button className="primary-btn" disabled={busy || !status?.has_wallet} onClick={toggle}>
          {status?.connected ? "Stop staking" : "Start staking"}
        </button>
      </div>

      <div className="card">
        <p className="h">Recent activity</p>
        {!summary || summary.recent.length === 0 ? (
          <div className="sub">No activity yet.</div>
        ) : (
          summary.recent.map((a) => (
            <div className="rowline" key={a.txid}>
              <span className="mono">{a.txid.slice(0, 12)}…</span>
              <span className={a.incoming ? "in" : "out"}>
                {a.incoming ? "+" : "−"}{fmtDivi(Math.abs(a.net_sats))} DIVI
              </span>
            </div>
          ))
        )}
      </div>
    </>
  );
}
