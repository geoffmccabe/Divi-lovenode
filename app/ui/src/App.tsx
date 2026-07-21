import { useEffect, useState } from "react";
import { inApp } from "./tauri";
import {
  getStatus,
  getDisclosures,
  startStaking,
  stopStaking,
  type StakingStatus,
  type Disclosures,
} from "./api";

// The whole UI. Deliberately small: it shows what the Rust core reports and
// offers Start/Stop. No staking judgement lives here — that is all one layer
// down in the tested crates.
export function App() {
  const [status, setStatus] = useState<StakingStatus | null>(null);
  const [disclosures, setDisclosures] = useState<Disclosures | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getDisclosures().then(setDisclosures).catch(() => {});
    let alive = true;
    const poll = async () => {
      try {
        const s = await getStatus();
        if (alive) setStatus(s);
      } catch {
        /* not in-app yet */
      }
    };
    poll();
    const id = setInterval(poll, 1000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  async function toggle() {
    if (!status) return;
    setBusy(true);
    setErr(null);
    try {
      if (status.connected) await stopStaking();
      else await startStaking();
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  if (!inApp()) {
    return (
      <div className="screen">
        <p className="note">Open LoveNode on your phone to stake.</p>
      </div>
    );
  }

  return (
    <div className="screen">
      <header className="header">
        <h1>LoveNode</h1>
        <p className="tagline">Stake DIVI from your phone.</p>
      </header>

      <section className="card status-card">
        <div className={`dot ${status?.connected ? "on" : "off"}`} />
        <p className="headline">{status?.headline ?? "Starting…"}</p>
      </section>

      {status?.has_wallet ? (
        <>
          <section className="stats">
            <Stat label="Eligible coins" value={status.eligible_coins} />
            <Stat label="Blocks won" value={status.blocks_won} />
          </section>

          <button className="primary" disabled={busy} onClick={toggle}>
            {status.connected ? "Stop staking" : "Start staking"}
          </button>
          {err && <p className="err">{err}</p>}

          {status.recent.length > 0 && (
            <section className="card">
              <h2>Recent</h2>
              <ul className="activity">
                {status.recent.map((a, i) => (
                  <li key={i} className={`act act-${a.kind}`}>
                    <span className="act-detail">{a.detail}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      ) : (
        <section className="card">
          <p className="note">
            Set up a staking wallet to begin. Your keys are created on this phone and
            never leave it.
          </p>
        </section>
      )}

      {disclosures && (
        <section className="card disclosures">
          <h2>Before you start</h2>
          <ul>
            {disclosures.lines.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
