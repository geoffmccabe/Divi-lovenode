// Settings: My Nodes (which relay backs the wallet), Password, Recovery Phrase,
// and 2FA. My Nodes is live (relay URL); the others are shells for on-device
// features (app-lock PIN, phrase reveal behind unlock, 2FA) landing in a later
// slice.
import { useEffect, useState } from "react";
import { getStatus, setRelay } from "../api";

export function Settings() {
  const [relay, setRelayUrl] = useState("");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => { getStatus().then((s) => setRelayUrl(s.relay_url)).catch(() => {}); }, []);

  const saveRelay = async () => {
    setErr(""); setSaved(false);
    try { await setRelay(relay.trim()); setSaved(true); }
    catch (e) { setErr(String(e)); }
  };

  return (
    <>
      <div className="card">
        <p className="h">My Nodes</p>
        <p className="sub">The relay your wallet connects to. Use the hosted relay, or your own desktop node.</p>
        <label>Relay address</label>
        <input value={relay} onChange={(e) => setRelayUrl(e.target.value)} placeholder="wss://relay.divi.love" />
        {err && <p className="err">{err}</p>}
        {saved && <p className="sub">Saved.</p>}
        <div style={{ height: 10 }} />
        <button className="ghost-btn" onClick={saveRelay}>Save relay</button>
      </div>

      <div className="card">
        <p className="h">Security</p>
        <button className="ghost-btn" disabled>App password / PIN</button>
        <div style={{ height: 10 }} />
        <button className="ghost-btn" disabled>Show recovery phrase (unlock required)</button>
        <div style={{ height: 10 }} />
        <button className="ghost-btn" disabled>Two-factor (2FA)</button>
        <p className="sub" style={{ marginTop: 10 }}>These unlock-gated settings are wired on-device.</p>
      </div>
    </>
  );
}
