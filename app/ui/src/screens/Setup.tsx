// First run: create a new wallet (shows the 12-word phrase ONCE) or restore from
// an existing phrase. No wallet can be used until this is done.
import { useState } from "react";
import { createWallet, restoreWallet } from "../api";

export function Setup({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<"choose" | "created" | "restore">("choose");
  const [phrase, setPhrase] = useState("");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const create = async () => {
    setBusy(true); setErr("");
    try { setPhrase(await createWallet()); setMode("created"); }
    catch (e) { setErr(String(e)); } finally { setBusy(false); }
  };
  const restore = async () => {
    setBusy(true); setErr("");
    try { await restoreWallet(input.trim()); onDone(); }
    catch (e) { setErr(String(e)); } finally { setBusy(false); }
  };

  if (mode === "created") {
    return (
      <div className="content"><div className="card">
        <p className="h">Your recovery phrase</p>
        <p className="sub">Write these 12 words down and keep them safe. They are the ONLY way to restore your wallet. We cannot recover them for you.</p>
        <div className="mono" style={{ margin: "16px 0", lineHeight: 1.8 }}>{phrase}</div>
        <button className="primary-btn" onClick={onDone}>I've written it down</button>
      </div></div>
    );
  }
  if (mode === "restore") {
    return (
      <div className="content"><div className="card">
        <p className="h">Restore from recovery phrase</p>
        <label>Enter your 12-word phrase</label>
        <textarea value={input} onChange={(e) => setInput(e.target.value)} rows={3} />
        {err && <p className="err">{err}</p>}
        <div style={{ height: 12 }} />
        <button className="primary-btn" disabled={busy} onClick={restore}>Restore wallet</button>
        <div style={{ height: 8 }} />
        <button className="ghost-btn" onClick={() => setMode("choose")}>Back</button>
      </div></div>
    );
  }
  return (
    <div className="content">
      <div className="card">
        <div className="coming"><div className="big">Welcome to LoveNode</div>
          <div>Stake DIVI from your phone.</div></div>
      </div>
      <div className="card">
        {err && <p className="err">{err}</p>}
        <button className="primary-btn" disabled={busy} onClick={create}>Create a new wallet</button>
        <div style={{ height: 10 }} />
        <button className="ghost-btn" onClick={() => setMode("restore")}>Restore from recovery phrase</button>
      </div>
    </div>
  );
}
