// Send: four send types as pills. Send and Fast Send are live; Pin Code Send and
// Bearer are greyed "Coming soon" placeholders (the backend for those is not
// built yet — see docs/FOR-OTHER-AGENTS.md).
import { useState } from "react";
import { send, type SendResult } from "../api";

type Kind = "normal" | "fast" | "pin" | "bearer";
const KINDS: { id: Kind; label: string; soon?: boolean }[] = [
  { id: "normal", label: "Send" },
  { id: "fast", label: "Fast Send" },
  { id: "pin", label: "Pin Code", soon: true },
  { id: "bearer", label: "Bearer", soon: true },
];

export function Send() {
  const [kind, setKind] = useState<Kind>("normal");
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState<SendResult | null>(null);

  const submit = async () => {
    setErr(""); setDone(null);
    const amt = Number(amount);
    if (!address.trim() || !(amt > 0)) { setErr("Enter an address and an amount."); return; }
    setBusy(true);
    try {
      const res = await send(address.trim(), Math.round(amt * 1e8), kind === "fast" ? "fast" : "normal");
      setDone(res);
      setAddress(""); setAmount("");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="pill-row">
        {KINDS.map((k) => (
          <button
            key={k.id}
            className={"pill" + (kind === k.id ? " active" : "") + (k.soon ? " soon" : "")}
            onClick={() => (k.soon ? null : setKind(k.id))}
          >
            {k.label}{k.soon ? " ·" : ""}
          </button>
        ))}
      </div>

      {kind === "fast" && (
        <p className="sub" style={{ marginTop: 0 }}>
          Fast Send pays a priority fee and marks the payment so the receiver is
          pinged the moment it is sent.
        </p>
      )}

      <label>To address</label>
      <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="D…" />
      <label>Amount (DIVI)</label>
      <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" placeholder="0.0" />

      {err && <p className="err">{err}</p>}
      {done && (
        <p className="sub">
          Sent. Fee {(done.fee_sats / 1e8).toFixed(8)} DIVI.<br />
          <span className="mono">{done.txid.slice(0, 20)}…</span>
        </p>
      )}

      <div style={{ height: 12 }} />
      <button className="primary-btn" disabled={busy} onClick={submit}>
        {busy ? "Sending…" : kind === "fast" ? "Fast Send" : "Send"}
      </button>
    </div>
  );
}
