// Receive: show a receiving address for funding. QR rendering is added on-device
// (a small QR lib) -- here we show the address and a copy button.
import { useEffect, useState } from "react";
import { addresses } from "../api";

export function Receive() {
  const [addrs, setAddrs] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  useEffect(() => { addresses().then(setAddrs).catch(() => {}); }, []);
  const addr = addrs[0] ?? "";

  return (
    <div className="card">
      <p className="h">Your receiving address</p>
      <p className="sub">Share this to receive DIVI. A new address is fine to reuse.</p>
      <div style={{ margin: "14px 0" }} className="mono">{addr || "—"}</div>
      <button
        className="ghost-btn"
        onClick={() => { if (addr) { navigator.clipboard?.writeText(addr); setCopied(true); } }}
      >
        {copied ? "Copied" : "Copy address"}
      </button>
      {/* QR: rendered on-device from `addr`. */}
    </div>
  );
}
