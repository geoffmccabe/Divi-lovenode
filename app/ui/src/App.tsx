// LoveNode root: first run shows wallet Setup; once a wallet exists, the Shell
// (hybrid nav + screens). All trust-critical logic lives one layer down in the
// tested Rust crates; this only renders what they report.
import { useEffect, useState } from "react";
import { hasWallet } from "./api";
import { Shell } from "./Shell";
import { Setup } from "./screens/Setup";

export function App() {
  const [ready, setReady] = useState<boolean | null>(null);
  const check = () => hasWallet().then(setReady).catch(() => setReady(false));
  useEffect(() => { check(); }, []);

  if (ready === null) return <div className="content"><div className="sub">Loading…</div></div>;
  if (!ready) return <Setup onDone={() => setReady(true)} />;
  return <Shell />;
}
