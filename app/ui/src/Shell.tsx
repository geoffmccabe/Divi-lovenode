// The hybrid navigation shell: a bottom tab bar for the primary screens
// (Overview / Send / Receive) plus a slide-out menu for everything else. The
// content area routes on the active screen id.
import { useEffect, useState } from "react";
import { getStatus } from "./api";
import { NAV, PRIMARY, type NavItem } from "./nav";
import { Overview } from "./screens/Overview";
import { Send } from "./screens/Send";
import { Receive } from "./screens/Receive";
import { Settings } from "./screens/Settings";
import { NetworkMap } from "./screens/NetworkMap";
import { ProofOfExistence } from "./screens/ProofOfExistence";
import { AddressBook } from "./screens/AddressBook";
import { ComingSoon } from "./screens/ComingSoon";

const TAB_ICON: Record<string, string> = { overview: "⌂", send: "↑", receive: "↓" };

function screenFor(item: NavItem) {
  if (item.comingSoon) return <ComingSoon label={item.label} />;
  switch (item.id) {
    case "overview": return <Overview />;
    case "send": return <Send />;
    case "receive": return <Receive />;
    case "poe": return <ProofOfExistence />;
    case "addressbook": return <AddressBook />;
    case "map": return <NetworkMap />;
    case "settings": return <Settings />;
    default: return <ComingSoon label={item.label} />;
  }
}

export function Shell() {
  const [active, setActive] = useState("overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [secure, setSecure] = useState(true);
  useEffect(() => { getStatus().then((s) => setSecure(s.secure_build)).catch(() => {}); }, []);
  const current = NAV.find((n) => n.id === active) ?? NAV[0];

  const go = (id: string) => { setActive(id); setMenuOpen(false); };

  return (
    <div className="shell">
      <div className="topbar">
        <button className="menu-btn" onClick={() => setMenuOpen(true)} aria-label="Menu">☰</button>
        <h1>{current.label}</h1>
        <span className="spacer" />
      </div>

      {!secure && (
        <div className="testbanner">TEST BUILD · testnet · do not use real funds</div>
      )}
      <div className="content">{screenFor(current)}</div>

      <nav className="tabbar">
        {PRIMARY.map((t) => (
          <button
            key={t.id}
            className={"tab" + (active === t.id ? " active" : "")}
            onClick={() => go(t.id)}
          >
            <span className="dot">{TAB_ICON[t.id] ?? "•"}</span>
            {t.label}
          </button>
        ))}
        <button className={"tab" + (!PRIMARY.some((p) => p.id === active) ? " active" : "")} onClick={() => setMenuOpen(true)}>
          <span className="dot">⋯</span>More
        </button>
      </nav>

      {menuOpen && (
        <>
          <div className="drawer-scrim" onClick={() => setMenuOpen(false)} />
          <div className="drawer">
            <h2>LoveNode</h2>
            {NAV.map((n) => (
              <button
                key={n.id}
                className={
                  "drawer-item" +
                  (active === n.id ? " active" : "") +
                  (n.comingSoon ? " soon" : "")
                }
                onClick={() => (n.comingSoon ? null : go(n.id))}
              >
                <span>{n.label}</span>
                {n.comingSoon && <span className="soon-tag">Coming soon</span>}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
