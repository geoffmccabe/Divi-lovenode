// Single typed boundary to the Rust backend. Everything else imports invoke().
type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

declare global {
  interface Window { __TAURI__?: { core: { invoke: Invoke } }; }
}

export function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const inv = window.__TAURI__?.core?.invoke;
  if (inv) return inv<T>(cmd, args);
  // Not inside the app → this is a BROWSER PREVIEW. Return sample data so the
  // screens can be clicked through on a laptop. This branch is only reachable
  // when Tauri is absent, so it never touches a real wallet or a real key.
  return previewInvoke<T>(cmd, args);
}
export const inApp = () => Boolean(window.__TAURI__?.core?.invoke);

// ── Browser-preview mock (dev only; unreachable inside the real app) ────────
const SAMPLE = {
  phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
  address: "DFakePreviewAddr1111111111111111",
  summary: {
    balance_sats: 2352199950000,
    received_sats: 18777799500000,
    usd_per_divi: 0.0005,
    recent: [
      { txid: "d4e0d34c2477aa11", net_sats: 41500000000, incoming: true, height: 891 },
      { txid: "16f8c09c64fcbb22", net_sats: -5000000000, incoming: false, height: 890 },
      { txid: "a20199093ab8cc33", net_sats: 41500000000, incoming: true, height: 860 },
    ],
  },
  status: {
    has_wallet: true, connected: false, relay_url: "wss://relay.divi.love",
    eligible_coins: 3, blocks_won: 1,
    headline: "Ready. Tap Start to begin staking.", recent: [],
  },
  disclosures: {
    lines: [
      "Rewards are proportional to your stake; a small balance wins rarely.",
      "Your phone must stay plugged in and connected to stake overnight.",
      "Your keys never leave this device.",
    ],
  },
};

function previewInvoke<T>(cmd: string, _args?: Record<string, unknown>): Promise<T> {
  const r = (v: unknown) => Promise.resolve(v as T);
  switch (cmd) {
    case "has_wallet": return r(false); // start at Setup so the whole flow is visible
    case "create_wallet": return r(SAMPLE.phrase);
    case "restore_wallet": return r(undefined);
    case "addresses": return r([SAMPLE.address]);
    case "status": return r(SAMPLE.status);
    case "disclosures": return r(SAMPLE.disclosures);
    case "get_summary": return r(SAMPLE.summary);
    case "send_coins": return r({ txid: "previewtxid00000000", fee_sats: 2460, kind: "normal" });
    case "set_relay":
    case "start_staking":
    case "stop_staking": return r(undefined);
    default: return Promise.reject(new Error(`preview: no mock for ${cmd}`));
  }
}
