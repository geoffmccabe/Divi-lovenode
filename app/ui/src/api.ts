// Typed calls into the Rust command surface. Mirrors app/src-tauri/src/commands.rs.
import { invoke } from "./tauri";

export interface ActivityLine {
  kind: string; // won | submitted | declined | info | error
  detail: string;
  unix_time: number;
}

export interface StakingStatus {
  has_wallet: boolean;
  connected: boolean;
  relay_url: string;
  eligible_coins: number;
  blocks_won: number;
  headline: string;
  recent: ActivityLine[];
  secure_build: boolean;
}

export interface Disclosures {
  lines: string[];
}

export const getStatus = () => invoke<StakingStatus>("status");
export const getDisclosures = () => invoke<Disclosures>("disclosures");
export const hasWallet = () => invoke<boolean>("has_wallet");
// returns the 12-word recovery phrase to show once
export const createWallet = () => invoke<string>("create_wallet");
export const restoreWallet = (phrase: string, passphrase = "") =>
  invoke<void>("restore_wallet", { phrase, passphrase });
export const addresses = () => invoke<string[]>("addresses");
export const setRelay = (url: string) => invoke<void>("set_relay", { url });
export const startStaking = () => invoke<void>("start_staking");
export const stopStaking = () => invoke<void>("stop_staking");

// ── Wallet view (Overview) ────────────────────────────────────────────────
export interface ActivityItem {
  txid: string;
  net_sats: number;
  incoming: boolean;
  height: number;
}
export interface WalletSummary {
  balance_sats: number;
  received_sats: number;
  usd_per_divi: number | null;
  recent: ActivityItem[];
}
export const getSummary = () => invoke<WalletSummary>("get_summary");

// ── Send ──────────────────────────────────────────────────────────────────
// kind: "normal" | "fast" (pin_code and bearer are placeholders, not sent)
export interface SendResult { txid: string; fee_sats: number; kind: string }
export const send = (address: string, amountSats: number, kind: "normal" | "fast") =>
  invoke<SendResult>("send_coins", { address, amountSats, kind });

// NOTE for the Android build: get_summary and send_coins are new Tauri commands
// that wrap lovenode-relay::wallet_view and lovenode-phone::send. They are wired
// in the mobile entry point (which owns the relay connection + the HD keys); the
// stubs live in app/src-tauri/src/commands.rs. See app/HANDOFF-JAMES.md.
