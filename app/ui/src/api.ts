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
}

export interface Disclosures {
  lines: string[];
}

export const getStatus = () => invoke<StakingStatus>("status");
export const getDisclosures = () => invoke<Disclosures>("disclosures");
export const hasWallet = () => invoke<boolean>("has_wallet");
export const createWallet = () => invoke<string>("create_wallet");
export const importWallet = (wif: string) => invoke<string>("import_wallet", { wif });
export const addresses = () => invoke<string[]>("addresses");
export const setRelay = (url: string) => invoke<void>("set_relay", { url });
export const startStaking = () => invoke<void>("start_staking");
export const stopStaking = () => invoke<void>("stop_staking");
