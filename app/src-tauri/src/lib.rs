//! LoveNode app — the Tauri shell.
//!
//! This is the thin layer between the React UI and the tested Rust staking core.
//! It holds no consensus logic and makes no security decisions of its own: it
//! stores the key (via [`lovenode_keystore`]), runs the client loop (via
//! [`lovenode_phone`]), and exposes a handful of commands the UI calls.
//!
//! The mobile entry point is `run()`, invoked from the generated Android/iOS
//! host. Everything security-critical is one layer down and unit-tested.

mod commands;
mod state;

use lovenode_keystore::DevKeyStore;
use lovenode_sign::wallet::Network;
use std::sync::Arc;
use tokio::sync::watch;

/// Whether this build stores the seed in real, persistent, hardware-backed secure
/// storage. It is **false** until the Android Keystore / iOS Keychain backend
/// (`app/android-plugin/SecureKeyStore.kt`) is wired in place of `DevKeyStore`.
///
/// While false, the seed lives only in process memory (lost when the app closes)
/// and MAINNET IS FORBIDDEN: the app runs on testnet so a user cannot deposit real
/// DIVI to a wallet whose keys will vanish. Flip to true only together with a real
/// persistent keystore, at which point mainnet is enabled.
pub const KEYSTORE_IS_SECURE: bool = false;

/// The network wallets are created on. Testnet until secure storage exists.
pub fn wallet_network() -> Network {
    if KEYSTORE_IS_SECURE {
        Network::Main
    } else {
        Network::Test
    }
}

/// Shared app state handed to every command.
pub struct App {
    /// Where the staking key lives. `DevKeyStore` in dev builds; a platform
    /// backend (Android Keystore / iOS Keychain) replaces it in a secure build.
    pub keystore: Arc<DevKeyStore>,
    /// The relay we connect to. Defaults to the hosted relay; the user may point
    /// it at their own desktop (DD69) instead.
    pub relay_url: std::sync::Mutex<String>,
    /// Flips true to ask a running client loop to stop.
    pub stop_tx: watch::Sender<bool>,
    pub stop_rx: watch::Receiver<bool>,
    /// Live status the UI polls.
    pub status: std::sync::Mutex<state::StakingStatus>,
}

impl App {
    fn new() -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);
        Self {
            keystore: Arc::new(DevKeyStore::new()),
            relay_url: std::sync::Mutex::new(DEFAULT_RELAY.to_string()),
            stop_tx,
            stop_rx,
            status: std::sync::Mutex::new(state::StakingStatus::default()),
        }
    }
}

/// The hosted relay, used unless the user chooses their own desktop.
pub const DEFAULT_RELAY: &str = "wss://relay.divi.love";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(App::new())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::disclosures,
            commands::has_wallet,
            commands::create_wallet,
            commands::restore_wallet,
            commands::addresses,
            commands::get_summary,
            commands::send_coins,
            commands::set_relay,
            commands::start_staking,
            commands::stop_staking,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LoveNode");
}
