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
use std::sync::Arc;
use tokio::sync::watch;

/// Shared app state handed to every command.
pub struct App {
    /// Where the staking key lives. `DevKeyStore` in dev builds; a platform
    /// backend (Android Keystore / iOS Keychain) is injected in a real build.
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
            commands::import_wallet,
            commands::addresses,
            commands::set_relay,
            commands::start_staking,
            commands::stop_staking,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LoveNode");
}
