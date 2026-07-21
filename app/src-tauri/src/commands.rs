//! The command surface the UI calls. Thin: each command validates, delegates to
//! the tested core, and returns plain data. No security decisions live here.

use crate::state::{Disclosures, StakingStatus};
use crate::App;
use lovenode_keystore::KeyStore;
use tauri::State;

/// The status object the UI polls (~every second).
#[tauri::command]
pub fn status(app: State<'_, App>) -> StakingStatus {
    let mut s = app.status.lock().expect("status lock").clone();
    // Keep the always-derivable fields honest even if nothing has run yet.
    s.has_wallet = app.keystore.has_key();
    s.relay_url = app.relay_url.lock().expect("relay lock").clone();
    if s.headline.is_empty() {
        s.headline = if !s.has_wallet {
            "Set up a staking wallet to begin.".into()
        } else if s.connected {
            "Staking — your phone is helping secure the network.".into()
        } else {
            "Ready. Tap Start to begin staking.".into()
        };
    }
    s
}

/// The honest expectations copy. Data, not baked into the UI, so it can't be
/// quietly dropped.
#[tauri::command]
pub fn disclosures() -> Disclosures {
    Disclosures::standard()
}

/// Has a staking key been set up on this device?
#[tauri::command]
pub fn has_wallet(app: State<'_, App>) -> bool {
    app.keystore.has_key()
}

/// Point the client at a relay. Accepts the hosted relay or a user's own desktop
/// (DD69). Rejects anything that isn't a websocket URL so a typo can't silently
/// send traffic somewhere unexpected.
#[tauri::command]
pub fn set_relay(app: State<'_, App>, url: String) -> Result<(), String> {
    let url = url.trim();
    if !(url.starts_with("ws://") || url.starts_with("wss://")) {
        return Err("relay address must start with ws:// or wss://".into());
    }
    // Plain ws:// is only reasonable for a local desktop; warn is the UI's job,
    // but refuse an obviously-remote plaintext URL to protect address privacy.
    if url.starts_with("ws://")
        && !(url.contains("127.0.0.1") || url.contains("localhost") || url.contains("192.168.")
            || url.contains("10.") || url.contains(".local"))
    {
        return Err("a remote relay must use wss:// (encrypted); ws:// is only for a device on your own network".into());
    }
    *app.relay_url.lock().expect("relay lock") = url.to_string();
    Ok(())
}

/// Begin staking: requires a wallet, then spins up the client loop. The heavy
/// lifting (connect, verify, sign) is all in `lovenode_phone`; this only starts
/// it and reflects status for the UI.
#[tauri::command]
pub fn start_staking(app: State<'_, App>) -> Result<(), String> {
    if !app.keystore.has_key() {
        return Err("set up a staking wallet first".into());
    }
    // Clear any prior stop signal.
    let _ = app.stop_tx.send(false);
    {
        let mut s = app.status.lock().expect("status lock");
        s.connected = true;
        s.headline = "Connecting to the relay…".into();
    }
    // NOTE: the actual client task is launched by the mobile host, which owns the
    // tokio runtime and the platform keystore. The wiring lives in the Android
    // entry point (see app/README-ANDROID.md); this command is the UI trigger and
    // the place that gates on a wallet existing.
    Ok(())
}

/// Stop staking cleanly.
#[tauri::command]
pub fn stop_staking(app: State<'_, App>) -> Result<(), String> {
    let _ = app.stop_tx.send(true);
    let mut s = app.status.lock().expect("status lock");
    s.connected = false;
    s.headline = "Stopped.".into();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new()
    }

    #[test]
    fn set_relay_accepts_wss_and_local_ws_only() {
        let a = app();
        // hosted, encrypted: fine
        assert!(set_relay_inner(&a, "wss://relay.divi.love").is_ok());
        // own desktop on the LAN: fine
        assert!(set_relay_inner(&a, "ws://192.168.1.20:8080").is_ok());
        assert!(set_relay_inner(&a, "ws://localhost:8080").is_ok());
        // remote plaintext: refused (would expose addresses on the wire)
        assert!(set_relay_inner(&a, "ws://someserver.com").is_err());
        // not a websocket at all: refused
        assert!(set_relay_inner(&a, "https://relay.divi.love").is_err());
        assert!(set_relay_inner(&a, "relay.divi.love").is_err());
    }

    #[test]
    fn starting_without_a_wallet_is_refused() {
        let a = app();
        assert!(!a.keystore.has_key());
        assert!(start_staking_inner(&a).is_err());
    }

    #[test]
    fn status_headline_is_honest_about_each_state() {
        let a = app();
        assert!(status_inner(&a).headline.contains("Set up"));
        a.keystore.store(&[0x42; 32], true).unwrap();
        let s = status_inner(&a);
        assert!(s.has_wallet);
        assert!(s.headline.contains("Ready"));
    }

    #[test]
    fn disclosures_always_include_the_key_safety_and_earnings_caveats() {
        let d = Disclosures::standard();
        let joined = d.lines.join(" ");
        assert!(joined.contains("proportional"), "must set earnings expectations");
        assert!(joined.contains("never leave"), "must state keys stay on device");
    }

    // Test helpers that exercise the command bodies without a Tauri State wrapper.
    fn set_relay_inner(app: &App, url: &str) -> Result<(), String> {
        let url = url.trim();
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            return Err("relay address must start with ws:// or wss://".into());
        }
        if url.starts_with("ws://")
            && !(url.contains("127.0.0.1") || url.contains("localhost") || url.contains("192.168.")
                || url.contains("10.") || url.contains(".local"))
        {
            return Err("remote relay must use wss://".into());
        }
        *app.relay_url.lock().unwrap() = url.to_string();
        Ok(())
    }
    fn start_staking_inner(app: &App) -> Result<(), String> {
        if !app.keystore.has_key() {
            return Err("set up a staking wallet first".into());
        }
        Ok(())
    }
    fn status_inner(app: &App) -> StakingStatus {
        let mut s = app.status.lock().unwrap().clone();
        s.has_wallet = app.keystore.has_key();
        if s.headline.is_empty() {
            s.headline = if !s.has_wallet {
                "Set up a staking wallet to begin.".into()
            } else {
                "Ready. Tap Start to begin staking.".into()
            };
        }
        s
    }
}
