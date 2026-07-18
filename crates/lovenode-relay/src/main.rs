//! LoveNode relay — entry point.
//!
//! Runs beside a Divi node. Each block it recomputes the staking tip, sweeps
//! every registered coin for a win, and (once the transport lands) hands the
//! winning ingredients to the owning phone to sign.
//!
//! It holds **no private keys** and can never move a user's funds.
//!
//! Usage:
//!   lovenode-relay check              # one-shot: connect, show the staking tip
//!   lovenode-relay watch <address>... # search these addresses each block

use lovenode_relay::{chain, engine::Engine, rpc::NodeRpc};

const MIN_CONFIRMATIONS: u64 = 20; // chainparams: nMaturity
const MIN_COIN_AGE_SECS: u32 = 60 * 60; // chainparams: nMinCoinAgeForStaking

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn connect() -> Result<NodeRpc, String> {
    // Credentials come from the node's own divi.conf; nothing secret lives here.
    let datadir = std::env::var("DIVI_DATADIR")
        .map_err(|_| "set DIVI_DATADIR to the node's data directory".to_string())?;
    let host = std::env::var("DIVI_RPC_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let conf = std::fs::read_to_string(format!("{datadir}/divi.conf"))
        .map_err(|e| format!("cannot read {datadir}/divi.conf: {e}"))?;
    NodeRpc::from_conf(&conf, &host)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("check");

    let rpc = match connect() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("lovenode-relay: {e}");
            std::process::exit(2);
        }
    };

    match cmd {
        "check" => match chain::staking_tip(&rpc) {
            Ok(t) => {
                println!("height         : {}", t.height);
                println!("tip hash       : {}", engine::display_hex(&t.tip_hash));
                println!("tip time       : {}", t.tip_time);
                println!("stake modifier : {}", t.tip.stake_modifier);
                println!("bits           : {:#010x}", t.tip.bits);
                println!("\n>>> relay can see the staking tip; search is ready.");
            }
            Err(e) => {
                eprintln!("lovenode-relay: {e}");
                std::process::exit(1);
            }
        },
        "watch" => {
            let addresses: Vec<String> = args[1..].to_vec();
            if addresses.is_empty() {
                eprintln!("usage: lovenode-relay watch <address>...");
                std::process::exit(2);
            }
            let tip = match chain::staking_tip(&rpc) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("lovenode-relay: {e}");
                    std::process::exit(1);
                }
            };
            let coins = match chain::eligible_coins(
                &rpc, &addresses, now(), MIN_CONFIRMATIONS, MIN_COIN_AGE_SECS,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("lovenode-relay: {e}");
                    std::process::exit(1);
                }
            };
            println!("eligible coins : {}", coins.len());
            if coins.is_empty() {
                println!("(coins must be {MIN_CONFIRMATIONS}+ confirmations and 1+ hour old)");
                return;
            }
            let staker = engine::Staker {
                device_token: "local".into(),
                payout_address: addresses[0].clone(),
                coins,
            };
            let wins = Engine::default().search(&tip, &[staker], now());
            match wins.first() {
                Some(w) => {
                    println!("\n>>> WIN at timestamp {}", w.notice.hashproof_timestamp);
                    println!("    coin  : {}:{}", w.notice.prevout_txid, w.notice.prevout_n);
                    println!("    height: {}", w.notice.height);
                    // Prove the notice stands on its own, exactly as a phone would.
                    match w.notice.verify_win() {
                        Ok(_) => println!("    verified independently ✓"),
                        Err(e) => println!("    SELF-CHECK FAILED: {e}"),
                    }
                }
                None => println!("\nno win in this window — normal; try again next block"),
            }
        }
        other => {
            eprintln!("unknown command `{other}` (expected: check | watch)");
            std::process::exit(2);
        }
    }
}

use lovenode_relay::engine;
