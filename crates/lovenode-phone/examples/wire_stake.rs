//! The WHOLE system over a real WebSocket, end to end:
//!
//!   regtest node  <--RPC-->  relay server  <==WebSocket==>  phone client
//!
//! The relay finds a win against the node, pushes it over the socket to the
//! phone, the phone signs LOCALLY (verifying everything itself), sends it back,
//! and the relay submits it to the node — which accepts the block.
//!
//! This is the definitive Phase 1 + Phase 2 proof: not a unit test with fakes,
//! but the actual server and client talking over TCP, staking a real block.
//!
//!   DIVI_DATADIR=~/divi-poe-regtest cargo run -p lovenode-phone --example wire_stake

use lovenode_phone::client;
use lovenode_phone::{OwnedCoin, PhoneStaker, StakeTemplate, TemplateSource};
use lovenode_relay::rpc::NodeRpc;
use lovenode_relay::server::{handle_one, RelayState};
use lovenode_sign::wallet::from_wif;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A template source that asks the real node via getstaketemplate. The node
/// authors the consensus-required payments; the phone still checks the value
/// against what it independently knows.
struct NodeTemplates {
    rpc: NodeRpc,
}
impl TemplateSource for NodeTemplates {
    fn stake_template(&self, txid: &str, vout: u32) -> Result<StakeTemplate, String> {
        let t = self.rpc.call("getstaketemplate", json!([txid, vout]))?;
        Ok(StakeTemplate {
            coinstake_hex: t["coinstake_hex"].as_str().unwrap().to_string(),
            height: t["height"].as_u64().unwrap(),
            prev_block_hash: t["prev_block_hash"].as_str().unwrap().to_string(),
            bits: t["bits"].as_u64().unwrap() as u32,
            tip_time: t["tip_time"].as_u64().unwrap() as u32,
        })
    }
}

#[tokio::main]
async fn main() {
    let datadir = std::env::var("DIVI_DATADIR").expect("set DIVI_DATADIR");
    let conf = std::fs::read_to_string(format!("{datadir}/divi.conf")).unwrap();
    let rpc = NodeRpc::from_conf(&conf, "127.0.0.1").unwrap();

    // --- pick one of our mature coins and its key ---
    let unspent = rpc.call("listunspent", json!([20, 9_999_999])).unwrap();
    let coin = unspent
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["spendable"].as_bool().unwrap_or(false))
        .max_by(|a, b| {
            a["amount"].as_f64().unwrap().partial_cmp(&b["amount"].as_f64().unwrap()).unwrap()
        })
        .expect("a spendable coin");
    let txid = coin["txid"].as_str().unwrap().to_string();
    let vout = coin["vout"].as_u64().unwrap() as u32;
    let address = coin["address"].as_str().unwrap().to_string();
    let value_sats = (coin["amount"].as_f64().unwrap() * 1e8).round() as i64;
    let wif = rpc.call("dumpprivkey", json!([address])).unwrap().as_str().unwrap().to_string();
    let (key, _net) = from_wif(&wif).expect("decode wif");
    println!("staking {}:{} ({} DIVI) on address {address}", &txid[..16], vout, coin["amount"]);

    let height_before = rpc.call("getblockcount", json!([])).unwrap().as_u64().unwrap();

    // --- stand up the REAL relay server on an ephemeral port ---
    let state = RelayState::new(rebuild_rpc(&conf));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let s = st.clone();
            tokio::spawn(async move { let _ = handle_one(stream, s).await; });
        }
    });

    // --- the phone: holds the key and knows ALL its coins on this address ---
    // (the relay may win with any of the address's coins, and the phone must
    // recognise whichever one wins -- it only signs coins it independently knows.)
    let owned: Vec<OwnedCoin> = unspent.as_array().unwrap().iter()
        .filter(|u| u["address"].as_str() == Some(&address))
        .map(|u| OwnedCoin {
            txid: u["txid"].as_str().unwrap().to_string(),
            vout: u["vout"].as_u64().unwrap() as u32,
            value_sats: (u["amount"].as_f64().unwrap() * 1e8).round() as i64,
        })
        .collect();
    println!("phone knows {} coin(s) on its address", owned.len());
    let staker = PhoneStaker::new(
        key,
        "wire-test".to_string(),
        owned,
        NodeTemplates { rpc: rebuild_rpc(&conf) },
    );
    let _ = (txid, vout, value_sats);

    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let (_stop_tx, stop_rx) = watch::channel(false);
    let url = format!("ws://{addr}");

    // run the phone client
    let client_handle = tokio::spawn(async move {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            client::run(&url, vec![address], "wire-test".into(), &staker,
                        move |e| ev.lock().unwrap().push(format!("{e:?}")), stop_rx),
        )
        .await;
    });

    // give the phone a moment to register, then drive a block tick on the relay
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    match state.tick(now).await {
        Ok(n) => println!("relay tick: {n} win(s) dispatched"),
        Err(e) => println!("relay tick error: {e}"),
    }

    // let the win flow phone -> relay -> node
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    client_handle.abort();

    let height_after = rpc.call("getblockcount", json!([])).unwrap().as_u64().unwrap();
    println!("\nphone events: {:?}", events.lock().unwrap());
    println!("height {height_before} -> {height_after}");
    if height_after > height_before {
        println!(">>> ACCEPTED over the wire — the phone staked a real block through the relay");
    } else {
        println!(">>> no block this run (no win in the window is normal; re-run)");
    }
}

fn rebuild_rpc(conf: &str) -> NodeRpc {
    NodeRpc::from_conf(conf, "127.0.0.1").unwrap()
}
