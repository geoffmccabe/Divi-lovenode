//! Prove balance + activity against a real node's address index.
//! DIVI_DATADIR=~/divi-poe-regtest cargo run -p lovenode-relay --example wallet_view_live
use lovenode_relay::rpc::NodeRpc;
use lovenode_relay::wallet_view::{address_balance, recent_activity};
fn main() {
    let dir = std::env::var("DIVI_DATADIR").unwrap();
    let conf = std::fs::read_to_string(format!("{dir}/divi.conf")).unwrap();
    let rpc = NodeRpc::from_conf(&conf, "127.0.0.1").unwrap();
    let addr = "yFGuPKNd3LD6Vvm9fv6mvX6aiFMZ54KFMi".to_string(); // a rich, well-used address
    let bal = address_balance(&rpc, std::slice::from_ref(&addr)).unwrap();
    println!("balance: {} sats ({:.4} DIVI), received {} sats",
        bal.balance_sats, bal.balance_sats as f64 / 1e8, bal.received_sats);
    let acts = recent_activity(&rpc, std::slice::from_ref(&addr), 5).unwrap();
    println!("recent activity ({} lines):", acts.len());
    for a in &acts {
        println!("  {} {:+} sats  (height {}, {})",
            &a.txid[..12], a.net_sats, a.height, if a.incoming {"in"} else {"out"});
    }
}
