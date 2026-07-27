//! Prove a locally-built Send and Fast Send are accepted by a real node.
//! DIVI_DATADIR=~/divi-poe-regtest cargo run -p lovenode-phone --example send_tx
use lovenode_hdwallet::HdWallet;
use lovenode_phone::send::{build_signed_send, FundingValues, SendKind};
use lovenode_phone::{HdKeys, OwnedCoin};
use lovenode_relay::rpc::NodeRpc;
use lovenode_sign::wallet::Network;
use serde_json::json;

// Verifier backed by the node: reads the funding tx's output value. On a real
// phone this fetch is from the relay and the raw bytes are checked to hash to the
// txid; here the trusted regtest node stands in for that verified fetch.
struct NodeFunding { conf: String }
impl FundingValues for NodeFunding {
    fn true_value(&self, txid: &str, vout: u32) -> Result<i64, String> {
        let rpc = NodeRpc::from_conf(&self.conf, "127.0.0.1")?;
        let t = rpc.call("getrawtransaction", json!([txid, 1]))?;
        let o = &t["vout"][vout as usize];
        Ok((o["value"].as_f64().ok_or("no value")? * 1e8).round() as i64)
    }
}

fn main() {
    let dir = std::env::var("DIVI_DATADIR").unwrap();
    let conf = std::fs::read_to_string(format!("{dir}/divi.conf")).unwrap();
    let rpc = NodeRpc::from_conf(&conf, "127.0.0.1").unwrap();

    // a fresh phone HD wallet; fund its receiving address 1 from the regtest wallet
    let (wallet, _phrase) = HdWallet::generate(Network::Test).unwrap();
    let addr = wallet.receiving_address(1).unwrap();
    let funding = rpc.call("sendtoaddress", json!([addr, 500.0])).unwrap();
    let fund_txid = funding.as_str().unwrap().to_string();
    rpc.call("setgenerate", json!([true, 1])).ok();
    std::thread::sleep(std::time::Duration::from_secs(2));

    // The coin is on the HD address, which the node's wallet doesn't track, so
    // decode the funding tx to find the vout that pays our address.
    let dec = rpc.call("getrawtransaction", json!([fund_txid, 1])).unwrap();
    let vout = dec["vout"].as_array().unwrap().iter().find(|o| {
        o["scriptPubKey"]["addresses"].as_array().map(|a| a.iter().any(|x| x.as_str() == Some(&addr))).unwrap_or(false)
            || o["scriptPubKey"]["address"].as_str() == Some(&addr)
    }).expect("funded vout");
    let coin = OwnedCoin::receiving(
        fund_txid.clone(),
        vout["n"].as_u64().unwrap() as u32,
        (vout["value"].as_f64().unwrap() * 1e8).round() as i64,
        1,
    );
    println!("funded {}:{} with {} sats", &coin.txid[..12], coin.vout, coin.value_sats);
    let keys = HdKeys(wallet);

    // a destination the node owns, so we can see it arrive
    let dest = rpc.call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();

    let mut coins_for_kind = vec![coin];
    // fund a second coin (index 2) for the fast send
    let addr2 = keys.0.receiving_address(2).unwrap();
    let f2 = rpc.call("sendtoaddress", json!([addr2, 500.0])).unwrap().as_str().unwrap().to_string();
    rpc.call("setgenerate", json!([true, 1])).ok();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let d2 = rpc.call("getrawtransaction", json!([f2, 1])).unwrap();
    let v2 = d2["vout"].as_array().unwrap().iter().find(|o|
        o["scriptPubKey"]["addresses"].as_array().map(|a| a.iter().any(|x| x.as_str()==Some(&addr2))).unwrap_or(false)
        || o["scriptPubKey"]["address"].as_str()==Some(&addr2)).unwrap();
    coins_for_kind.push(OwnedCoin::receiving(f2.clone(), v2["n"].as_u64().unwrap() as u32, (v2["value"].as_f64().unwrap()*1e8).round() as i64, 2));

    for (i, kind) in [SendKind::Normal, SendKind::Fast].into_iter().enumerate() {
        let built = build_signed_send(&keys, std::slice::from_ref(&coins_for_kind[i]), &dest, 100 * 100_000_000, kind, Network::Test, &NodeFunding { conf: conf.clone() }).unwrap();
        match rpc.call("sendrawtransaction", json!([built.raw_hex])) {
            Ok(txid) => {
                println!(">>> {:?} ACCEPTED by node: txid {} (fee {} sats)", kind, txid.as_str().unwrap_or(""), built.fee_sats);
                // for the fast send, confirm the node sees the DFS1 marker
                if kind == SendKind::Fast {
                    let dec = rpc.call("decoderawtransaction", json!([built.raw_hex])).unwrap();
                    let has = dec["vout"].as_array().unwrap().iter().any(|o|
                        o["scriptPubKey"]["asm"].as_str().unwrap_or("").contains("444653")  // "DFS" hex, or
                        || o["scriptPubKey"]["hex"].as_str().unwrap_or("").contains("44465331")); // DFS1
                    println!("    DFS1 marker present on-chain: {}", has);
                }
                rpc.call("setgenerate", json!([true, 1])).ok();
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
            Err(e) => println!(">>> {:?} REJECTED: {}", kind, e),
        }
    }
}
