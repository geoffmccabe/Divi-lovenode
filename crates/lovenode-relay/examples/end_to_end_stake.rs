//! Phase 0 proof: stake a block with ALL signing done outside the node.
//!
//! Every cryptographic step here happens in this process using lovenode-core /
//! lovenode-sign -- exactly what a phone would do. The node only supplies the
//! template (consensus-required payments) and accepts the finished block.
//!
//! Run against a regtest node:
//!   DIVI_DATADIR=~/divi-poe-regtest cargo run -p lovenode-relay --example end_to_end_stake

use lovenode_core::block::{merkle_root, BlockHeader};
use lovenode_core::serialize::{display_hex, from_hex, hash_from_display_hex, to_hex};
use lovenode_core::tx::{coinstake_returns_at_least, OutPoint, Transaction, TxIn, TxOut};
use lovenode_core::{check_win, NetworkTip, StakeCandidate};
use lovenode_relay::rpc::NodeRpc;
use lovenode_sign::{sign_block, sign_coinstake, StakingKey};
use serde_json::json;

fn connect() -> NodeRpc {
    let datadir = std::env::var("DIVI_DATADIR").expect("set DIVI_DATADIR");
    let conf = std::fs::read_to_string(format!("{datadir}/divi.conf")).expect("divi.conf");
    NodeRpc::from_conf(&conf, "127.0.0.1").expect("credentials")
}

/// The PoS coinbase is fully determined by the block height (BlockFactory.cpp),
/// so we can rebuild it here without asking the node for anything.
fn deterministic_coinbase(height: i64) -> Transaction {
    // scriptSig = <height> <CScriptNum(1)>, minimally encoded
    let mut script = Vec::new();
    let mut h = Vec::new();
    let mut v = height;
    while v > 0 {
        h.push((v & 0xff) as u8);
        v >>= 8;
    }
    if let Some(&last) = h.last() {
        if last & 0x80 != 0 {
            h.push(0);
        }
    }
    script.push(h.len() as u8);
    script.extend_from_slice(&h);
    script.push(1); // push 1 byte
    script.push(1); // extranonce = 1

    Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint { hash: [0u8; 32], n: u32::MAX },
            script_sig: script,
            sequence: u32::MAX,
        }],
        vout: vec![TxOut { value: 0, script_pubkey: Vec::new() }],
        lock_time: 0,
    }
}

fn main() {
    let rpc = connect();

    // ---- pick a mature coin we can stake -------------------------------------
    let unspent = rpc.call("listunspent", json!([20, 9_999_999])).expect("listunspent");
    let coin = unspent
        .as_array()
        .expect("array")
        .iter()
        .filter(|u| u["spendable"].as_bool().unwrap_or(false))
        .max_by(|a, b| {
            a["amount"].as_f64().unwrap_or(0.0)
                .partial_cmp(&b["amount"].as_f64().unwrap_or(0.0))
                .unwrap()
        })
        .expect("a spendable coin");
    let txid = coin["txid"].as_str().unwrap().to_string();
    let vout = coin["vout"].as_u64().unwrap() as u32;
    println!("staking {}:{} ({} DIVI)", &txid[..16], vout, coin["amount"]);

    // The private key for that coin -- on a phone this never leaves the device.
    let addr = coin["address"].as_str().expect("address");
    let wif = rpc.call("dumpprivkey", json!([addr])).expect("privkey").as_str().unwrap().to_string();
    let key = key_from_wif(&wif);
    println!("signing key loaded (stays in this process, as on a phone)");

    // ---- ask the node for the template ---------------------------------------
    let tmpl = rpc.call("getstaketemplate", json!([txid, vout, addr])).expect("template");
    let height = tmpl["height"].as_i64().unwrap();
    let bits = tmpl["bits"].as_u64().unwrap() as u32;
    let prev = hash_from_display_hex(tmpl["prev_block_hash"].as_str().unwrap()).unwrap();
    let tip_time = tmpl["tip_time"].as_u64().unwrap() as u32;
    let unsigned = Transaction::deserialize(&from_hex(tmpl["coinstake_hex"].as_str().unwrap()).unwrap())
        .expect("parse coinstake");
    println!("template: height {height}, staker gains {} sats", tmpl["staker_reward"]);

    // ---- VERIFY before signing (the security rule) ---------------------------
    let our_script = key.p2pkh_script();
    // CRITICAL: take the coin's value from OUR OWN view of our UTXO, never from
    // the template. The template's supplier also supplies the coinstake, so
    // trusting its figure lets it declare a 10,000 DIVI coin worth 1 satoshi,
    // pay us 1 satoshi (enough to satisfy the block-signature check) and route
    // the rest to itself in a perfectly valid block.
    let stake_value = (coin["amount"].as_f64().expect("amount") * 1e8).round() as i64;
    if let Some(claimed) = tmpl["stake_value"].as_i64() {
        if claimed != stake_value {
            panic!("template claims {claimed} sats but our coin is {stake_value} -- refusing");
        }
    }
    let paid = coinstake_returns_at_least(&unsigned, &our_script, stake_value)
        .expect("must return at least the staked value");
    println!("verified: coinstake returns {paid} sats to our own script");

    // ---- find a winning timestamp -------------------------------------------
    let si = rpc.call("getstakinginfo", json!([])).expect("staking info");
    let modifier = u64::from_str_radix(si["stake_modifier"].as_str().unwrap(), 16).unwrap();
    let tip = NetworkTip { stake_modifier: modifier, bits };
    let candidate = StakeCandidate {
        prevout_hash: hash_from_display_hex(&txid).unwrap(),
        prevout_n: vout,
        value_sats: stake_value,
        coinstake_start_time: coin_start_time(&rpc, &txid),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    let from = now.max(tip_time + 1);
    let (win_time, _) = (from..from + 600)
        .find_map(|t| check_win(&tip, &candidate, t).map(|h| (t, h)))
        .expect("no win found in the window");
    println!("WIN at timestamp {win_time}");

    // ---- sign the coinstake (outside the node) -------------------------------
    let signed = sign_coinstake(&key, &unsigned, &our_script, stake_value).expect("sign coinstake");

    // ---- build the block ourselves and sign the header -----------------------
    let coinbase = deterministic_coinbase(height);
    let root = merkle_root(&[coinbase.txid(), signed.txid()]);
    let header = BlockHeader {
        version: 4,
        prev_block: prev,
        merkle_root: root,
        time: win_time,
        bits,
        nonce: 0,
        accumulator_checkpoint: [0u8; 32],
    };
    let block_sig = sign_block(&key, &header).expect("sign block");
    println!("built header locally, block hash {}", header.hash_hex().unwrap());

    // ---- submit ---------------------------------------------------------------
    match rpc.call(
        "submitstakeblock",
        json!([to_hex(&signed.serialize()), to_hex(&block_sig), win_time, display_hex(&root)]),
    ) {
        Ok(v) => println!("\n>>> ACCEPTED — block {}", v.as_str().unwrap_or("?")),
        Err(e) => println!("\n>>> REJECTED — {e}"),
    }
}

fn coin_start_time(rpc: &NodeRpc, txid: &str) -> u32 {
    let tx = rpc.call("getrawtransaction", json!([txid, 1])).expect("funding tx");
    tx["blocktime"].as_u64().expect("blocktime") as u32
}

/// Decode a base58check WIF into a staking key.
fn key_from_wif(wif: &str) -> StakingKey {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Standard base58 -> big-endian bytes. Start from an EMPTY bignum: seeding
    // it with a zero byte leaves a spurious leading zero that shifts every
    // subsequent field and yields the wrong key.
    let mut num: Vec<u8> = Vec::new();
    for c in wif.bytes() {
        let d = A.iter().position(|&x| x == c).expect("base58 char") as u32;
        let mut carry = d;
        for b in num.iter_mut().rev() {
            let x = (*b as u32) * 58 + carry;
            *b = (x & 0xff) as u8;
            carry = x >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // each leading '1' encodes a leading zero byte
    let zeros = wif.bytes().take_while(|&c| c == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend_from_slice(&num);

    // layout: [version][32-byte key][0x01 if compressed][4-byte checksum]
    assert!(full.len() >= 37, "WIF too short: {} bytes", full.len());
    let payload = &full[1..full.len() - 4];
    let compressed = payload.len() == 33 && payload[32] == 1;
    let mut k = [0u8; 32];
    k.copy_from_slice(&payload[..32]);
    StakingKey::from_bytes(&k, compressed).expect("valid key")
}
