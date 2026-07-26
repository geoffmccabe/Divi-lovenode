//! The wallet's balance and recent activity, read from the node by address.
//!
//! The phone holds no chain, so the relay answers "what's my balance and what
//! happened lately?" using the node's address index (`getaddressbalance`,
//! `getaddressdeltas`) over the wallet's PUBLIC addresses — no keys, no wallet
//! access. LoveNode has no separate transaction-history screen; this recent
//! activity is what the Overview shows.
//!
//! The parsing is split from the RPC call so it can be tested against fixed
//! node-response fixtures without a live node.

use crate::rpc::NodeRpc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

/// A wallet's spendable balance and lifetime received, in satoshis.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    pub balance_sats: i64,
    pub received_sats: i64,
}

/// One line of activity for the Overview: a net movement in a single transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Activity {
    pub txid: String,
    /// Net change to the wallet in this tx: positive = received, negative = sent.
    pub net_sats: i64,
    pub height: i64,
    /// True when the net is positive (received). Convenience for the UI.
    pub incoming: bool,
}

/// Parse a `getaddressbalance` response (`{ "balance", "received" }`).
pub fn parse_balance(v: &Value) -> Result<Balance, String> {
    let balance_sats = v["balance"].as_i64().ok_or("balance: missing 'balance'")?;
    let received_sats = v["received"].as_i64().unwrap_or(0);
    Ok(Balance { balance_sats, received_sats })
}

/// Parse a `getaddressdeltas` response (an array of per-output/input deltas) into
/// recent activity, aggregating all deltas that share a txid into one net line,
/// newest first. `limit` caps how many are returned.
pub fn parse_activity(v: &Value, limit: usize) -> Result<Vec<Activity>, String> {
    let arr = v.as_array().ok_or("deltas: expected an array")?;
    // sum satoshis per txid, keep the max height seen for that txid
    let mut nets: HashMap<String, (i64, i64)> = HashMap::new(); // txid -> (net, height)
    for d in arr {
        let txid = d["txid"].as_str().ok_or("delta: missing txid")?.to_string();
        let sats = d["satoshis"].as_i64().ok_or("delta: missing satoshis")?;
        let height = d["height"].as_i64().unwrap_or(0);
        let e = nets.entry(txid).or_insert((0, height));
        e.0 += sats;
        if height > e.1 {
            e.1 = height;
        }
    }
    let mut out: Vec<Activity> = nets
        .into_iter()
        .map(|(txid, (net, height))| Activity { txid, net_sats: net, height, incoming: net >= 0 })
        .collect();
    // newest first (highest height); height 0 = mempool, treat as newest
    out.sort_by(|a, b| {
        let ha = if a.height == 0 { i64::MAX } else { a.height };
        let hb = if b.height == 0 { i64::MAX } else { b.height };
        hb.cmp(&ha)
    });
    out.truncate(limit);
    Ok(out)
}

/// Query the node for the combined balance of `addresses`.
pub fn address_balance(rpc: &NodeRpc, addresses: &[String]) -> Result<Balance, String> {
    if addresses.is_empty() {
        return Ok(Balance { balance_sats: 0, received_sats: 0 });
    }
    let v = rpc.call("getaddressbalance", json!([{ "addresses": addresses }]))?;
    parse_balance(&v)
}

/// Query the node for recent activity across `addresses` (newest `limit` txs).
pub fn recent_activity(rpc: &NodeRpc, addresses: &[String], limit: usize) -> Result<Vec<Activity>, String> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let v = rpc.call("getaddressdeltas", json!([{ "addresses": addresses }]))?;
    parse_activity(&v, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_balance_response() {
        let v = json!({ "balance": 2352199950000i64, "received": 18777799500000i64 });
        assert_eq!(
            parse_balance(&v).unwrap(),
            Balance { balance_sats: 2352199950000, received_sats: 18777799500000 }
        );
    }

    #[test]
    fn aggregates_deltas_by_txid_into_net_activity() {
        // one tx: received 100 on one output; another tx: spent 40 (negative) and
        // got 10 change (net -30). Newest (higher height) first.
        let v = json!([
            { "satoshis": 100_00000000i64, "txid": "aa", "index": 0, "blockindex": 1, "height": 10, "address": "x" },
            { "satoshis": -40_00000000i64, "txid": "bb", "index": 0, "blockindex": 1, "height": 20, "address": "x" },
            { "satoshis":  10_00000000i64, "txid": "bb", "index": 1, "blockindex": 1, "height": 20, "address": "x" }
        ]);
        let acts = parse_activity(&v, 10).unwrap();
        assert_eq!(acts.len(), 2);
        // bb is newer (height 20) and is a net send of -30
        assert_eq!(acts[0].txid, "bb");
        assert_eq!(acts[0].net_sats, -30_00000000);
        assert!(!acts[0].incoming);
        // aa is a receive of +100
        assert_eq!(acts[1].txid, "aa");
        assert_eq!(acts[1].net_sats, 100_00000000);
        assert!(acts[1].incoming);
    }

    #[test]
    fn mempool_txs_height_zero_sort_newest() {
        let v = json!([
            { "satoshis": 5_00000000i64, "txid": "old", "index": 0, "blockindex": 1, "height": 100, "address": "x" },
            { "satoshis": 5_00000000i64, "txid": "pending", "index": 0, "blockindex": 1, "height": 0, "address": "x" }
        ]);
        let acts = parse_activity(&v, 10).unwrap();
        assert_eq!(acts[0].txid, "pending", "a mempool (height 0) tx sorts newest");
    }

    #[test]
    fn limit_caps_the_list() {
        let v = json!([
            { "satoshis": 1, "txid": "a", "index": 0, "blockindex": 1, "height": 1, "address": "x" },
            { "satoshis": 1, "txid": "b", "index": 0, "blockindex": 1, "height": 2, "address": "x" },
            { "satoshis": 1, "txid": "c", "index": 0, "blockindex": 1, "height": 3, "address": "x" }
        ]);
        assert_eq!(parse_activity(&v, 2).unwrap().len(), 2);
    }

    #[test]
    fn empty_addresses_query_nothing() {
        // no network call happens; both return empties
        assert_eq!(parse_activity(&json!([]), 10).unwrap().len(), 0);
    }
}
