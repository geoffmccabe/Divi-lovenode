//! Node-facing adapter: everything the relay needs to read from the chain.
//!
//! ## ⚠ Node prerequisite
//!
//! The stake modifier lives in `CBlockIndex::nStakeModifier` (see
//! `divi/src/chain.h`) and is **not exposed by any existing RPC** — verified
//! against the Divi source. The relay therefore needs one small, **read-only**
//! RPC added to `divid`:
//!
//! ```text
//! getstakinginfo -> { height, tip_hash, stake_modifier, bits, tip_time }
//! ```
//!
//! This changes no validation rule and requires no fork — it only surfaces a
//! value the node already computes and stores. Until it exists, [`staking_tip`]
//! will return an error explaining exactly what is missing, and the relay can
//! still be exercised with an injected tip (see `engine::Engine::search_with`).

use crate::rpc::NodeRpc;
use lovenode_core::{NetworkTip, StakeCandidate};
use serde_json::json;

/// The per-block values the win-search needs, plus context for building a block.
#[derive(Clone, Debug)]
pub struct StakingTip {
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub tip_time: u32,
    pub tip: NetworkTip,
}

/// Name of the read-only RPC described above. Configurable so the relay can be
/// pointed at whatever the node patch ends up calling it.
pub const STAKING_INFO_RPC: &str = "getstakinginfo";

/// Parse a 64-hex string in *display* order into internal byte order.
/// Divi (like Bitcoin) shows hashes reversed relative to how they are hashed,
/// and the kernel must be fed the internal order — getting this backwards
/// silently produces stakes that never win.
pub fn hash_from_display_hex(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not a 64-hex hash: {hex}"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        out[31 - i] = byte; // reverse into internal order
    }
    Ok(out)
}

/// Fetch the current staking tip from the node.
pub fn staking_tip(rpc: &NodeRpc) -> Result<StakingTip, String> {
    let v = rpc.call(STAKING_INFO_RPC, json!([])).map_err(|e| {
        format!(
            "{e}\n\nThe relay needs a read-only `{STAKING_INFO_RPC}` RPC exposing \
             CBlockIndex::nStakeModifier, which stock divid does not provide. \
             See crates/lovenode-relay/src/chain.rs for the required shape."
        )
    })?;

    let get_u64 = |k: &str| v.get(k).and_then(|x| x.as_u64());
    let height = get_u64("height").ok_or("staking info: missing height")?;
    let stake_modifier = get_u64("stake_modifier").ok_or("staking info: missing stake_modifier")?;
    let bits = get_u64("bits").ok_or("staking info: missing bits")? as u32;
    let tip_time = get_u64("tip_time").ok_or("staking info: missing tip_time")? as u32;
    let tip_hash = hash_from_display_hex(
        v.get("tip_hash").and_then(|x| x.as_str()).ok_or("staking info: missing tip_hash")?,
    )?;

    Ok(StakingTip {
        height,
        tip_hash,
        tip_time,
        tip: NetworkTip { stake_modifier, bits },
    })
}

/// Eligible coins for an address set, as seen by the node.
///
/// Only coins that can actually stake are returned: at least `min_confirmations`
/// deep and at least `min_age_secs` old (Divi requires 20 confirmations and one
/// hour — see `chainparams.cpp`).
pub fn eligible_coins(
    rpc: &NodeRpc,
    addresses: &[String],
    now: u32,
    min_confirmations: u64,
    min_age_secs: u32,
) -> Result<Vec<StakeCandidate>, String> {
    let unspent = rpc.call(
        "listunspent",
        json!([min_confirmations, 9_999_999, addresses]),
    )?;
    let arr = unspent.as_array().ok_or("listunspent: expected an array")?;

    let mut out = Vec::new();
    for u in arr {
        let (Some(txid), Some(vout), Some(amount)) = (
            u.get("txid").and_then(|x| x.as_str()),
            u.get("vout").and_then(|x| x.as_u64()),
            u.get("amount").and_then(|x| x.as_f64()),
        ) else {
            continue;
        };
        // The coin's first-confirmation block time drives coin age. Ask the node
        // for the funding transaction's block time.
        let start_time = match coin_start_time(rpc, txid) {
            Ok(t) => t,
            Err(_) => continue, // unknown age => cannot stake it safely
        };
        if now.saturating_sub(start_time) < min_age_secs {
            continue;
        }
        out.push(StakeCandidate {
            prevout_hash: hash_from_display_hex(txid)?,
            prevout_n: vout as u32,
            value_sats: (amount * lovenode_core::COIN as f64).round() as i64,
            coinstake_start_time: start_time,
        });
    }
    Ok(out)
}

/// Block time of the block that first confirmed a transaction.
fn coin_start_time(rpc: &NodeRpc, txid: &str) -> Result<u32, String> {
    let tx = rpc.call("getrawtransaction", json!([txid, 1]))?;
    tx.get("blocktime")
        .and_then(|t| t.as_u64())
        .map(|t| t as u32)
        .ok_or_else(|| format!("{txid}: not yet in a block"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hex_is_reversed_into_internal_order() {
        // A hash shown as 00..01 is internally 01..00.
        let display = format!("{}{}", "00".repeat(31), "01");
        let internal = hash_from_display_hex(&display).unwrap();
        assert_eq!(internal[0], 0x01, "display-last byte must become internal-first");
        assert_eq!(internal[31], 0x00);

        let d2 = format!("{}{}", "ff", "00".repeat(31));
        assert_eq!(hash_from_display_hex(&d2).unwrap()[31], 0xff);
    }

    #[test]
    fn malformed_hashes_are_rejected() {
        assert!(hash_from_display_hex("").is_err());
        assert!(hash_from_display_hex("abc").is_err());
        assert!(hash_from_display_hex(&"z".repeat(64)).is_err());
        assert!(hash_from_display_hex(&"a".repeat(63)).is_err());
    }
}
