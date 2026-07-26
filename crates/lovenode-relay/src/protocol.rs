//! The phone ↔ relay wire protocol.
//!
//! # Security contract (read before changing anything here)
//!
//! The staking key signs a 32-byte digest (`BlockSigning.cpp` signs
//! `block.GetHash()`). If the relay were allowed to hand the phone a digest to
//! sign, a compromised relay could send the *sighash of a transaction spending
//! the user's coins* and convert the returned signature into a spend — the
//! `(r,s)` of a compact signature re-encodes as a DER transaction signature.
//! That is theft, not a lost reward.
//!
//! Therefore this protocol **never carries a digest to be signed**. The relay
//! sends only the raw ingredients; the phone assembles the coinstake and the
//! block header itself, hashes them locally, and signs what it built.
//! [`WinNotice`] is deliberately shaped so that a digest cannot be smuggled in.

use serde::{Deserialize, Serialize};

/// Relay → phone: "one of your coins just won; here are the ingredients."
///
/// Contains no digest and no pre-built structure — only public chain facts the
/// phone verifies and uses to construct the block itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinNotice {
    /// Height the new block would occupy.
    pub height: u64,
    /// Previous block hash, display hex.
    pub prev_block_hash: String,
    /// Difficulty for the new block.
    pub bits: u32,
    /// Stake modifier that produced the win.
    pub stake_modifier: u64,
    /// The winning coin, display hex txid + index.
    pub prevout_txid: String,
    pub prevout_n: u32,
    /// The coin's value in satoshis, and its first-confirmation block time.
    pub value_sats: i64,
    pub coinstake_start_time: u32,
    /// The timestamp at which the coin wins.
    pub hashproof_timestamp: u32,
    /// Other transactions the relay proposes to include, as raw hex. The phone
    /// does not need to validate these — a bad one only makes the block
    /// rejected, costing an attempt, never funds — but it MUST hash them itself
    /// to build the merkle root.
    pub mempool_txs_hex: Vec<String>,
}

impl WinNotice {
    /// Re-check the relay's claim locally before doing any signing work.
    /// The phone must call this: it is what turns "trust the relay" into
    /// "verify the relay". Returns the proof hash on success.
    /// A hostile relay must not be able to exhaust a phone's memory. The doc
    /// tells the phone not to validate these transactions but to hash them all,
    /// so an unbounded list is a denial-of-service straight at the device.
    pub const MAX_MEMPOOL_TXS: usize = 4_000;
    pub const MAX_MEMPOOL_BYTES: usize = 2 * 1024 * 1024;

    pub fn verify_win(&self) -> Result<[u8; 32], String> {
        if self.mempool_txs_hex.len() > Self::MAX_MEMPOOL_TXS {
            return Err(format!(
                "win notice carries {} transactions, over the {} limit",
                self.mempool_txs_hex.len(),
                Self::MAX_MEMPOOL_TXS
            ));
        }
        let total: usize = self.mempool_txs_hex.iter().map(|t| t.len()).sum();
        if total > Self::MAX_MEMPOOL_BYTES {
            return Err(format!(
                "win notice carries {total} bytes of transactions, over the {} limit",
                Self::MAX_MEMPOOL_BYTES
            ));
        }
        let prevout_hash = crate::chain::hash_from_display_hex(&self.prevout_txid)?;
        let coin = lovenode_core::StakeCandidate {
            prevout_hash,
            prevout_n: self.prevout_n,
            value_sats: self.value_sats,
            coinstake_start_time: self.coinstake_start_time,
        };
        let tip = lovenode_core::NetworkTip {
            stake_modifier: self.stake_modifier,
            bits: self.bits,
        };
        lovenode_core::check_win(&tip, &coin, self.hashproof_timestamp)
            .ok_or_else(|| "relay claimed a win that does not meet the target".to_string())
    }
}

/// Phone → relay: the signed pieces, built and hashed on the device.
///
/// The phone returns *its own constructed* coinstake and a signature over the
/// header **it** assembled. The relay can only assemble; it can never ask for a
/// signature over bytes of its choosing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedStake {
    pub height: u64,
    /// Fully-formed, signed coinstake transaction, raw hex — built on device.
    pub coinstake_hex: String,
    /// Signature over the block hash the phone computed from the header it built.
    pub block_signature: String,
    /// The header fields the phone committed to, so the relay reassembles
    /// exactly the block that was signed (any mismatch invalidates the block).
    pub header_version: u32,
    pub header_time: u32,
    pub header_nonce: u32,
    pub merkle_root: String,
}

/// Relay → phone: what happened to a submitted stake. Purely informational.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StakeOutcome {
    /// Block accepted by the network at this height.
    Accepted { block_hash: String },
    /// Another staker got there first — no loss, just a missed attempt.
    Stale,
    /// The assembled block was rejected; reason is for diagnostics only.
    Rejected { reason: String },
}

/// Registration: a phone tells the relay which public addresses to watch.
/// Only addresses — never keys, never an extended private key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registration {
    pub addresses: Vec<String>,
    /// Opaque device token for pushing win notices back.
    pub device_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::COIN;

    fn notice(bits: u32, ts: u32) -> WinNotice {
        WinNotice {
            height: 100,
            prev_block_hash: "aa".repeat(32),
            bits,
            stake_modifier: 12345,
            prevout_txid: "bb".repeat(32),
            prevout_n: 0,
            value_sats: 1_000 * COIN,
            coinstake_start_time: 1_700_000_000,
            hashproof_timestamp: ts,
            mempool_txs_hex: vec![],
        }
    }

    #[test]
    fn a_bogus_win_claim_is_rejected_by_the_phone() {
        // Near-impossible target: the relay's claim cannot be true.
        let n = notice(0x0100_0001, 1_700_003_600);
        assert!(n.verify_win().is_err(), "phone must not trust an unverified win");
    }

    #[test]
    fn a_genuine_win_verifies_locally() {
        // Very easy target: the claim should check out on the device.
        let n = notice(0x2100_ffff, 1_700_003_600);
        assert!(n.verify_win().is_ok());
    }

    #[test]
    fn an_oversized_transaction_list_is_refused() {
        let mut n = notice(0x2100_ffff, 1_700_003_600);
        n.mempool_txs_hex = vec!["00".repeat(64); WinNotice::MAX_MEMPOOL_TXS + 1];
        assert!(n.verify_win().is_err(), "must refuse an unbounded tx list");

        let mut big = notice(0x2100_ffff, 1_700_003_600);
        big.mempool_txs_hex = vec!["ab".repeat(600_000); 3];
        assert!(big.verify_win().is_err(), "must refuse oversized payloads");
    }

    #[test]
    fn malformed_ids_fail_closed_rather_than_panicking() {
        let mut n = notice(0x2100_ffff, 1_700_003_600);
        n.prevout_txid = "not-a-hash".into();
        assert!(n.verify_win().is_err());
    }

    #[test]
    fn win_notice_carries_no_signable_digest() {
        // Guard against a future edit reintroducing a "sign this" field. Checked
        // against exact field names: `prev_block_hash` is legitimate (a chain
        // fact the phone needs to build the header itself), whereas a bare
        // `block_hash`/`digest`/`sighash` would mean the relay is handing over
        // something to blind-sign — the one thing this protocol must never do.
        let v = serde_json::to_value(notice(0x2100_ffff, 1)).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        for banned in ["digest", "sighash", "to_sign", "tosign", "block_hash", "hash_to_sign"] {
            assert!(
                !keys.contains(&banned),
                "WinNotice must never carry a `{banned}` field; keys were {keys:?}"
            );
        }
        // and the fields the phone genuinely needs are present
        for required in ["prev_block_hash", "bits", "stake_modifier", "hashproof_timestamp"] {
            assert!(keys.contains(&required), "WinNotice is missing `{required}`");
        }
    }
}

/// Relay → phone: "money just arrived for you." Sent when the relay sees a
/// payment land on one of a device's registered addresses. Purely informational
/// — it carries no digest and nothing to sign, so it cannot be abused the way a
/// win notice could if it were shaped wrong.
///
/// Privacy: this goes ONLY to the device that owns the receiving address, over
/// its own encrypted connection. The `from` field is the sender's address (or its
/// human-readable name if one is assigned) — already public on-chain, so it
/// reveals nothing the receiver could not read from the transaction itself. For a
/// backgrounded app the delivery layer must use a content-less push wake and let
/// the app fetch this over TLS, so amounts never pass through Google/Apple.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentNotice {
    /// Amount received, in satoshis.
    pub amount_sats: i64,
    /// Value in US cents at the time, if a price was available. `None` = unknown.
    pub usd_cents: Option<i64>,
    /// The sender: a human-readable name if assigned, otherwise the address.
    pub from: String,
    /// True if this was a Fast Send (carried the DFS1 marker).
    pub is_fast: bool,
    /// The transaction id, so the app can track/confirm it.
    pub txid: String,
}

impl PaymentNotice {
    /// The one-line, privacy-safe message to show the receiver.
    /// e.g. "You were fast sent 100 DIVI worth $5.00 USD from geoff.divi".
    pub fn message(&self) -> String {
        let divi = format_divi(self.amount_sats);
        let verb = if self.is_fast { "fast sent" } else { "sent" };
        let usd = match self.usd_cents {
            Some(c) => format!(" worth ${:.2} USD", c as f64 / 100.0),
            None => String::new(),
        };
        format!("You were {verb} {divi} DIVI{usd} from {}", self.from)
    }
}

/// Format sats as DIVI, trimming trailing zeros (100_00000000 -> "100").
fn format_divi(sats: i64) -> String {
    let s = format!("{:.8}", sats as f64 / 1e8);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_string()
}

#[cfg(test)]
mod payment_tests {
    use super::*;

    #[test]
    fn fast_send_message_reads_naturally() {
        let n = PaymentNotice {
            amount_sats: 100_00000000,
            usd_cents: Some(500),
            from: "geoff.divi".into(),
            is_fast: true,
            txid: "ab".repeat(32),
        };
        assert_eq!(n.message(), "You were fast sent 100 DIVI worth $5.00 USD from geoff.divi");
    }

    #[test]
    fn normal_send_without_price_omits_usd() {
        let n = PaymentNotice {
            amount_sats: 150_50000000,
            usd_cents: None,
            from: "DTaddr123".into(),
            is_fast: false,
            txid: "cd".repeat(32),
        };
        assert_eq!(n.message(), "You were sent 150.5 DIVI from DTaddr123");
    }
}
