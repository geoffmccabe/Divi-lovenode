//! Send and Fast Send — building a signed payment on the phone.
//!
//! DD69 builds these against a local node; the phone has none, so it selects
//! coins, builds outputs, and **signs every input locally** with the HD keys,
//! then hands the finished raw transaction to the relay to broadcast. The relay
//! can only forward the bytes — it cannot alter a signed transaction without
//! invalidating it.
//!
//! The fee model, the 5x priority multiple, the `DFS1` on-chain marker, and the
//! hard fee cap all mirror DD69's `fastsend.rs` (`crates/supervisor/src/fastsend.rs`)
//! so a Fast Send from the phone is byte-compatible with one from the desktop:
//! the receiver recognises the same marker.
//!
//! Two more send types exist in DD69 — **Pin Code Send** and **Bearer** — and are
//! deliberately NOT built here yet; the UI shows them greyed out. See
//! `docs/FOR-OTHER-AGENTS.md`.

use crate::{CoinKeys, OwnedCoin};
use lovenode_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use lovenode_sign::sign_p2pkh_input;
use lovenode_sign::wallet::{base58check_decode, Network};

/// Divi relay fee: 0.0001 DIVI/kB ≈ 10 sat/byte.
const RELAY_SATS_PER_BYTE: i64 = 10;
/// Fast Send pays 5x the relay fee for priority (matches DD69).
const FAST_FEE_MULTIPLE: i64 = 5;
/// Absolute fee ceiling; abort rather than ever burning more than this.
const FEE_CAP_SATS: i64 = 100_000_000; // 1 DIVI
/// Below this a change output is dropped (absorbed into fee) rather than created.
const DUST_SATS: i64 = 10_000; // 0.0001 DIVI
/// Divi Fast Send v1 on-chain marker, carried in an OP_META output.
pub const FAST_MARKER: &str = "DFS1";

/// Which kind of send. Pin Code and Bearer are intentionally absent (placeholders
/// in the UI only) until their flows are built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendKind {
    /// A plain payment at the normal relay fee.
    Normal,
    /// A priority payment (5x fee) carrying the `DFS1` marker.
    Fast,
}

impl SendKind {
    fn fee_multiple(self) -> i64 {
        match self {
            SendKind::Normal => 1,
            SendKind::Fast => FAST_FEE_MULTIPLE,
        }
    }
    fn is_fast(self) -> bool {
        self == SendKind::Fast
    }
}

/// A finished, signed payment ready to broadcast.
#[derive(Clone, Debug)]
pub struct BuiltSend {
    /// The signed raw transaction hex, to hand to the relay for `sendrawtransaction`.
    pub raw_hex: String,
    pub txid: String,
    /// The real fee this transaction pays (recomputed from inputs minus outputs).
    pub fee_sats: i64,
    pub kind: SendKind,
}

/// The OP_META (0x6a) + pushdata output carrying the Fast Send marker.
fn fast_marker_output() -> TxOut {
    let data = FAST_MARKER.as_bytes();
    let mut script = Vec::with_capacity(2 + data.len());
    script.push(0x6a); // OP_META / OP_RETURN-style
    script.push(data.len() as u8);
    script.extend_from_slice(data);
    TxOut { value: 0, script_pubkey: script }
}

/// The P2PKH scriptPubKey for a destination address, validating it belongs to the
/// expected network (so a mainnet coin can never be sent to a testnet address).
fn dest_script(address: &str, network: Network) -> Result<Vec<u8>, String> {
    let (version, payload) = base58check_decode(address.trim())?;
    let expected = match network {
        Network::Main => 30,
        Network::Test => 139,
    };
    if version != expected {
        return Err(format!(
            "address is not a Divi {} address",
            if network == Network::Main { "mainnet" } else { "testnet" }
        ));
    }
    if payload.len() != 20 {
        return Err("address does not encode a 20-byte key hash".into());
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&payload);
    Ok(lovenode_sign::p2pkh_script(&h))
}

/// Estimate a transaction's fee at this kind's priority, for `inputs` P2PKH inputs
/// and `outputs` outputs (P2PKH sizing + slack), matching DD69.
fn est_fee(kind: SendKind, inputs: usize, outputs: usize) -> i64 {
    let size = 10 + inputs * 148 + outputs * 34 + 20;
    size as i64 * RELAY_SATS_PER_BYTE * kind.fee_multiple()
}

/// The AUTHORITATIVE on-chain value of a coin, obtained trustlessly. The phone
/// has no chain, so a live build gets each coin's value by fetching its funding
/// transaction from the relay and checking the raw bytes hash to the txid it is
/// spending (the txid cryptographically commits to the outputs) — the relay
/// cannot lie about a value without breaking that hash. This is the send-side
/// analogue of the staking path's independently-known coin value.
///
/// SAFETY: `build_signed_send` uses THIS for all money math, never the caller's
/// `OwnedCoin.value_sats` (which is only a selection hint). Without it, a relay
/// that under-reports a coin's value could make the phone burn the difference as
/// fee — so the trait is required, not optional.
pub trait FundingValues {
    fn true_value(&self, txid: &str, vout: u32) -> Result<i64, String>;
}

/// Build and sign a payment. `coins` are this wallet's spendable UTXOs (each with
/// the derivation that lets `keys` sign it); `amount_sats` is what the recipient
/// receives. `funding` supplies each coin's verified on-chain value.
pub fn build_signed_send<K: CoinKeys, F: FundingValues>(
    keys: &K,
    coins: &[OwnedCoin],
    dest_address: &str,
    amount_sats: i64,
    kind: SendKind,
    network: Network,
    funding: &F,
) -> Result<BuiltSend, String> {
    if amount_sats <= 0 {
        return Err("amount must be greater than zero".into());
    }
    let to_script = dest_script(dest_address, network)?;
    let change_script = keys.change_script()?;

    // outputs: recipient + change (+ marker for fast). Fee is sized for the max.
    let n_out = if kind.is_fast() { 3 } else { 2 };

    // --- coin selection: prefer the smallest single coin that covers it; else
    // accumulate largest-first (mirrors DD69). The believed `value_sats` is only
    // a SELECTION HINT here; the money math below uses verified values. ---
    let mut sorted: Vec<&OwnedCoin> = coins.iter().filter(|c| c.value_sats > 0).collect();
    sorted.sort_by_key(|c| c.value_sats);
    let need_single = amount_sats.saturating_add(est_fee(kind, 1, n_out));
    let selected: Vec<&OwnedCoin> = if let Some(one) = sorted.iter().find(|c| c.value_sats >= need_single) {
        vec![*one]
    } else {
        let mut acc: Vec<&OwnedCoin> = Vec::new();
        for c in sorted.iter().rev() {
            acc.push(*c);
            let sum: i64 = acc.iter().map(|c| c.value_sats).sum();
            if sum >= amount_sats.saturating_add(est_fee(kind, acc.len(), n_out)) {
                break;
            }
        }
        acc
    };
    // AUTHORITATIVE total: the VERIFIED value of each selected coin, never the
    // caller-supplied hint. This is what stops a lied-about value burning funds.
    let mut total_in: i64 = 0;
    for c in &selected {
        total_in = total_in.saturating_add(funding.true_value(&c.txid, c.vout)?);
    }
    let fee = est_fee(kind, selected.len(), n_out);
    if total_in < amount_sats.saturating_add(fee) {
        return Err("not enough spendable balance for this send (amount plus fee)".into());
    }
    if fee > FEE_CAP_SATS {
        return Err("computed fee exceeds the safety cap".into());
    }

    // --- outputs ---
    let mut vout = vec![TxOut { value: amount_sats, script_pubkey: to_script }];
    if kind.is_fast() {
        vout.push(fast_marker_output());
    }
    let change = total_in - amount_sats - fee;
    if change >= DUST_SATS {
        vout.push(TxOut { value: change, script_pubkey: change_script });
    }
    // (change below dust is left in the fee)

    // --- unsigned inputs ---
    let vin: Vec<TxIn> = selected
        .iter()
        .map(|c| {
            Ok(TxIn {
                prevout: OutPoint {
                    hash: lovenode_core::serialize::hash_from_display_hex(&c.txid)?,
                    n: c.vout,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            })
        })
        .collect::<Result<_, String>>()?;
    let mut tx = Transaction { version: 1, vin, vout, lock_time: 0 };

    // --- sign each input with the key that controls its coin ---
    for (i, coin) in selected.iter().enumerate() {
        let key = keys.key_for(coin)?;
        let script_code = key.p2pkh_script();
        let script_sig = sign_p2pkh_input(&key, &tx, i, &script_code)?;
        tx.vin[i].script_sig = script_sig;
    }

    // --- final safety: recompute the REAL fee from the signed tx and re-check the
    // cap. Coin-selection or change math errors would show up here as a burned
    // fee; we refuse to broadcast rather than lose funds. ---
    let total_out: i64 = tx.vout.iter().map(|o| o.value).sum();
    let real_fee = total_in - total_out;
    if real_fee < 0 {
        return Err("outputs exceed inputs (internal error); refusing to sign".into());
    }
    if real_fee > FEE_CAP_SATS {
        return Err("final fee exceeds the safety cap; refusing to broadcast".into());
    }

    let raw = tx.serialize();
    Ok(BuiltSend {
        raw_hex: lovenode_core::serialize::to_hex(&raw),
        txid: lovenode_core::serialize::display_hex(&tx.txid()),
        fee_sats: real_fee,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_hdwallet::HdWallet;

    const COIN: i64 = 100_000_000;

    // A funding verifier for tests: maps each coin to its TRUE on-chain value.
    struct FakeFunding(std::collections::HashMap<(String, u32), i64>);
    impl FakeFunding {
        // by default, true value == the coin's believed value (honest case)
        fn honest(coins: &[OwnedCoin]) -> Self {
            FakeFunding(coins.iter().map(|c| ((c.txid.clone(), c.vout), c.value_sats)).collect())
        }
    }
    impl FundingValues for FakeFunding {
        fn true_value(&self, txid: &str, vout: u32) -> Result<i64, String> {
            self.0.get(&(txid.to_string(), vout)).copied().ok_or_else(|| "unknown coin".into())
        }
    }

    // a wallet plus some coins on its first receiving addresses
    fn wallet_with_coins(values: &[i64]) -> (crate::HdKeys, Vec<OwnedCoin>, String) {
        let (w, _) = HdWallet::generate(Network::Main).unwrap();
        let dest = w.receiving_address(9).unwrap(); // an address we can send to
        let coins = values
            .iter()
            .enumerate()
            .map(|(i, &v)| OwnedCoin::receiving("cc".repeat(32), i as u32, v, i as u32))
            .collect();
        (crate::HdKeys(w), coins, dest)
    }

    #[test]
    fn normal_send_builds_a_valid_signed_tx_with_change() {
        let (keys, coins, dest) = wallet_with_coins(&[1000 * COIN]);
        let built =
            build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins)).unwrap();
        // parses back, has the expected shape
        let tx = Transaction::deserialize(
            &lovenode_core::serialize::from_hex(&built.raw_hex).unwrap(),
        )
        .unwrap();
        assert_eq!(tx.vin.len(), 1);
        // recipient + change (no marker on a normal send)
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[0].value, 100 * COIN);
        assert!(!tx.vin[0].script_sig.is_empty(), "input must be signed");
        assert!(built.fee_sats > 0 && built.fee_sats < COIN);
    }

    #[test]
    fn fast_send_carries_the_dfs1_marker_and_a_higher_fee() {
        let (keys, coins, dest) = wallet_with_coins(&[1000 * COIN]);
        let normal =
            build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins)).unwrap();
        let fast =
            build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Fast, Network::Main, &FakeFunding::honest(&coins)).unwrap();
        assert!(fast.fee_sats > normal.fee_sats, "fast send pays more");

        let tx = Transaction::deserialize(
            &lovenode_core::serialize::from_hex(&fast.raw_hex).unwrap(),
        )
        .unwrap();
        // one output must be the OP_META DFS1 marker with value 0
        let has_marker = tx.vout.iter().any(|o| {
            o.value == 0
                && o.script_pubkey.first() == Some(&0x6a)
                && o.script_pubkey.ends_with(FAST_MARKER.as_bytes())
        });
        assert!(has_marker, "fast send must carry the DFS1 marker");
    }

    #[test]
    fn selects_multiple_coins_when_no_single_one_covers_it() {
        let (keys, coins, dest) = wallet_with_coins(&[40 * COIN, 40 * COIN, 40 * COIN]);
        let built =
            build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins)).unwrap();
        let tx = Transaction::deserialize(
            &lovenode_core::serialize::from_hex(&built.raw_hex).unwrap(),
        )
        .unwrap();
        assert!(tx.vin.len() >= 3, "should accumulate several coins");
    }

    #[test]
    fn refuses_when_balance_is_insufficient() {
        let (keys, coins, dest) = wallet_with_coins(&[10 * COIN]);
        assert!(
            build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins)).is_err()
        );
    }

    #[test]
    fn refuses_a_wrong_network_destination() {
        let (keys, coins, _) = wallet_with_coins(&[1000 * COIN]);
        // a testnet address on a mainnet send must be refused
        let (tw, _) = HdWallet::generate(Network::Test).unwrap();
        let testnet_addr = tw.receiving_address(1).unwrap();
        let err = build_signed_send(&keys, &coins, &testnet_addr, 100 * COIN, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins))
            .unwrap_err();
        assert!(err.contains("mainnet"), "got: {err}");
    }

    #[test]
    fn dust_change_is_absorbed_into_fee_not_created() {
        // amount chosen so the leftover after fee is below dust
        let (keys, coins, dest) = wallet_with_coins(&[100 * COIN]);
        let fee_guess = est_fee(SendKind::Normal, 1, 2);
        let amount = 100 * COIN - fee_guess - (DUST_SATS / 2); // change would be < dust
        let built =
            build_signed_send(&keys, &coins, &dest, amount, SendKind::Normal, Network::Main, &FakeFunding::honest(&coins)).unwrap();
        let tx = Transaction::deserialize(
            &lovenode_core::serialize::from_hex(&built.raw_hex).unwrap(),
        )
        .unwrap();
        // only the recipient output; the tiny change went into the fee
        assert_eq!(tx.vout.len(), 1, "dust change must not create an output");
    }

    #[test]
    fn under_reported_value_cannot_burn_funds() {
        // A hostile relay tells the phone a 1000-DIVI coin is worth 200. If the
        // builder trusted that, sending 100 would burn ~800 as fee. The verified
        // true value (1000) is used instead, so change is correct and the fee cap
        // holds -- no burn.
        let (keys, mut coins, dest) = wallet_with_coins(&[200 * COIN]); // BELIEVED 200
        // the on-chain truth is 1000 DIVI
        let mut truth = std::collections::HashMap::new();
        truth.insert((coins[0].txid.clone(), coins[0].vout), 1000 * COIN);
        let funding = FakeFunding(truth);
        coins[0].value_sats = 200 * COIN; // the lie the relay fed us

        let built = build_signed_send(&keys, &coins, &dest, 100 * COIN, SendKind::Normal, Network::Main, &funding).unwrap();
        // fee is tiny (well under the cap), NOT ~800 DIVI
        assert!(built.fee_sats < COIN, "verified value must prevent a burned fee, got {}", built.fee_sats);
        // change went back to us: total_out ~= 1000, so change ~= 900
        let tx = Transaction::deserialize(&lovenode_core::serialize::from_hex(&built.raw_hex).unwrap()).unwrap();
        let total_out: i64 = tx.vout.iter().map(|o| o.value).sum();
        assert!(total_out > 990 * COIN, "change must be returned, total_out={}", total_out);
    }
}
