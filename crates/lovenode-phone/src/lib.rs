//! # lovenode-phone — the on-device staker
//!
//! This is what turns a relay's "you won" into a signed block, on the device
//! that holds the key. It is the security core of the phone app, kept as pure
//! Rust so it can be exhaustively tested off-device and then wrapped by the
//! Tauri/Android shell without any of the trust-critical logic living in the UI.
//!
//! It implements [`lovenode_relay::session::StakeSigner`], so the exact same
//! flow the relay drives in tests drives a real phone.
//!
//! ## The rules this type enforces, so the shell never has to
//!
//! A relay is untrusted. Before producing any signature this staker:
//! 1. **re-verifies the win itself** ([`WinNotice::verify_win`]) — a relay
//!    cannot make it sign for a win that doesn't meet the target;
//! 2. **asks the node, via a template, what the coinstake must pay** — the
//!    consensus-required masternode/treasury outputs come from the node, not the
//!    relay;
//! 3. **confirms the coinstake returns at least what THIS device independently
//!    knows its coin is worth** — never a figure the relay supplied — which is
//!    the line between signing a stake and signing away a balance;
//! 4. **builds and hashes the block header itself** and signs only that, so
//!    there is no way to be handed bytes to blind-sign.
//!
//! The key never leaves this type. On a real device it is generated in / loaded
//! from the Android Keystore; here it is held as a [`StakingKey`] and redacted
//! from any debug output.

use lovenode_core::block::{merkle_root, BlockHeader};
use lovenode_core::serialize::{display_hex, from_hex, hash_from_display_hex, to_hex};
use lovenode_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use lovenode_relay::protocol::{SignedStake, WinNotice};
use lovenode_relay::session::StakeSigner;
use lovenode_sign::{sign_block, sign_coinstake, StakingKey};

/// What the device knows about one of its own coins, independent of any relay.
/// The `value_sats` here is the ground truth the payback guard checks against.
#[derive(Clone, Debug)]
pub struct OwnedCoin {
    /// Funding txid, display hex.
    pub txid: String,
    pub vout: u32,
    /// The value THIS device believes the coin holds. Sourced from the device's
    /// own view of the chain, never from a win notice.
    pub value_sats: i64,
}

/// A source of stake templates — in production, the node via the relay, but
/// abstracted so the staker can be tested without a live node.
///
/// The template is *node-authored* consensus data (the required payments); it is
/// safe to take the coinstake bytes from here, but NOT the coin's value — that is
/// checked against the device's own [`OwnedCoin`].
pub trait TemplateSource {
    /// Return the unsigned coinstake hex and the height/prev/bits/tip_time for a
    /// stake of `txid:vout`.
    fn stake_template(&self, txid: &str, vout: u32) -> Result<StakeTemplate, String>;
}

/// The node's answer: an unsigned coinstake plus what the header needs.
#[derive(Clone, Debug)]
pub struct StakeTemplate {
    pub coinstake_hex: String,
    pub height: u64,
    pub prev_block_hash: String,
    pub bits: u32,
    pub tip_time: u32,
}

/// The on-device staker.
pub struct PhoneStaker<T: TemplateSource> {
    key: StakingKey,
    device_token: String,
    /// This device's own coins, keyed for lookup by "txid:vout".
    coins: Vec<OwnedCoin>,
    templates: T,
}

impl<T: TemplateSource> PhoneStaker<T> {
    pub fn new(key: StakingKey, device_token: impl Into<String>, coins: Vec<OwnedCoin>, templates: T) -> Self {
        Self { key, device_token: device_token.into(), coins, templates }
    }

    /// Our own record of what a coin is worth, or None if it isn't ours.
    fn known_value(&self, txid: &str, vout: u32) -> Option<i64> {
        self.coins
            .iter()
            .find(|c| c.vout == vout && c.txid.eq_ignore_ascii_case(txid))
            .map(|c| c.value_sats)
    }

    /// The full sign flow for one win. This is the heart of the security model.
    pub fn build_signed_stake(&self, notice: &WinNotice) -> Result<SignedStake, String> {
        // 1. Re-verify the relay's win claim ourselves.
        notice.verify_win()?;

        // 2. It must be OUR coin, and we must know its value independently.
        let known_value = self
            .known_value(&notice.prevout_txid, notice.prevout_n)
            .ok_or("win notice names a coin this device does not own")?;

        // 3. Get the node-authored template (consensus-required payments).
        let tmpl = self.templates.stake_template(&notice.prevout_txid, notice.prevout_n)?;
        let unsigned = Transaction::deserialize(&from_hex(&tmpl.coinstake_hex)?)?;

        // Sanity: the template must build on the same tip the win is for.
        if tmpl.height != notice.height {
            return Err(format!(
                "template height {} disagrees with win height {}",
                tmpl.height, notice.height
            ));
        }

        // 4. Sign the coinstake input, refusing unless at least the value WE know
        //    comes back to us. `known_value` is our ground truth, never the relay's.
        let script_code = self.key.p2pkh_script();
        let signed_coinstake = sign_coinstake(&self.key, &unsigned, &script_code, known_value)?;

        // 5. Build the block header ourselves and sign its hash. The deterministic
        //    PoS coinbase is rebuilt from the height, and the merkle root is
        //    computed locally over (coinbase, coinstake, ...relay txs). We hash
        //    every relay-supplied transaction ourselves, so nothing is trusted;
        //    a bad one only makes the block invalid, never redirects funds.
        let coinbase = deterministic_coinbase(notice.height);
        let mut txids = vec![coinbase.txid(), signed_coinstake.txid()];
        for hex in &notice.mempool_txs_hex {
            let tx = Transaction::deserialize(&from_hex(hex)?)?;
            txids.push(tx.txid());
        }
        let root = merkle_root(&txids);

        let header = BlockHeader {
            version: 4,
            prev_block: hash_from_display_hex(&notice.prev_block_hash)?,
            merkle_root: root,
            time: notice.hashproof_timestamp,
            bits: notice.bits,
            nonce: 0,
            accumulator_checkpoint: [0u8; 32],
        };
        let block_signature = sign_block(&self.key, &header)?;

        Ok(SignedStake {
            height: notice.height,
            coinstake_hex: to_hex(&signed_coinstake.serialize()),
            block_signature: to_hex(&block_signature),
            header_version: 4,
            header_time: header.time,
            header_nonce: 0,
            merkle_root: display_hex(&root),
        })
    }
}

impl<T: TemplateSource + Send + Sync> StakeSigner for PhoneStaker<T> {
    fn sign_win(&self, notice: &WinNotice) -> Result<SignedStake, String> {
        self.build_signed_stake(notice)
    }
    fn device_token(&self) -> &str {
        &self.device_token
    }
}

/// The PoS coinbase, fully determined by block height (`BlockFactory.cpp`):
/// `scriptSig = <height> <CScriptNum(1)>`. Reproduced so the phone needs nothing
/// from the relay to compute the merkle root.
fn deterministic_coinbase(height: u64) -> Transaction {
    let mut script = Vec::new();
    // minimal push of the height as a signed CScriptNum
    let mut h = Vec::new();
    let mut v = height;
    while v > 0 {
        h.push((v & 0xff) as u8);
        v >>= 8;
    }
    if h.last().is_some_and(|&b| b & 0x80 != 0) {
        h.push(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::tx::{build_coinstake, TxOut};
    use lovenode_core::COIN;

    // A template source we control, so we can play the role of a hostile relay.
    struct FakeTemplates {
        coinstake: Transaction,
        height: u64,
        prev: String,
        bits: u32,
    }
    impl TemplateSource for FakeTemplates {
        fn stake_template(&self, _txid: &str, _vout: u32) -> Result<StakeTemplate, String> {
            Ok(StakeTemplate {
                coinstake_hex: to_hex(&self.coinstake.serialize()),
                height: self.height,
                prev_block_hash: self.prev.clone(),
                bits: self.bits,
                tip_time: 1_700_000_000,
            })
        }
    }

    fn key() -> StakingKey {
        StakingKey::from_bytes(&[0x42; 32], true).unwrap()
    }

    fn notice(bits: u32, txid: &str) -> WinNotice {
        WinNotice {
            height: 1_001,
            prev_block_hash: "aa".repeat(32),
            bits,
            stake_modifier: 12345,
            prevout_txid: txid.to_string(),
            prevout_n: 0,
            value_sats: 10_000 * COIN, // relay's CLAIM -- must not be trusted
            coinstake_start_time: 1_699_000_000,
            hashproof_timestamp: 1_700_003_600,
            mempool_txs_hex: vec![],
        }
    }

    fn honest_setup() -> (PhoneStaker<FakeTemplates>, WinNotice) {
        let k = key();
        let txid = "cc".repeat(32);
        let real_value = 10_000 * COIN;
        // node template pays the full value + reward back to our script
        let coinstake = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&txid).unwrap(), n: 0 },
            vec![TxOut { value: real_value + 498 * COIN, script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();
        let templates = FakeTemplates {
            coinstake,
            height: 1_001,
            prev: "aa".repeat(32),
            bits: 0x2100_ffff,
        };
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: real_value }];
        let staker = PhoneStaker::new(k, "dev-1", coins, templates);
        (staker, notice(0x2100_ffff, &txid))
    }

    #[test]
    fn signs_an_honest_win_end_to_end() {
        let (staker, n) = honest_setup();
        let signed = staker.build_signed_stake(&n).expect("should sign");
        assert_eq!(signed.height, 1_001);
        assert!(!signed.coinstake_hex.is_empty());
        assert_eq!(signed.block_signature.len(), 130); // 65 bytes hex
        assert_eq!(signed.merkle_root.len(), 64);
    }

    #[test]
    fn refuses_a_win_for_a_coin_we_do_not_own() {
        let (staker, _) = honest_setup();
        let foreign = notice(0x2100_ffff, &"ff".repeat(32));
        let err = staker.build_signed_stake(&foreign).unwrap_err();
        assert!(err.contains("does not own"), "got: {err}");
    }

    #[test]
    fn refuses_a_bogus_win_claim_before_doing_anything() {
        // Near-impossible target: the relay's claim cannot be true, so we must
        // refuse before touching a template or a key.
        let (staker, mut n) = honest_setup();
        n.bits = 0x0100_0001;
        assert!(staker.build_signed_stake(&n).is_err());
    }

    #[test]
    fn refuses_when_the_template_underpays_our_coin() {
        // THE theft attempt: a hostile template pays us 1 satoshi and routes the
        // rest away. We know our coin is worth 10,000 DIVI, so we refuse -- even
        // though the win itself is real and the relay declared value_sats = 1.
        let k = key();
        let txid = "cc".repeat(32);
        let real_value = 10_000 * COIN;
        let theft = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&txid).unwrap(), n: 0 },
            vec![
                TxOut { value: 1, script_pubkey: k.p2pkh_script() },
                TxOut { value: real_value, script_pubkey: lovenode_sign::p2pkh_script(&[0xbb; 20]) },
            ],
        )
        .unwrap();
        let templates = FakeTemplates { coinstake: theft, height: 1_001, prev: "aa".repeat(32), bits: 0x2100_ffff };
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: real_value }];
        let staker = PhoneStaker::new(k, "dev-1", coins, templates);

        let err = staker.build_signed_stake(&notice(0x2100_ffff, &txid)).unwrap_err();
        assert!(err.contains("burned as fee"), "got: {err}");
    }

    #[test]
    fn refuses_a_template_built_on_a_different_height() {
        let (mut _staker, n) = honest_setup();
        // rebuild with a template height that disagrees with the win
        let k = key();
        let txid = "cc".repeat(32);
        let coinstake = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&txid).unwrap(), n: 0 },
            vec![TxOut { value: 10_498 * COIN, script_pubkey: k.p2pkh_script() }],
        ).unwrap();
        let templates = FakeTemplates { coinstake, height: 999, prev: "aa".repeat(32), bits: 0x2100_ffff };
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: 10_000 * COIN }];
        let staker = PhoneStaker::new(k, "dev-1", coins, templates);
        let err = staker.build_signed_stake(&n).unwrap_err();
        assert!(err.contains("height"), "got: {err}");
    }

    #[test]
    fn the_staker_is_a_stake_signer() {
        let (staker, n) = honest_setup();
        assert_eq!(StakeSigner::device_token(&staker), "dev-1");
        assert!(StakeSigner::sign_win(&staker, &n).is_ok());
    }

    // The relay side and the phone side, meeting through the StakeSigner seam:
    // a win notice goes in, a fully-formed SignedStake comes out, without either
    // side reaching into the other. This is the Phase 1 + Phase 2 fit.
    #[test]
    fn the_relay_can_drive_the_phone_signer_through_the_shared_trait() {
        let (staker, n) = honest_setup();
        // The relay only ever sees the phone as a StakeSigner.
        let signer: &dyn StakeSigner = &staker;
        assert_eq!(signer.device_token(), "dev-1");

        let signed = signer.sign_win(&n).expect("phone signs");
        // The relay would hand exactly these fields to submitstakeblock.
        assert_eq!(signed.height, n.height);
        assert_eq!(signed.merkle_root.len(), 64);
        assert_eq!(signed.block_signature.len(), 130);

        // And a hostile win the phone would refuse surfaces as an Err the relay
        // records as a decline, never a crash.
        let foreign = notice(0x2100_ffff, &"ee".repeat(32));
        assert!(signer.sign_win(&foreign).is_err());
    }
}
