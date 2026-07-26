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

pub mod client;
pub mod send;

#[cfg(test)]
pub(crate) mod tests_support {
    //! Shared fixtures for the crate's tests.
    use super::*;
    use lovenode_core::tx::{build_coinstake, OutPoint, TxOut};
    use lovenode_core::{serialize::hash_from_display_hex, COIN};

    struct HonestTemplates {
        coinstake: Transaction,
        height: u64,
        prev: String,
        bits: u32,
    }
    impl TemplateSource for HonestTemplates {
        fn stake_template(&self, _txid: &str, _vout: u32) -> Result<StakeTemplate, String> {
            Ok(StakeTemplate {
                coinstake_hex: lovenode_core::serialize::to_hex(&self.coinstake.serialize()),
                height: self.height,
                prev_block_hash: self.prev.clone(),
                bits: self.bits,
                tip_time: 1_700_000_000,
            })
        }
    }

    /// A staker set up to sign one honest win, plus its addresses and token.
    pub fn honest_staker() -> (PhoneStaker<impl TemplateSource, SingleKey>, Vec<String>, String) {
        let k = StakingKey::from_bytes(&[0x42; 32], true).unwrap();
        let txid = "cc".repeat(32);
        let real_value = 10_000 * COIN;
        let coinstake = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&txid).unwrap(), n: 0 },
            vec![TxOut { value: real_value + 498 * COIN, script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();
        let templates = HonestTemplates { coinstake, height: 1_001, prev: "aa".repeat(32), bits: 0x2100_ffff };
        let coins = vec![OwnedCoin { txid, vout: 0, value_sats: real_value, change: false, key_index: 0 }];
        let staker = PhoneStaker::new(SingleKey(k), "dev-1", coins, templates);
        (staker, vec!["DTaddZU8Xy1234567890abcdefghij".into()], "dev-1".into())
    }
}

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
    /// Which HD key controls this coin: the internal (change) chain or the
    /// external (receiving) chain, and the index within it. The staker derives
    /// the signing key from these, so a wallet stakes across ALL its addresses,
    /// not just one. (Single-key setups leave these at 0/false and use a
    /// [`SingleKey`] provider that ignores them.)
    pub change: bool,
    pub key_index: u32,
}

impl OwnedCoin {
    /// A coin on the external (receiving) chain at `key_index`.
    pub fn receiving(txid: impl Into<String>, vout: u32, value_sats: i64, key_index: u32) -> Self {
        Self { txid: txid.into(), vout, value_sats, change: false, key_index }
    }
}

/// Where the staker gets the signing key for a coin it owns. Abstracted so the
/// same staker works with a full HD wallet (production) or a single key
/// (tests/import/sweep) without the signing core caring which.
pub trait CoinKeys {
    fn key_for(&self, coin: &OwnedCoin) -> Result<StakingKey, String>;

    /// The P2PKH script that a send's change output should pay back to — an
    /// address this wallet controls. HD wallets use the internal (change) chain;
    /// a single-key wallet returns change to its own key.
    fn change_script(&self) -> Result<Vec<u8>, String>;
}

/// A key provider backed by one key — for a single-key wallet, a swept import, or
/// tests. Ignores the coin's derivation fields.
pub struct SingleKey(pub StakingKey);
impl CoinKeys for SingleKey {
    fn key_for(&self, _coin: &OwnedCoin) -> Result<StakingKey, String> {
        Ok(self.0.clone())
    }
    fn change_script(&self) -> Result<Vec<u8>, String> {
        Ok(self.0.p2pkh_script())
    }
}

/// A key provider backed by the HD wallet — derives the exact key that controls
/// each coin from its `change`/`key_index`. This is the production provider.
pub struct HdKeys(pub lovenode_hdwallet::HdWallet);
impl CoinKeys for HdKeys {
    fn key_for(&self, coin: &OwnedCoin) -> Result<StakingKey, String> {
        if coin.change {
            self.0.change_key(coin.key_index)
        } else {
            self.0.receiving_key(coin.key_index)
        }
    }
    fn change_script(&self) -> Result<Vec<u8>, String> {
        Ok(self.0.change_key(0)?.p2pkh_script())
    }
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
pub struct PhoneStaker<T: TemplateSource, K: CoinKeys = HdKeys> {
    keys: K,
    device_token: String,
    /// This device's own coins, keyed for lookup by "txid:vout".
    coins: Vec<OwnedCoin>,
    templates: T,
}

impl<T: TemplateSource, K: CoinKeys> PhoneStaker<T, K> {
    /// Build a staker from any key provider (`HdKeys` in production).
    pub fn new(keys: K, device_token: impl Into<String>, coins: Vec<OwnedCoin>, templates: T) -> Self {
        Self { keys, device_token: device_token.into(), coins, templates }
    }

    /// The coin, if we own it, or None. Used both for its value (ground truth for
    /// the payback guard) and to derive the key that controls it.
    fn owned_coin(&self, txid: &str, vout: u32) -> Option<&OwnedCoin> {
        self.coins.iter().find(|c| c.vout == vout && c.txid.eq_ignore_ascii_case(txid))
    }

    /// The full sign flow for one win. This is the heart of the security model.
    pub fn build_signed_stake(&self, notice: &WinNotice) -> Result<SignedStake, String> {
        // 1. Re-verify the relay's win claim ourselves.
        notice.verify_win()?;

        // 2. It must be OUR coin, and we must know its value independently. From
        //    the coin we also derive the exact key that controls it (HD wallets
        //    stake across many addresses, so the key is per-coin, not global).
        let coin = self
            .owned_coin(&notice.prevout_txid, notice.prevout_n)
            .ok_or("win notice names a coin this device does not own")?;
        let known_value = coin.value_sats;
        let key = self.keys.key_for(coin)?;

        // 3. Get the node-authored template (consensus-required payments).
        let tmpl = self.templates.stake_template(&notice.prevout_txid, notice.prevout_n)?;
        let unsigned = Transaction::deserialize(&from_hex(&tmpl.coinstake_hex)?)?;

        // CRITICAL: the coinstake must spend EXACTLY the coin whose value we just
        // checked. One key controls every coin on the address, so without this a
        // hostile relay could name a 1-DIVI coin (cheap known_value) but hand a
        // template that spends a 10,000-DIVI coin, pay 1 back and route the rest
        // away -- a valid block, and outright theft. Bind the value check to the
        // input actually being signed.
        let expected = hash_from_display_hex(&notice.prevout_txid)?;
        if unsigned.vin.len() != 1
            || unsigned.vin[0].prevout.hash != expected
            || unsigned.vin[0].prevout.n != notice.prevout_n
        {
            return Err("template spends a different coin than the win names; refusing".into());
        }

        // Sanity: the template must build on the same tip the win is for.
        if tmpl.height != notice.height {
            return Err(format!(
                "template height {} disagrees with win height {}",
                tmpl.height, notice.height
            ));
        }

        // 4. Sign the coinstake input, refusing unless at least the value WE know
        //    comes back to us. `known_value` is our ground truth, never the relay's,
        //    and it is now provably the value of the coin actually being spent.
        let script_code = key.p2pkh_script();
        let signed_coinstake = sign_coinstake(&key, &unsigned, &script_code, known_value)?;

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
        let block_signature = sign_block(&key, &header)?;

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

impl<T: TemplateSource + Send + Sync, K: CoinKeys + Send + Sync> StakeSigner for PhoneStaker<T, K> {
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

    fn honest_setup() -> (PhoneStaker<FakeTemplates, SingleKey>, WinNotice) {
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
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: real_value, change: false, key_index: 0 }];
        let staker = PhoneStaker::new(SingleKey(k), "dev-1", coins, templates);
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
    fn hd_wallet_signs_for_a_coin_on_a_nonzero_index() {
        // The point of the HD refactor: a wallet stakes across ALL its addresses.
        // Put the coin on receiving index 3, and let the staker derive that exact
        // key from the HD wallet (not a global single key) to sign.
        use lovenode_hdwallet::HdWallet;
        use lovenode_sign::wallet::Network;
        let (wallet, _phrase) = HdWallet::generate(Network::Test).unwrap();
        let idx = 3u32;
        let k = wallet.receiving_key(idx).unwrap(); // the key that controls the coin
        let txid = "cc".repeat(32);
        let real_value = 10_000 * COIN;
        let coinstake = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&txid).unwrap(), n: 0 },
            vec![TxOut { value: real_value + 498 * COIN, script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();
        let templates =
            FakeTemplates { coinstake, height: 1_001, prev: "aa".repeat(32), bits: 0x2100_ffff };
        let coins = vec![OwnedCoin::receiving(txid.clone(), 0, real_value, idx)];
        // HdKeys must derive the SAME index-3 key to sign successfully.
        let staker = PhoneStaker::new(HdKeys(wallet), "dev-1", coins, templates);
        let signed = staker
            .build_signed_stake(&notice(0x2100_ffff, &txid))
            .expect("HD staker signs a coin on a non-zero index");
        assert_eq!(signed.height, 1_001);
        assert_eq!(signed.block_signature.len(), 130);
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
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: real_value, change: false, key_index: 0 }];
        let staker = PhoneStaker::new(SingleKey(k), "dev-1", coins, templates);

        let err = staker.build_signed_stake(&notice(0x2100_ffff, &txid)).unwrap_err();
        assert!(err.contains("burned as fee"), "got: {err}");
    }

    #[test]
    fn refuses_a_template_that_spends_a_different_coin_than_the_win_names() {
        // THE coin-substitution theft. We own two coins on one key: a small one
        // (named in the win, cheap known_value) and a big one. A hostile template
        // names the small coin but its coinstake spends the BIG coin, paying the
        // big value away. Binding the value check to the actual input refuses it.
        let k = key();
        let small_txid = "cc".repeat(32);
        let big_txid = "dd".repeat(32);
        let big_value = 10_000 * COIN;

        // template's coinstake spends the BIG coin (not the small one the win names)
        let coinstake = build_coinstake(
            OutPoint { hash: hash_from_display_hex(&big_txid).unwrap(), n: 0 },
            vec![TxOut { value: 10_498 * COIN, script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();
        let templates = FakeTemplates { coinstake, height: 1_001, prev: "aa".repeat(32), bits: 0x2100_ffff };
        // the phone knows BOTH coins; the small one is worth 1 sat
        let coins = vec![
            OwnedCoin { txid: small_txid.clone(), vout: 0, value_sats: 1, change: false, key_index: 0 },
            OwnedCoin { txid: big_txid.clone(), vout: 0, value_sats: big_value, change: false, key_index: 0 },
        ];
        let staker = PhoneStaker::new(SingleKey(k), "dev-1", coins, templates);

        // the win names the SMALL coin
        let err = staker.build_signed_stake(&notice(0x2100_ffff, &small_txid)).unwrap_err();
        assert!(err.contains("different coin"), "got: {err}");
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
        let coins = vec![OwnedCoin { txid: txid.clone(), vout: 0, value_sats: 10_000 * COIN, change: false, key_index: 0 }];
        let staker = PhoneStaker::new(SingleKey(k), "dev-1", coins, templates);
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
