//! Divi transaction serialization and the proof-of-stake coinstake.
//!
//! Divi transactions are plain Bitcoin-format — `nTime` is commented out in
//! `primitives/transaction.h`, so there is no PoS timestamp field:
//! ```text
//! nVersion(4) | vin | vout | nLockTime(4)
//! ```
//!
//! The coinstake is the transaction that claims a stake win. Per
//! `CTransaction::IsCoinStake()`:
//! > the coin stake transaction is marked with the first output empty
//!
//! i.e. `vin[0]` spends the staked coin, `vout.len() >= 2`, and `vout[0]` is
//! empty (zero value, empty script).
//!
//! **The phone builds this itself** and must confirm it pays back to its own
//! address before signing (see `docs/SECURITY.md`).

use crate::serialize::{display_hex, dsha256, write_compact_size, write_var_bytes, Reader};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OutPoint {
    /// Funding transaction id, internal byte order.
    pub hash: [u8; 32],
    pub n: u32,
}

impl OutPoint {
    pub fn is_null(&self) -> bool {
        self.hash == [0u8; 32] && self.n == u32::MAX
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxIn {
    /// A spend of `prevout`, unsigned (empty scriptSig) and final.
    pub fn spending(prevout: OutPoint) -> Self {
        Self { prevout, script_sig: Vec::new(), sequence: u32::MAX }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    /// The empty output that marks a transaction as a coinstake.
    pub fn empty() -> Self {
        Self { value: 0, script_pubkey: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.value == 0 && self.script_pubkey.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());

        write_compact_size(&mut out, self.vin.len() as u64);
        for input in &self.vin {
            out.extend_from_slice(&input.prevout.hash);
            out.extend_from_slice(&input.prevout.n.to_le_bytes());
            write_var_bytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }

        write_compact_size(&mut out, self.vout.len() as u64);
        for output in &self.vout {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_var_bytes(&mut out, &output.script_pubkey);
        }

        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Parse a transaction from raw wire bytes. Bounds-checked throughout:
    /// hostile or truncated input errors rather than panicking.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.read_i32()?;

        let vin_count = r.read_compact_size()?;
        let mut vin = Vec::new();
        for _ in 0..vin_count {
            let hash = r.read_hash()?;
            let n = r.read_u32()?;
            let script_sig = r.read_var_bytes()?;
            let sequence = r.read_u32()?;
            vin.push(TxIn { prevout: OutPoint { hash, n }, script_sig, sequence });
        }

        let vout_count = r.read_compact_size()?;
        let mut vout = Vec::new();
        for _ in 0..vout_count {
            let value = r.read_i64()?;
            let script_pubkey = r.read_var_bytes()?;
            vout.push(TxOut { value, script_pubkey });
        }

        let lock_time = r.read_u32()?;
        if !r.is_empty() {
            return Err(format!("{} trailing bytes after transaction", r.remaining()));
        }
        Ok(Transaction { version, vin, vout, lock_time })
    }

    /// Transaction id (internal byte order).
    pub fn txid(&self) -> [u8; 32] {
        dsha256(&self.serialize())
    }

    /// Transaction id as RPC displays it.
    pub fn txid_hex(&self) -> String {
        display_hex(&self.txid())
    }

    /// Mirrors `CTransaction::IsCoinStake()`.
    pub fn is_coinstake(&self) -> bool {
        !self.vin.is_empty()
            && !self.vin[0].prevout.is_null()
            && self.vout.len() >= 2
            && self.vout[0].is_empty()
    }
}

/// Build the unsigned coinstake for a stake win.
///
/// `payouts` are the outputs after the empty marker — normally the staked value
/// plus the reward returning to the staker's own script, and, where the network
/// requires it, any additional payment the block must make. Extra outputs the
/// staker did not choose can only make the block *invalid* (a wasted attempt);
/// they can never redirect the staker's own coins, because those are placed here
/// by the staker.
///
/// The result is unsigned: `vin[0].script_sig` is empty and must be filled in by
/// the signer that holds the key.
pub fn build_coinstake(staked: OutPoint, payouts: Vec<TxOut>) -> Result<Transaction, String> {
    if staked.is_null() {
        return Err("cannot stake a null outpoint".into());
    }
    if payouts.is_empty() {
        return Err("a coinstake needs at least one payout output".into());
    }
    if payouts.iter().any(|o| o.value < 0) {
        return Err("coinstake outputs cannot be negative".into());
    }
    let mut vout = Vec::with_capacity(payouts.len() + 1);
    vout.push(TxOut::empty()); // the coinstake marker
    vout.extend(payouts);

    let tx = Transaction { version: 1, vin: vec![TxIn::spending(staked)], vout, lock_time: 0 };
    debug_assert!(tx.is_coinstake());
    Ok(tx)
}

/// Check that a coinstake returns value to the expected script — the difference
/// between "sign my staking transaction" and "sign away my balance".
///
/// Returns the total paid to `expected_script`.
pub fn coinstake_pays_to(tx: &Transaction, expected_script: &[u8]) -> Result<i64, String> {
    if !tx.is_coinstake() {
        return Err("not a coinstake (first output must be empty)".into());
    }
    // Saturating: a hostile transaction can carry outputs summing past i64::MAX,
    // which panics a debug build and wraps silently in release.
    let paid: i64 = tx
        .vout
        .iter()
        .filter(|o| o.script_pubkey == expected_script)
        .map(|o| o.value)
        .fold(0i64, |acc, v| acc.saturating_add(v));
    if paid <= 0 {
        return Err("coinstake pays nothing back to the staker".into());
    }
    Ok(paid)
}

/// Check the coinstake returns **at least** `min_expected_sats` to our script.
///
/// This is the guard that [`coinstake_pays_to`] alone is not: knowing that
/// *some* value comes back is not enough, because the difference between the
/// input and the outputs is simply paid away as fee.
///
/// Concretely, without this check a relay that under-reports a coin's value
/// causes a coinstake which spends the real (large) output but pays back only
/// the small declared amount — and the remainder is burned. That is loss of
/// principal, not lost earnings.
///
/// `min_expected_sats` must come from what the **signer independently knows**
/// the staked coin is worth, never from the party proposing the coinstake.
pub fn coinstake_returns_at_least(
    tx: &Transaction,
    expected_script: &[u8],
    min_expected_sats: i64,
) -> Result<i64, String> {
    let paid = coinstake_pays_to(tx, expected_script)?;
    if paid < min_expected_sats {
        return Err(format!(
            "coinstake returns only {paid} sats but the staked coin is worth at least \
             {min_expected_sats}; the difference would be burned as fee"
        ));
    }
    Ok(paid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{from_hex, hash_from_display_hex, to_hex};

    // The real coinbase transaction of regtest block 700, taken from the node.
    const RAW_COINBASE: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0502bc020101ffffffff0100000000000000000000000000";
    const COINBASE_TXID: &str =
        "631924290af6236c7f240b62f8c016b48c47074b0ca469cc3b4309b907db3ae9";

    #[test]
    fn reproduces_a_real_transaction_byte_for_byte() {
        // Rebuild the node's own coinbase from its parts and confirm our
        // serializer emits exactly the bytes the node produced.
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint { hash: [0u8; 32], n: u32::MAX }, // null => coinbase
                script_sig: from_hex("02bc020101").unwrap(),
                sequence: u32::MAX,
            }],
            vout: vec![TxOut { value: 0, script_pubkey: Vec::new() }],
            lock_time: 0,
        };
        assert_eq!(to_hex(&tx.serialize()), RAW_COINBASE);
    }

    #[test]
    fn reproduces_a_real_txid() {
        // txid = double-SHA256 of the raw bytes, shown reversed.
        let raw = from_hex(RAW_COINBASE).unwrap();
        assert_eq!(display_hex(&dsha256(&raw)), COINBASE_TXID);
    }

    #[test]
    fn coinstake_has_the_empty_marker_output() {
        let staked = OutPoint { hash: [0x11; 32], n: 2 };
        let payout = TxOut { value: 1_000, script_pubkey: vec![0x76, 0xa9] };
        let tx = build_coinstake(staked, vec![payout]).unwrap();

        assert!(tx.is_coinstake());
        assert!(tx.vout[0].is_empty(), "vout[0] must be the empty marker");
        assert_eq!(tx.vout.len(), 2);
        assert!(tx.vin[0].script_sig.is_empty(), "must be built unsigned");
    }

    #[test]
    fn a_plain_transaction_is_not_a_coinstake() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::spending(OutPoint { hash: [0x11; 32], n: 0 })],
            vout: vec![TxOut { value: 5, script_pubkey: vec![0x51] }],
            lock_time: 0,
        };
        assert!(!tx.is_coinstake(), "needs an empty first output and 2+ outputs");
    }

    #[test]
    fn coinstake_construction_rejects_nonsense() {
        let null = OutPoint { hash: [0u8; 32], n: u32::MAX };
        assert!(build_coinstake(null, vec![TxOut { value: 1, script_pubkey: vec![1] }]).is_err());

        let ok = OutPoint { hash: [0x11; 32], n: 0 };
        assert!(build_coinstake(ok.clone(), vec![]).is_err());
        assert!(build_coinstake(ok, vec![TxOut { value: -1, script_pubkey: vec![1] }]).is_err());
    }

    #[test]
    fn payback_check_catches_a_coinstake_that_pays_someone_else() {
        let mine = vec![0x76, 0xa9, 0x14, 0xaa];
        let theirs = vec![0x76, 0xa9, 0x14, 0xbb];
        let staked = OutPoint { hash: [0x11; 32], n: 0 };

        let good =
            build_coinstake(staked.clone(), vec![TxOut { value: 500, script_pubkey: mine.clone() }])
                .unwrap();
        assert_eq!(coinstake_pays_to(&good, &mine).unwrap(), 500);

        // the attack this guards against: everything routed elsewhere
        let bad =
            build_coinstake(staked, vec![TxOut { value: 500, script_pubkey: theirs }]).unwrap();
        assert!(
            coinstake_pays_to(&bad, &mine).is_err(),
            "must refuse a coinstake that pays nothing back to us"
        );
    }

    #[test]
    fn split_stakes_sum_correctly() {
        // Divi splits stake rewards across multiple outputs; all of ours count.
        let mine = vec![0x76, 0xa9, 0x14, 0xcc];
        let tx = build_coinstake(
            OutPoint { hash: [0x11; 32], n: 0 },
            vec![
                TxOut { value: 300, script_pubkey: mine.clone() },
                TxOut { value: 200, script_pubkey: mine.clone() },
                TxOut { value: 99, script_pubkey: vec![0xde, 0xad] }, // e.g. a required payment
            ],
        )
        .unwrap();
        assert_eq!(coinstake_pays_to(&tx, &mine).unwrap(), 500);
    }

    #[test]
    fn txid_changes_when_any_field_changes() {
        let base = build_coinstake(
            OutPoint { hash: [0x11; 32], n: 0 },
            vec![TxOut { value: 10, script_pubkey: vec![0x51] }],
        )
        .unwrap();
        let id = base.txid();

        let mut other = base.clone();
        other.lock_time = 1;
        assert_ne!(other.txid(), id);

        let mut other2 = base.clone();
        other2.vin[0].prevout.n = 1;
        assert_ne!(other2.txid(), id);

        let mut other3 = base;
        other3.vout[1].value = 11;
        assert_ne!(other3.txid(), id);
    }

    // A REAL coinstake produced by Divi's own staking code (regtest block 700).
    const RAW_COINSTAKE: &str = "010000000167acc570ae2ca4152ff64d563c9b8e6f599c7315c3ae15fffd4aeff2968a111f010000006a473044022003170165c75f0f70e340838caf76adc73eec191991109bcff0e8f3b6fbaf256102205e883516dc54346e37db77670c625054436dc24444a84d074bc9bc6e4916cc09012103237960bdd77ac3cc98792328c3454a131219c0197cb0f51c827550733fa5220bffffffff03000000000000000000004801a69c0000001976a914f8a5f85e154b663bca343ba47fd6fadef43bcef288ac00ba1dd2050000001976a914357f730ffd65afb707e8860ae7b1b227019a4e9088ac00000000";
    const COINSTAKE_TXID: &str = "2ceefc9345840938dd8baffd0fa1383c547f099affd8b990dbe2557b8590e1ab";

    #[test]
    fn parses_a_real_coinstake_and_re_emits_it_byte_for_byte() {
        let raw = from_hex(RAW_COINSTAKE).unwrap();
        let tx = Transaction::deserialize(&raw).unwrap();

        // structure matches what the node reported
        assert!(tx.is_coinstake());
        assert_eq!(tx.vout.len(), 3);
        assert!(tx.vout[0].is_empty());
        assert_eq!(tx.vin.len(), 1);

        // and both directions agree with the node
        assert_eq!(to_hex(&tx.serialize()), RAW_COINSTAKE);
        assert_eq!(tx.txid_hex(), COINSTAKE_TXID);
    }

    #[test]
    fn deserialize_rejects_truncated_and_trailing_garbage() {
        let raw = from_hex(RAW_COINSTAKE).unwrap();
        assert!(Transaction::deserialize(&raw[..raw.len() - 4]).is_err(), "truncated");
        let mut extra = raw.clone();
        extra.push(0x00);
        assert!(Transaction::deserialize(&extra).is_err(), "trailing bytes");
        assert!(Transaction::deserialize(&[]).is_err());
    }

    #[test]
    fn hash_from_display_hex_round_trips_for_a_real_txid() {
        let internal = hash_from_display_hex(COINBASE_TXID).unwrap();
        assert_eq!(display_hex(&internal), COINBASE_TXID);
    }
}
