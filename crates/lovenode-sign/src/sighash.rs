//! Legacy Bitcoin signature hash, as Divi uses it.
//!
//! From `script/SignatureCheckers.cpp`:
//! ```text
//! CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);
//! CHashWriter ss(SER_GETHASH, 0);
//! ss << txTmp << nHashType;
//! return ss.GetHash();
//! ```
//!
//! For `SIGHASH_ALL` that serializer means: the input being signed carries
//! `scriptCode` as its scriptSig, every other input carries an empty script, all
//! outputs are kept, then the 4-byte hash type is appended and the whole thing is
//! double-SHA256'd.
//!
//! Only `SIGHASH_ALL` is implemented. A coinstake never needs anything else, and
//! a half-implemented SIGHASH_SINGLE/ANYONECANPAY is a classic source of
//! fund-losing bugs — the other types are refused rather than approximated.

use lovenode_core::serialize::dsha256;
use lovenode_core::tx::{Transaction, TxIn};

pub const SIGHASH_ALL: u32 = 1;

/// Compute the signature hash for input `n_in`, signing with `script_code`
/// (normally the scriptPubKey of the output being spent).
pub fn signature_hash(
    tx: &Transaction,
    n_in: usize,
    script_code: &[u8],
    hash_type: u32,
) -> Result<[u8; 32], String> {
    if hash_type != SIGHASH_ALL {
        return Err(format!(
            "only SIGHASH_ALL ({SIGHASH_ALL}) is supported, got {hash_type}"
        ));
    }
    if n_in >= tx.vin.len() {
        return Err(format!("input {n_in} out of range ({} inputs)", tx.vin.len()));
    }

    // Blank every scriptSig except the one being signed, which gets script_code.
    let mut tmp = tx.clone();
    for (i, input) in tmp.vin.iter_mut().enumerate() {
        input.script_sig = if i == n_in { script_code.to_vec() } else { Vec::new() };
    }

    let mut buf = tmp.serialize();
    buf.extend_from_slice(&hash_type.to_le_bytes());
    Ok(dsha256(&buf))
}

/// Convenience: the sighash for a single-input transaction such as a coinstake.
pub fn coinstake_sighash(tx: &Transaction, script_code: &[u8]) -> Result<[u8; 32], String> {
    signature_hash(tx, 0, script_code, SIGHASH_ALL)
}

/// True when the transaction's input scripts are all empty (i.e. unsigned).
pub fn is_unsigned(tx: &Transaction) -> bool {
    tx.vin.iter().all(|i: &TxIn| i.script_sig.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::tx::{build_coinstake, OutPoint, TxOut};

    fn unsigned_coinstake() -> Transaction {
        build_coinstake(
            OutPoint { hash: [0x11; 32], n: 3 },
            vec![TxOut { value: 1_000, script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa] }],
        )
        .unwrap()
    }

    // A REAL coinstake produced by Divi's own staking code (regtest block 700),
    // and the scriptPubKey of the coin it spent. If our sighash is right, the
    // node's own signature must verify against the hash WE compute.
    const RAW_COINSTAKE: &str = "010000000167acc570ae2ca4152ff64d563c9b8e6f599c7315c3ae15fffd4aeff2968a111f010000006a473044022003170165c75f0f70e340838caf76adc73eec191991109bcff0e8f3b6fbaf256102205e883516dc54346e37db77670c625054436dc24444a84d074bc9bc6e4916cc09012103237960bdd77ac3cc98792328c3454a131219c0197cb0f51c827550733fa5220bffffffff03000000000000000000004801a69c0000001976a914f8a5f85e154b663bca343ba47fd6fadef43bcef288ac00ba1dd2050000001976a914357f730ffd65afb707e8860ae7b1b227019a4e9088ac00000000";
    const FUNDING_SCRIPT: &str = "76a914f8a5f85e154b663bca343ba47fd6fadef43bcef288ac";

    #[test]
    fn the_nodes_own_signature_verifies_against_our_sighash() {
        use lovenode_core::serialize::from_hex;
        use secp256k1::ecdsa::Signature;
        use secp256k1::{Message, PublicKey, Secp256k1};

        let signed = Transaction::deserialize(&from_hex(RAW_COINSTAKE).unwrap()).unwrap();

        // Split the real scriptSig into <sig+hashtype> <pubkey>.
        let ss = &signed.vin[0].script_sig;
        let sig_len = ss[0] as usize;
        let der = &ss[1..sig_len]; // drop the trailing SIGHASH byte
        assert_eq!(ss[sig_len], SIGHASH_ALL as u8, "node used SIGHASH_ALL");
        let pk_len = ss[1 + sig_len] as usize;
        let pubkey = &ss[2 + sig_len..2 + sig_len + pk_len];

        // Reconstruct the unsigned form the node must have hashed.
        let mut unsigned = signed.clone();
        unsigned.vin[0].script_sig = Vec::new();
        let our_sighash =
            coinstake_sighash(&unsigned, &from_hex(FUNDING_SCRIPT).unwrap()).unwrap();

        // THE PROOF: Divi's own signature validates over the hash we computed.
        let secp = Secp256k1::verification_only();
        let sig = Signature::from_der(der).expect("node produced valid DER");
        let pk = PublicKey::from_slice(pubkey).expect("node produced a valid pubkey");
        secp.verify_ecdsa(&Message::from_digest(our_sighash), &sig, &pk)
            .expect("our sighash must match the one the node signed");
    }

    #[test]
    fn rejects_unsupported_hash_types() {
        let tx = unsigned_coinstake();
        for bad in [0u32, 2, 3, 0x81] {
            assert!(signature_hash(&tx, 0, &[0x51], bad).is_err(), "must refuse type {bad}");
        }
    }

    #[test]
    fn rejects_out_of_range_input() {
        let tx = unsigned_coinstake();
        assert!(signature_hash(&tx, 1, &[0x51], SIGHASH_ALL).is_err());
    }

    #[test]
    fn script_code_is_committed_to() {
        // Signing with a different scriptCode must give a different hash,
        // otherwise a signature could be replayed against another script.
        let tx = unsigned_coinstake();
        let a = signature_hash(&tx, 0, &[0x76, 0xa9, 0x14, 0xaa], SIGHASH_ALL).unwrap();
        let b = signature_hash(&tx, 0, &[0x76, 0xa9, 0x14, 0xbb], SIGHASH_ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn every_output_is_committed_to() {
        // SIGHASH_ALL must bind all outputs: changing where the money goes has
        // to invalidate the signature. This is the property that stops a relay
        // rewriting payouts after the fact.
        let tx = unsigned_coinstake();
        let base = coinstake_sighash(&tx, &[0x51]).unwrap();

        let mut moved = tx.clone();
        moved.vout[1].script_pubkey = vec![0x76, 0xa9, 0x14, 0xbb]; // pay someone else
        assert_ne!(coinstake_sighash(&moved, &[0x51]).unwrap(), base);

        let mut amount = tx.clone();
        amount.vout[1].value += 1;
        assert_ne!(coinstake_sighash(&amount, &[0x51]).unwrap(), base);

        let mut extra = tx;
        extra.vout.push(TxOut { value: 1, script_pubkey: vec![0xde] });
        assert_ne!(coinstake_sighash(&extra, &[0x51]).unwrap(), base);
    }

    #[test]
    fn the_staked_coin_is_committed_to() {
        let tx = unsigned_coinstake();
        let base = coinstake_sighash(&tx, &[0x51]).unwrap();
        let mut other = tx;
        other.vin[0].prevout.n = 4;
        assert_ne!(coinstake_sighash(&other, &[0x51]).unwrap(), base);
    }

    #[test]
    fn signing_does_not_mutate_the_caller_transaction() {
        let tx = unsigned_coinstake();
        let before = tx.clone();
        let _ = coinstake_sighash(&tx, &[0x76, 0xa9]).unwrap();
        assert_eq!(tx, before, "sighash must not disturb the transaction");
        assert!(is_unsigned(&tx));
    }
}
