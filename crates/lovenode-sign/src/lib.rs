//! # lovenode-sign — on-device signing
//!
//! Everything that touches a private key. Kept in its own crate so
//! `lovenode-core` stays dependency-light and auditable, and so the key-handling
//! surface is one small, reviewable place.
//!
//! Signing uses **libsecp256k1** — the same C library the Divi node itself uses —
//! rather than a reimplementation, so signatures come from identical code.
//!
//! ## What the phone signs, and what it must never sign
//!
//! Two signatures are needed to claim a stake:
//! 1. the **coinstake input**, proving the staked coin is yours, and
//! 2. the **block hash** (`BlockSigning.cpp` signs `block.GetHash()`).
//!
//! Both are produced here from structures the phone built itself. This crate
//! deliberately offers **no** "sign these arbitrary 32 bytes" entry point: such a
//! function is exactly what would let a compromised relay hand over a
//! transaction sighash and have it signed. [`sign_block`] takes a
//! [`BlockHeader`] and hashes it internally for that reason.
//!
//! See `docs/SECURITY.md`.

pub mod script;
pub mod sighash;

use lovenode_core::block::BlockHeader;
use lovenode_core::tx::{coinstake_returns_at_least, Transaction};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, SecretKey};

pub use script::{hash160, p2pkh_script, pubkey_from_secret};
pub use sighash::{coinstake_sighash, signature_hash, SIGHASH_ALL};

/// A staking key. Wraps the secret so it is never printed or serialized.
pub struct StakingKey {
    secret: SecretKey,
    compressed: bool,
}

impl std::fmt::Debug for StakingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material into logs.
        f.write_str("StakingKey(<redacted>)")
    }
}

impl StakingKey {
    pub fn from_bytes(bytes: &[u8; 32], compressed: bool) -> Result<Self, String> {
        let secret = SecretKey::from_slice(bytes).map_err(|e| format!("invalid key: {e}"))?;
        Ok(Self { secret, compressed })
    }

    /// The public key, in the encoding the address was derived from.
    pub fn public_key(&self) -> Vec<u8> {
        pubkey_from_secret(&self.secret, self.compressed)
    }

    /// This key's P2PKH scriptPubKey — what its coins pay to, and the
    /// `scriptCode` used when signing.
    pub fn p2pkh_script(&self) -> Vec<u8> {
        p2pkh_script(&hash160(&self.public_key()))
    }
}

/// Sign the coinstake's single input, returning a fully-signed transaction.
///
/// `script_code` is the scriptPubKey of the coin being staked.
/// `staked_value_sats` is what the signer **independently knows** the staked
/// coin is worth — never a figure supplied by whoever proposed the coinstake.
///
/// Refuses to sign unless the coinstake returns at least that much to this key.
/// Checking only that *something* comes back is not enough: the gap between the
/// real input value and the outputs is paid away as fee, so a proposer that
/// under-reports the coin's value would have the remainder burned. That is loss
/// of principal, which this signer must make impossible.
pub fn sign_coinstake(
    key: &StakingKey,
    unsigned: &Transaction,
    script_code: &[u8],
    staked_value_sats: i64,
) -> Result<Transaction, String> {
    if !unsigned.is_coinstake() {
        return Err("not a coinstake (first output must be the empty marker)".into());
    }
    // Guard: at least the full staked value must come back to us.
    coinstake_returns_at_least(unsigned, &key.p2pkh_script(), staked_value_sats)?;

    let sighash = sighash::coinstake_sighash(unsigned, script_code)?;
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, &key.secret);
    // Low-S normalisation: libsecp256k1 already produces canonical low-S
    // signatures, which is what the network's standardness rules require.
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);

    // P2PKH scriptSig: <signature+hashtype> <pubkey>
    let pubkey = key.public_key();
    let mut script_sig = Vec::with_capacity(der.len() + pubkey.len() + 2);
    script::push_data(&mut script_sig, &der);
    script::push_data(&mut script_sig, &pubkey);

    let mut signed = unsigned.clone();
    signed.vin[0].script_sig = script_sig;
    Ok(signed)
}

/// Sign a block header, producing `vchBlockSig`.
///
/// Takes the **header**, not a digest: the hash is computed here from a
/// structure the caller built, so there is no way to be tricked into signing a
/// transaction sighash. `BlockSigning.cpp` uses `SignCompact` for
/// pay-to-pubkey-hash stakes, which is what this produces.
pub fn sign_block(key: &StakingKey, header: &BlockHeader) -> Result<Vec<u8>, String> {
    let hash = header.hash()?; // rejects legacy versions rather than mis-hashing
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(hash);
    let rec_sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &key.secret);
    let (rec_id, compact) = rec_sig.serialize_compact();
    Ok(encode_compact(rec_id, &compact, key.compressed))
}

/// Bitcoin's compact signature encoding, as `CKey::SignCompact` produces:
/// a header byte of 27 + recovery id (+4 when the key is compressed),
/// followed by the 64-byte signature.
fn encode_compact(rec_id: RecoveryId, compact: &[u8; 64], compressed: bool) -> Vec<u8> {
    let id = rec_id.to_i32() as u8;
    let header = 27 + id + if compressed { 4 } else { 0 };
    let mut out = Vec::with_capacity(65);
    out.push(header);
    out.extend_from_slice(compact);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::tx::{build_coinstake, OutPoint, TxOut};
    use secp256k1::ecdsa::Signature;
    use secp256k1::PublicKey;

    fn key() -> StakingKey {
        StakingKey::from_bytes(&[0x42; 32], true).unwrap()
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: 4,
            prev_block: [0x0a; 32],
            merkle_root: [0x0b; 32],
            time: 1_784_407_239,
            bits: 0x207f_ffff,
            nonce: 0,
            accumulator_checkpoint: [0u8; 32],
        }
    }

    fn coinstake_paying(script: Vec<u8>) -> Transaction {
        build_coinstake(
            OutPoint { hash: [0x11; 32], n: 0 },
            vec![TxOut { value: 1_000, script_pubkey: script }],
        )
        .unwrap()
    }

    #[test]
    fn signed_coinstake_verifies_against_our_own_sighash() {
        let k = key();
        let unsigned = coinstake_paying(k.p2pkh_script());
        let script_code = k.p2pkh_script();
        let signed = sign_coinstake(&k, &unsigned, &script_code, 1_000).unwrap();

        // Pull the signature and pubkey back out of the scriptSig and verify.
        let script_sig = &signed.vin[0].script_sig;
        let sig_len = script_sig[0] as usize;
        let der = &script_sig[1..1 + sig_len - 1]; // minus the trailing hashtype
        let hashtype = script_sig[sig_len];
        assert_eq!(hashtype, SIGHASH_ALL as u8);
        let pk_start = 1 + sig_len;
        let pk_len = script_sig[pk_start] as usize;
        let pubkey = &script_sig[pk_start + 1..pk_start + 1 + pk_len];
        assert_eq!(pubkey, k.public_key().as_slice());

        let sighash = coinstake_sighash(&unsigned, &script_code).unwrap();
        let secp = Secp256k1::verification_only();
        let sig = Signature::from_der(der).expect("valid DER");
        let pk = PublicKey::from_slice(pubkey).expect("valid pubkey");
        assert!(secp
            .verify_ecdsa(&Message::from_digest(sighash), &sig, &pk)
            .is_ok());
    }

    #[test]
    fn refuses_to_sign_a_coinstake_that_pays_someone_else() {
        // THE critical guard. A relay proposing a coinstake that routes the
        // staker's coins elsewhere must never get a signature.
        let k = key();
        let attacker_script = p2pkh_script(&[0xbb; 20]);
        let hostile = coinstake_paying(attacker_script);
        let err = sign_coinstake(&k, &hostile, &k.p2pkh_script(), 1_000).unwrap_err();
        assert!(err.contains("pays nothing back"), "got: {err}");
    }

    #[test]
    fn refuses_a_coinstake_that_would_burn_the_stake_as_fee() {
        // THE attack: a relay under-reports the coin's value, so the coinstake
        // spends a 10,000 DIVI output but pays back only 100 -- the rest is
        // burned as fee. Signing must be refused when the returned value is
        // below what we independently know the coin is worth.
        let k = key();
        let real_value = 10_000 * lovenode_core::COIN;
        let under_paying = build_coinstake(
            OutPoint { hash: [0x11; 32], n: 0 },
            vec![TxOut { value: 100 * lovenode_core::COIN, script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();

        let err = sign_coinstake(&k, &under_paying, &k.p2pkh_script(), real_value).unwrap_err();
        assert!(err.contains("burned as fee"), "got: {err}");

        // and the honest case still signs
        let honest = build_coinstake(
            OutPoint { hash: [0x11; 32], n: 0 },
            vec![TxOut { value: real_value + 498 * lovenode_core::COIN,
                         script_pubkey: k.p2pkh_script() }],
        )
        .unwrap();
        assert!(sign_coinstake(&k, &honest, &k.p2pkh_script(), real_value).is_ok());
    }

    #[test]
    fn refuses_a_transaction_that_is_not_a_coinstake() {
        let k = key();
        let mut tx = coinstake_paying(k.p2pkh_script());
        tx.vout.remove(0); // drop the empty marker
        assert!(sign_coinstake(&k, &tx, &k.p2pkh_script(), 1_000).is_err());
    }

    #[test]
    fn block_signature_is_65_bytes_and_recovers_the_signer() {
        let k = key();
        let h = header();
        let sig = sign_block(&k, &h).unwrap();
        assert_eq!(sig.len(), 65, "compact signature is a header byte + 64");

        // The header byte must encode "compressed" (27 + recid + 4 => 31..34).
        assert!((31..=34).contains(&sig[0]), "header byte was {}", sig[0]);

        // Recover the public key from the signature over the header hash and
        // confirm it is ours — proving we signed the block we actually built.
        let rec_id = RecoveryId::from_i32(((sig[0] - 27) & 3) as i32).unwrap();
        let rec = RecoverableSignature::from_compact(&sig[1..], rec_id).unwrap();
        let secp = Secp256k1::new();
        let recovered = secp
            .recover_ecdsa(&Message::from_digest(h.hash().unwrap()), &rec)
            .unwrap();
        assert_eq!(recovered.serialize().to_vec(), k.public_key());
    }

    #[test]
    fn block_signing_refuses_legacy_versions_rather_than_mis_hashing() {
        let k = key();
        let legacy = BlockHeader { version: 3, ..header() };
        assert!(sign_block(&k, &legacy).is_err(), "v<4 uses HashQuark");
    }

    #[test]
    fn signing_the_same_thing_twice_is_stable() {
        // libsecp256k1 uses RFC6979 deterministic nonces, so a repeated signature
        // is identical -- no nonce-reuse surprises across retries.
        let k = key();
        assert_eq!(sign_block(&k, &header()).unwrap(), sign_block(&k, &header()).unwrap());
    }

    #[test]
    fn a_different_block_gets_a_different_signature() {
        let k = key();
        let a = sign_block(&k, &header()).unwrap();
        let b = sign_block(&k, &BlockHeader { nonce: 1, ..header() }).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_material_never_appears_in_debug_output() {
        assert_eq!(format!("{:?}", key()), "StakingKey(<redacted>)");
    }
}
