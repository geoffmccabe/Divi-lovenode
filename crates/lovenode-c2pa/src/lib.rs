//! # lovenode-c2pa — Divi Proof-of-Existence as a C2PA assertion
//!
//! Makes a Divi anchor legible to the wider content-provenance ecosystem.
//! Adobe's Content Authenticity Initiative, newsroom tooling and camera firmware
//! all speak **C2PA Content Credentials**; this crate defines the assertion that
//! carries a Divi anchor inside one, so a photo anchored on Divi verifies in
//! tools that have never heard of Divi.
//!
//! ## Why bother, when C2PA already signs the content
//!
//! C2PA deliberately uses **no blockchain** — it signs with X.509 certificates.
//! That is a good design, with one structural weakness: certificates expire, get
//! revoked, and the authorities behind them eventually disappear. When that
//! happens the signature's *meaning* decays, and there is no independent way to
//! establish **when** the content existed.
//!
//! A chain anchor does not rot. It supplies exactly the thing PKI cannot: an
//! independent, permanent, non-revocable timestamp. The two are complements, not
//! competitors — C2PA proves *who signed and what was done*, the anchor proves
//! *by when it existed*.
//!
//! ## ⚠ The ordering problem (read before using)
//!
//! Embedding a manifest changes the file's bytes, so "hash the file, anchor it,
//! then put the txid in the manifest" is circular: the anchored hash is of the
//! file *before* the manifest existed. There is no way around this — only two
//! honest ways through it, both supported here (see [`AnchorMode`]):
//!
//! * [`AnchorMode::PreManifest`] — anchor the original asset, then sign a
//!   manifest that records that hash and txid. The assertion states plainly that
//!   `document_hash` refers to the asset **as it was before this manifest was
//!   embedded**, so a verifier knows what to reproduce.
//! * [`AnchorMode::PostManifest`] — sign the manifest first, then anchor the
//!   hash of the *signed* asset and keep the proof alongside it (or in a second
//!   manifest that takes the first as an ingredient). Nothing is circular, and
//!   the anchor covers the credential itself.
//!
//! Silently picking one and hoping is how these systems end up unverifiable, so
//! the mode is recorded **in the assertion** and verification requires it.

use lovenode_core::serialize::{from_hex, to_hex};
use serde::{Deserialize, Serialize};

pub mod record;
pub use record::{parse_poe_record, PoeRecord};

/// Reverse-DNS assertion label, per the C2PA convention for vendor assertions.
/// Namespaced to divi.love, the domain that serves the network's seeds.
pub const ASSERTION_LABEL: &str = "love.divi.poe";

/// Version of this assertion schema.
pub const ASSERTION_VERSION: u32 = 1;

/// What the anchored hash refers to. See the ordering problem above.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorMode {
    /// `document_hash` is of the asset **before** this manifest was embedded.
    PreManifest,
    /// `document_hash` is of the asset **after** signing, including its manifest.
    PostManifest,
}

/// The Divi anchor, as carried inside a C2PA manifest.
///
/// Deliberately minimal: it binds a document hash to a transaction. Block height
/// and time are **not** stored, because they are not known when the manifest is
/// signed and would be stale or absent if guessed — a verifier resolves them
/// from the chain, which is authoritative anyway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiviPoeAssertion {
    /// Schema version of this assertion.
    pub version: u32,
    /// Chain identifier, e.g. "divi".
    pub chain: String,
    /// Network: "main", "testnet" or "regtest".
    pub network: String,
    /// Hash algorithm — only "sha256" is defined today.
    pub hash_alg: String,
    /// The hash that was anchored, hex, as displayed.
    pub document_hash: String,
    /// The Divi transaction carrying the anchor, display hex.
    pub txid: String,
    /// Which bytes `document_hash` covers.
    pub anchor_mode: AnchorMode,
}

impl DiviPoeAssertion {
    /// Build an assertion for a completed anchor.
    pub fn new(
        network: &str,
        document_hash: &[u8; 32],
        txid: &str,
        anchor_mode: AnchorMode,
    ) -> Result<Self, String> {
        validate_txid(txid)?;
        Ok(Self {
            version: ASSERTION_VERSION,
            chain: "divi".to_string(),
            network: network.to_string(),
            hash_alg: "sha256".to_string(),
            document_hash: to_hex(document_hash),
            txid: txid.trim().to_lowercase(),
            anchor_mode,
        })
    }

    /// Serialize for embedding as a C2PA custom assertion (JSON form).
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("cannot serialize assertion: {e}"))
    }

    /// Parse an assertion pulled out of a manifest, rejecting anything malformed
    /// rather than partially trusting it.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let a: Self =
            serde_json::from_str(json).map_err(|e| format!("cannot parse assertion: {e}"))?;
        a.validate()?;
        Ok(a)
    }

    /// Structural checks. Verification against the chain is separate
    /// ([`verify_against_record`]) because it needs chain access.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != ASSERTION_VERSION {
            return Err(format!(
                "unsupported assertion version {} (expected {ASSERTION_VERSION})",
                self.version
            ));
        }
        if self.chain != "divi" {
            return Err(format!("not a Divi assertion: chain={}", self.chain));
        }
        if self.hash_alg != "sha256" {
            return Err(format!("unsupported hash algorithm: {}", self.hash_alg));
        }
        if !matches!(self.network.as_str(), "main" | "testnet" | "regtest") {
            return Err(format!("unknown network: {}", self.network));
        }
        validate_hex32(&self.document_hash, "document_hash")?;
        validate_txid(&self.txid)?;
        Ok(())
    }

    /// The anchored hash as bytes.
    pub fn document_hash_bytes(&self) -> Result<[u8; 32], String> {
        let v = from_hex(&self.document_hash)?;
        v.try_into().map_err(|_| "document_hash is not 32 bytes".to_string())
    }
}

/// Verify an assertion against the on-chain record found in its transaction.
///
/// `record_script_hex` is the OP_META output's script, as the chain reports it.
/// This is the step that turns "the manifest claims an anchor" into "the anchor
/// is really there" — a manifest is only as good as this check.
pub fn verify_against_record(
    assertion: &DiviPoeAssertion,
    record_script_hex: &str,
) -> Result<(), String> {
    assertion.validate()?;
    let record = parse_poe_record(record_script_hex)
        .ok_or("the transaction carries no Divi PoE record")?;
    // The chain must agree with what the assertion declares about itself.
    // Without this, a record anchoring a hash under a different algorithm or a
    // future layout is accepted as a SHA-256 v1 anchor.
    if record.version != ASSERTION_VERSION as u8 {
        return Err(format!(
            "on-chain record is version {} but the manifest declares {ASSERTION_VERSION}",
            record.version
        ));
    }
    if record.hash_alg != 0x01 {
        return Err(format!(
            "on-chain record uses hash algorithm 0x{:02x}, not SHA-256, but the manifest \
             declares \"{}\"",
            record.hash_alg, assertion.hash_alg
        ));
    }
    let claimed = assertion.document_hash.trim().to_lowercase();
    if record.document_hash != claimed {
        return Err(format!(
            "anchor mismatch: chain holds {}, manifest claims {claimed}",
            record.document_hash
        ));
    }
    Ok(())
}

fn validate_hex32(s: &str, field: &str) -> Result<(), String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{field} is not 64 hex characters"));
    }
    Ok(())
}

fn validate_txid(txid: &str) -> Result<(), String> {
    validate_hex32(txid, "txid")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [0xab; 32];
    const TXID: &str = "9046c496c295690f279f224c7136be59603bc6c5c921a58c9aba5fb995f357bb";

    fn assertion() -> DiviPoeAssertion {
        DiviPoeAssertion::new("main", &HASH, TXID, AnchorMode::PreManifest).unwrap()
    }

    #[test]
    fn round_trips_through_json() {
        let a = assertion();
        let back = DiviPoeAssertion::from_json(&a.to_json().unwrap()).unwrap();
        assert_eq!(a, back);
        assert_eq!(back.document_hash_bytes().unwrap(), HASH);
    }

    #[test]
    fn the_anchor_mode_survives_the_round_trip() {
        // If the mode were lost, a verifier would not know which bytes the hash
        // covers -- the whole ordering problem in one field.
        for mode in [AnchorMode::PreManifest, AnchorMode::PostManifest] {
            let a = DiviPoeAssertion::new("main", &HASH, TXID, mode).unwrap();
            let json = a.to_json().unwrap();
            assert_eq!(DiviPoeAssertion::from_json(&json).unwrap().anchor_mode, mode);
        }
        // and it is spelled readably in the JSON, not as an opaque number
        let json = assertion().to_json().unwrap();
        assert!(json.contains("pre_manifest"), "got: {json}");
    }

    #[test]
    fn malformed_assertions_are_refused() {
        assert!(DiviPoeAssertion::new("main", &HASH, "nope", AnchorMode::PreManifest).is_err());

        let mut bad = assertion();
        bad.chain = "bitcoin".into();
        assert!(bad.validate().is_err(), "must not accept another chain");

        let mut bad2 = assertion();
        bad2.hash_alg = "md5".into();
        assert!(bad2.validate().is_err(), "must not accept a weak algorithm");

        let mut bad3 = assertion();
        bad3.network = "mainnet".into(); // not one of the three valid names
        assert!(bad3.validate().is_err());

        let mut bad4 = assertion();
        bad4.version = 99;
        assert!(bad4.validate().is_err(), "must not guess at a future schema");
    }

    #[test]
    fn parsing_rejects_junk_rather_than_half_trusting_it() {
        assert!(DiviPoeAssertion::from_json("").is_err());
        assert!(DiviPoeAssertion::from_json("{}").is_err());
        assert!(DiviPoeAssertion::from_json(r#"{"chain":"divi"}"#).is_err());
    }

    #[test]
    fn verifies_against_a_matching_on_chain_record() {
        // A real-shaped DVXP PoE record: OP_META, push 39, DVXP|v1|type1|sha256|hash
        let hash_hex = to_hex(&HASH);
        let script = format!("6a27{}{}", "44565850010101", hash_hex);
        let a = DiviPoeAssertion::new("main", &HASH, TXID, AnchorMode::PreManifest).unwrap();
        assert!(verify_against_record(&a, &script).is_ok());
    }

    #[test]
    fn catches_a_manifest_claiming_an_anchor_it_does_not_have() {
        // The attack this exists to stop: a Content Credential that points at a
        // real transaction which anchors somebody else's content.
        let other = [0xcd; 32];
        let script = format!("6a27{}{}", "44565850010101", to_hex(&other));
        let a = DiviPoeAssertion::new("main", &HASH, TXID, AnchorMode::PreManifest).unwrap();
        let err = verify_against_record(&a, &script).unwrap_err();
        assert!(err.contains("anchor mismatch"), "got: {err}");
    }

    #[test]
    fn a_transaction_with_no_poe_record_fails_closed() {
        let a = assertion();
        assert!(verify_against_record(&a, "6a0400112233").is_err());
        assert!(verify_against_record(&a, "").is_err());
    }

    #[test]
    fn the_label_is_reverse_dns_as_c2pa_requires() {
        assert_eq!(ASSERTION_LABEL, "love.divi.poe");
        assert!(!ASSERTION_LABEL.starts_with("c2pa."), "must not squat the c2pa namespace");
    }
}
