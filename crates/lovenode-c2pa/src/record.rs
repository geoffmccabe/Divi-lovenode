//! Reading the DVXP Proof-of-Existence record out of an on-chain OP_META output.
//!
//! Format (see `Divi-Blockchain_6.9/docs/POE-NFT-RECORD-FORMAT.md`):
//! ```text
//! OP_META(0x6a) PUSH(payload)
//! payload = "DVXP"(4) | version(1) | type(1)=0x01 | hashAlg(1)=0x01 | hash(32)
//! ```
//! 39 bytes of payload. Bounds-checked against arbitrary on-chain data: the
//! chain is full of unrelated nulldata, so this must fail closed on anything
//! that is not exactly our record.

/// A parsed Proof-of-Existence record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoeRecord {
    pub version: u8,
    pub record_type: u8,
    pub hash_alg: u8,
    /// The anchored document hash, lowercase hex.
    pub document_hash: String,
}

const MAGIC: &str = "44565850"; // "DVXP"
const TYPE_POE: &str = "01";
const PAYLOAD_HEX_LEN: usize = 78; // 39 bytes

/// Parse a PoE record from an OP_META scriptPubKey hex, or `None`.
pub fn parse_poe_record(script_hex: &str) -> Option<PoeRecord> {
    let s = script_hex.trim().to_lowercase();
    if s.len() < 4 || !s.starts_with("6a") || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    // Push length: a single-byte push, or OP_PUSHDATA1 (0x4c).
    let (payload_off, push_len) = match &s[2..4] {
        "4c" => {
            if s.len() < 6 {
                return None;
            }
            (6usize, usize::from_str_radix(&s[4..6], 16).ok()?)
        }
        b => {
            let n = usize::from_str_radix(b, 16).ok()?;
            if n > 75 {
                return None; // not a single-byte push
            }
            (4usize, n)
        }
    };

    let payload = s.get(payload_off..payload_off.checked_add(push_len * 2)?)?;
    if payload.len() < PAYLOAD_HEX_LEN || !payload.starts_with(MAGIC) {
        return None;
    }
    if &payload[10..12] != TYPE_POE {
        return None; // a different DVXP record type (NFD, batch, ...)
    }

    Some(PoeRecord {
        version: u8::from_str_radix(&payload[8..10], 16).ok()?,
        record_type: 1,
        hash_alg: u8::from_str_radix(&payload[12..14], 16).ok()?,
        document_hash: payload[14..PAYLOAD_HEX_LEN].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_script(hash_hex: &str) -> String {
        format!("6a27{}{}", "44565850010101", hash_hex)
    }

    #[test]
    fn parses_a_well_formed_record() {
        let hash = "aa".repeat(32);
        let r = parse_poe_record(&record_script(&hash)).expect("should parse");
        assert_eq!(r.version, 1);
        assert_eq!(r.record_type, 1);
        assert_eq!(r.hash_alg, 1);
        assert_eq!(r.document_hash, hash);
    }

    #[test]
    fn accepts_the_pushdata1_encoding_too() {
        let hash = "bb".repeat(32);
        let s = format!("6a4c27{}{}", "44565850010101", hash);
        assert_eq!(parse_poe_record(&s).unwrap().document_hash, hash);
    }

    #[test]
    fn rejects_other_dvxp_record_types() {
        let hash = "cc".repeat(32);
        // type 0x03 is the Merkle batch root, not a single-document PoE
        let batch = format!("6a27{}{}", "44565850010301", hash);
        assert!(parse_poe_record(&batch).is_none(), "must not read a batch as a PoE");
        // type 0x02 is reserved for NFDs
        let nfd = format!("6a27{}{}", "44565850010201", hash);
        assert!(parse_poe_record(&nfd).is_none());
    }

    #[test]
    fn fails_closed_on_unrelated_or_hostile_data() {
        for bad in [
            "",                       // empty
            "6a",                     // truncated
            "ff27445658500101",       // not OP_META
            "6a2700",                 // truncated payload
            "6a27445658",             // magic cut short
            "6a4c",                   // PUSHDATA1 with no length
            "6azz",                   // not hex
            "6a2744565850010101aa",   // payload shorter than a full record
        ] {
            assert!(parse_poe_record(bad).is_none(), "should reject {bad:?}");
        }
    }

    #[test]
    fn a_push_longer_than_the_data_is_refused() {
        // Claims a 39-byte push but supplies far less: must not read past the end.
        assert!(parse_poe_record("6a2744565850").is_none());
    }

    #[test]
    fn is_case_insensitive_about_hex() {
        let hash = "AB".repeat(32);
        let upper = format!("6A27{}{}", "44565850010101", hash);
        assert_eq!(parse_poe_record(&upper).unwrap().document_hash, "ab".repeat(32));
    }
}
