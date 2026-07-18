//! Divi block header: serialization, hashing, and the merkle root.
//!
//! The phone builds this itself and hashes it locally — it must never sign a
//! digest handed to it by the relay (see `docs/SECURITY.md`). That makes this
//! module part of the security boundary, not just a convenience.
//!
//! Header layout (`primitives/block.h`):
//! ```text
//! nVersion(4) hashPrevBlock(32) hashMerkleRoot(32) nTime(4) nBits(4) nNonce(4)
//! nAccumulatorCheckpoint(32)   <- only when nVersion > 3
//! ```
//! Divi blocks are version 4, so the header is **112 bytes, not 80**. Hashing
//! only the first 80 would silently produce a wrong block hash every time.
//!
//! And from `primitives/block.cpp`:
//! ```text
//! if (nVersion < 4) return HashQuark(...);   // legacy PoW-era blocks
//! return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
//! ```

use crate::serialize::{dsha256, display_hex};

/// The 112-byte (v4+) Divi block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    /// Previous block hash, internal byte order.
    pub prev_block: [u8; 32],
    /// Merkle root, internal byte order.
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    /// Zerocoin accumulator checkpoint; serialized only when `version > 3`.
    pub accumulator_checkpoint: [u8; 32],
}

impl BlockHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(112);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.prev_block);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        if self.version > 3 {
            out.extend_from_slice(&self.accumulator_checkpoint);
        }
        out
    }

    /// The block hash. Only version >= 4 is supported: earlier blocks use
    /// HashQuark, a different algorithm, and are historical only. Returning an
    /// error beats silently computing a wrong hash for consensus code.
    pub fn hash(&self) -> Result<[u8; 32], String> {
        if self.version < 4 {
            return Err(format!(
                "block version {} uses HashQuark (legacy PoW era) and is not supported",
                self.version
            ));
        }
        Ok(dsha256(&self.serialize()))
    }

    /// The block hash in display (reversed) hex, as RPC reports it.
    pub fn hash_hex(&self) -> Result<String, String> {
        self.hash().map(|h| display_hex(&h))
    }
}

/// Merkle root over transaction ids (internal byte order).
///
/// Bitcoin's construction, including the odd-count duplication that causes
/// CVE-2012-2459 — reproduced deliberately, because consensus requires it.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("level is non-empty");
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                dsha256(&buf)
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::hash_from_display_hex;

    // A real Divi block (regtest height 700, version 4), read straight from a
    // node. If the header layout or hashing ever drifts, these fail.
    const BLOCK_HASH: &str = "c9dadb995b26fbbabb767d919bfbfce7f5546b94681eaa89f372b08e22a78d10";
    const PREV: &str = "0a1b072419cdcccbf3f392226a4b8b138c75404dc3fc8fe4ce87e045d3f1f287";
    const MERKLE: &str = "c364b304be6cf8514f72e4d47de99426213a008eded9db81b6aed2ece0a58aec";
    const TXID0: &str = "631924290af6236c7f240b62f8c016b48c47074b0ca469cc3b4309b907db3ae9";
    const TXID1: &str = "2ceefc9345840938dd8baffd0fa1383c547f099affd8b990dbe2557b8590e1ab";

    fn real_header() -> BlockHeader {
        BlockHeader {
            version: 4,
            prev_block: hash_from_display_hex(PREV).unwrap(),
            merkle_root: hash_from_display_hex(MERKLE).unwrap(),
            time: 1_784_407_239,
            bits: 0x207f_ffff,
            nonce: 0,
            accumulator_checkpoint: [0u8; 32],
        }
    }

    #[test]
    fn reproduces_a_real_block_hash() {
        // THE decisive check: our header bytes hash to the hash the node reports.
        assert_eq!(real_header().hash_hex().unwrap(), BLOCK_HASH);
    }

    #[test]
    fn v4_header_is_112_bytes_not_80() {
        assert_eq!(real_header().serialize().len(), 112);
        let legacy = BlockHeader { version: 3, ..real_header() };
        assert_eq!(legacy.serialize().len(), 80, "pre-v4 omits the accumulator");
    }

    #[test]
    fn accumulator_is_actually_covered_by_the_hash() {
        // Guard against "serialized but not hashed": changing only the
        // accumulator must change the block hash.
        let a = real_header();
        let mut b = a.clone();
        b.accumulator_checkpoint = [0x01; 32];
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn legacy_versions_are_refused_rather_than_mishashed() {
        let legacy = BlockHeader { version: 3, ..real_header() };
        assert!(legacy.hash().is_err(), "v<4 uses HashQuark; must not guess");
    }

    #[test]
    fn reproduces_a_real_merkle_root() {
        let txids = [
            hash_from_display_hex(TXID0).unwrap(),
            hash_from_display_hex(TXID1).unwrap(),
        ];
        assert_eq!(display_hex(&merkle_root(&txids)), MERKLE);
    }

    #[test]
    fn merkle_edge_cases() {
        let a = hash_from_display_hex(TXID0).unwrap();
        // a single transaction is its own root
        assert_eq!(merkle_root(&[a]), a);
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        // odd counts duplicate the last leaf (the CVE-2012-2459 behaviour)
        let b = hash_from_display_hex(TXID1).unwrap();
        assert_eq!(merkle_root(&[a, b, b]), merkle_root(&[a, b, b, b]));
    }

    #[test]
    fn header_fields_all_affect_the_hash() {
        let base = real_header();
        let h = base.hash().unwrap();
        for modified in [
            BlockHeader { time: base.time + 1, ..base.clone() },
            BlockHeader { nonce: 1, ..base.clone() },
            BlockHeader { bits: 0x207f_fffe, ..base.clone() },
            BlockHeader { prev_block: [0xaa; 32], ..base.clone() },
            BlockHeader { merkle_root: [0xbb; 32], ..base.clone() },
        ] {
            assert_ne!(modified.hash().unwrap(), h);
        }
    }
}
