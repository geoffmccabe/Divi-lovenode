//! Divi/Bitcoin wire-format primitives.
//!
//! Consensus-critical: these bytes decide whether a block is accepted. Every
//! function here is validated against real chain data in the tests of the
//! modules that use it.

use sha2::{Digest, Sha256};

/// Double-SHA256, the hash used for txids, block hashes and merkle nodes.
pub fn dsha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Bitcoin "CompactSize" length prefix.
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// A length-prefixed byte string (scripts).
pub fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Parse a 64-hex hash in *display* order (as RPC and explorers show it) into
/// the internal byte order used for hashing. Divi, like Bitcoin, reverses these
/// for display — mixing the two up is the single easiest way to break everything.
pub fn hash_from_display_hex(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not a 64-hex hash: {hex}"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[31 - i] =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Internal byte order → the reversed hex form shown by RPC.
pub fn display_hex(internal: &[u8; 32]) -> String {
    internal.iter().rev().map(|b| format!("{b:02x}")).collect()
}

/// Decode an arbitrary hex string (not byte-reversed) — for raw transactions.
pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not valid hex".to_string());
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Encode bytes as hex (not byte-reversed).
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_boundaries() {
        let enc = |n| {
            let mut v = Vec::new();
            write_compact_size(&mut v, n);
            v
        };
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(0xfc), vec![0xfc]);
        assert_eq!(enc(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(enc(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(enc(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(enc(0xffff_ffff), vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            enc(0x1_0000_0000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn dsha256_matches_a_known_vector() {
        // double-SHA256 of the empty string
        assert_eq!(
            to_hex(&dsha256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn display_and_internal_order_round_trip() {
        let display = "c9dadb995b26fbbabb767d919bfbfce7f5546b94681eaa89f372b08e22a78d10";
        let internal = hash_from_display_hex(display).unwrap();
        assert_eq!(display_hex(&internal), display);
        // and the reversal is real, not a no-op
        assert_ne!(to_hex(&internal), display);
    }

    #[test]
    fn hex_helpers_reject_malformed_input() {
        assert!(from_hex("abc").is_err()); // odd length
        assert!(from_hex("zz").is_err());
        assert!(hash_from_display_hex("").is_err());
        assert_eq!(from_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
    }
}
