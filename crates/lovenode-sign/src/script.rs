//! Script and key-hash helpers.

use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Bitcoin's HASH160: RIPEMD160(SHA256(x)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// Serialized public key for a secret, compressed or not.
pub fn pubkey_from_secret(secret: &SecretKey, compressed: bool) -> Vec<u8> {
    let secp = Secp256k1::signing_only();
    let pk = PublicKey::from_secret_key(&secp, secret);
    if compressed {
        pk.serialize().to_vec()
    } else {
        pk.serialize_uncompressed().to_vec()
    }
}

/// Standard pay-to-pubkey-hash scriptPubKey:
/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`
pub fn p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

/// Push a data item onto a script with the minimal encoding for our sizes
/// (signatures and public keys are always well under 76 bytes).
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() < 0x4c, "push_data is only used for sigs and pubkeys");
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::serialize::to_hex;

    #[test]
    fn hash160_matches_a_known_vector() {
        // HASH160("") = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        assert_eq!(to_hex(&hash160(b"")), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    #[test]
    fn p2pkh_script_has_the_standard_shape() {
        let s = p2pkh_script(&[0xab; 20]);
        assert_eq!(s.len(), 25);
        assert_eq!(s[0], 0x76); // OP_DUP
        assert_eq!(s[1], 0xa9); // OP_HASH160
        assert_eq!(s[2], 0x14); // 20-byte push
        assert_eq!(s[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(s[24], 0xac); // OP_CHECKSIG
        assert_eq!(&s[3..23], &[0xab; 20]);
    }

    #[test]
    fn compressed_and_uncompressed_pubkeys_have_the_right_form() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let c = pubkey_from_secret(&secret, true);
        let u = pubkey_from_secret(&secret, false);
        assert_eq!(c.len(), 33);
        assert!(c[0] == 0x02 || c[0] == 0x03);
        assert_eq!(u.len(), 65);
        assert_eq!(u[0], 0x04);
        // both encode the same point, so the X coordinate matches
        assert_eq!(&c[1..33], &u[1..33]);
    }

    #[test]
    fn push_data_prefixes_the_length() {
        let mut s = Vec::new();
        push_data(&mut s, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(s, vec![0x03, 0xaa, 0xbb, 0xcc]);
    }
}
