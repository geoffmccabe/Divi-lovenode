//! BIP32 hierarchical key derivation — the tree grown from the BIP39 seed.
//!
//! Only what an HD wallet needs: a master key from the seed, and child
//! derivation (hardened and normal). Validated against the official BIP32 test
//! vectors, so the tree matches every other correct implementation, including
//! Divi Core's.

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// One node in the HD tree: a private key plus its chain code.
#[derive(Clone)]
pub struct ExtKey {
    pub secret: SecretKey,
    pub chain_code: [u8; 32],
}

impl ExtKey {
    /// The BIP32 master key from a seed: HMAC-SHA512("Bitcoin seed", seed); left
    /// 32 bytes are the key, right 32 the chain code.
    pub fn master(seed: &[u8]) -> Result<ExtKey, String> {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac key len");
        mac.update(seed);
        let i = mac.finalize().into_bytes();
        let secret = SecretKey::from_slice(&i[..32])
            .map_err(|_| "invalid master key from seed".to_string())?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(ExtKey { secret, chain_code })
    }

    /// Derive one child. `index` with the top bit set (>= 0x8000_0000) is
    /// hardened.
    pub fn derive_child(&self, index: u32) -> Result<ExtKey, String> {
        let secp = Secp256k1::new();
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key len");
        if index & 0x8000_0000 != 0 {
            // hardened: 0x00 || ser256(kpar) || ser32(i)
            mac.update(&[0u8]);
            mac.update(&self.secret.secret_bytes());
        } else {
            // normal: serP(point(kpar)) || ser32(i)
            let pk = PublicKey::from_secret_key(&secp, &self.secret);
            mac.update(&pk.serialize());
        }
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();

        // child key = (IL + kpar) mod n; child chain code = IR
        let il = Scalar::from_be_bytes(i[..32].try_into().unwrap())
            .map_err(|_| "derived tweak out of range (try next index)".to_string())?;
        let child_secret = self
            .secret
            .add_tweak(&il)
            .map_err(|_| "derived key invalid (try next index)".to_string())?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(ExtKey { secret: child_secret, chain_code })
    }

    /// Walk a path of indices from this key.
    pub fn derive_path(&self, path: &[u32]) -> Result<ExtKey, String> {
        let mut key = self.clone();
        for &idx in path {
            key = key.derive_child(idx)?;
        }
        Ok(key)
    }
}

impl Drop for ExtKey {
    fn drop(&mut self) {
        self.chain_code.zeroize();
        // SecretKey has its own zeroization on drop in secp256k1.
    }
}

impl std::fmt::Debug for ExtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtKey(<redacted>)")
    }
}

/// Mark an index hardened.
pub const fn hardened(i: u32) -> u32 {
    i | 0x8000_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // BIP32 official Test Vector 1, seed 000102...0f.
    #[test]
    fn bip32_vector1_master_and_children() {
        let seed = (0u8..=15).collect::<Vec<u8>>();
        let m = ExtKey::master(&seed).unwrap();
        // known master private key + chain code for this seed
        assert_eq!(
            hex(&m.secret.secret_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex(&m.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );

        // m/0' (hardened)
        let c = m.derive_child(hardened(0)).unwrap();
        assert_eq!(
            hex(&c.secret.secret_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );

        // m/0'/1
        let c2 = c.derive_child(1).unwrap();
        assert_eq!(
            hex(&c2.secret.secret_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn derive_path_matches_step_by_step() {
        let seed = (0u8..=15).collect::<Vec<u8>>();
        let m = ExtKey::master(&seed).unwrap();
        let stepwise = m.derive_child(hardened(0)).unwrap().derive_child(1).unwrap();
        let pathwise = m.derive_path(&[hardened(0), 1]).unwrap();
        assert_eq!(stepwise.secret.secret_bytes(), pathwise.secret.secret_bytes());
    }
}
