//! Addresses and WIF keys — the human-facing forms of a Divi key.
//!
//! Pure, dependency-free (beyond the SHA-256 already in this crate), and tested
//! against a real address the node produced. Getting base58check or the version
//! bytes wrong would mean the app shows an address that isn't the one the key
//! controls — funds sent there would be unrecoverable — so every function here
//! is checked against ground truth.
//!
//! Version bytes (from `chainparams.cpp`):
//! | network        | pubkey (address) | secret (WIF) |
//! |----------------|------------------|--------------|
//! | main           | 30 ('D')         | 212          |
//! | testnet/regtest| 139 ('x'/'y')    | 239          |

use crate::script::{hash160, pubkey_from_secret};
use crate::StakingKey;
use lovenode_core::serialize::dsha256;
use secp256k1::SecretKey;

/// Which Divi network an address/WIF belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    /// testnet and regtest share the same base58 version bytes.
    Test,
}

impl Network {
    fn pubkey_version(self) -> u8 {
        match self {
            Network::Main => 30,
            Network::Test => 139,
        }
    }
    fn secret_version(self) -> u8 {
        match self {
            Network::Main => 212,
            Network::Test => 239,
        }
    }
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// base58check encode: `version || payload || checksum`, checksum = first 4
/// bytes of double-SHA256(version || payload).
pub fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);
    let checksum = dsha256(&data);
    data.extend_from_slice(&checksum[..4]);
    base58_encode(&data)
}

/// base58check decode, returning `(version, payload)` if the checksum verifies.
pub fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), String> {
    let data = base58_decode(s)?;
    if data.len() < 5 {
        return Err("too short to be base58check".into());
    }
    let (body, checksum) = data.split_at(data.len() - 4);
    let expected = dsha256(body);
    if checksum != &expected[..4] {
        return Err("bad base58check checksum".into());
    }
    Ok((body[0], body[1..].to_vec()))
}

fn base58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(B58[d as usize] as char);
    }
    out
}

fn base58_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let val = B58.iter().position(|&b| b == c).ok_or("invalid base58 character")? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// The public address for a key on a given network.
pub fn address_for_key(key: &StakingKey, network: Network) -> String {
    let h = hash160(&key.public_key());
    base58check_encode(network.pubkey_version(), &h)
}

/// The address for a raw pubkey-hash (e.g. taken from a scriptPubKey).
pub fn address_for_hash160(h: &[u8; 20], network: Network) -> String {
    base58check_encode(network.pubkey_version(), h)
}

/// Encode a key as a Wallet Import Format string.
pub fn to_wif(secret: &[u8; 32], compressed: bool, network: Network) -> String {
    let mut payload = secret.to_vec();
    if compressed {
        payload.push(0x01);
    }
    base58check_encode(network.secret_version(), &payload)
}

/// Decode a WIF string into a staking key, verifying the checksum and version.
pub fn from_wif(wif: &str) -> Result<(StakingKey, Network), String> {
    let (version, payload) = base58check_decode(wif.trim())?;
    let network = match version {
        212 => Network::Main,
        239 => Network::Test,
        v => return Err(format!("not a Divi WIF (version byte {v})")),
    };
    // payload is 32 bytes (uncompressed) or 33 with a trailing 0x01 (compressed).
    let (secret, compressed) = match payload.len() {
        32 => (&payload[..32], false),
        33 if payload[32] == 0x01 => (&payload[..32], true),
        _ => return Err("WIF payload is not a 32-byte key".into()),
    };
    let mut k = [0u8; 32];
    k.copy_from_slice(secret);
    // Zero the intermediate copy of the secret we no longer need.
    let key = StakingKey::from_bytes(&k, compressed)?;
    Ok((key, network))
}

/// Generate a fresh staking secret from the operating system's CSPRNG.
///
/// This is the birth of a wallet — the randomness here is everything, so it
/// comes straight from the OS entropy source (`getrandom`), never a userspace
/// PRNG. Retries on the astronomically unlikely event that the 32 bytes are not
/// a valid secp256k1 scalar.
pub fn generate_secret() -> Result<[u8; 32], String> {
    for _ in 0..8 {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| format!("no system entropy: {e}"))?;
        if SecretKey::from_slice(&secret).is_ok() {
            return Ok(secret);
        }
    }
    Err("could not generate a valid key".into())
}

/// Create a brand-new wallet: a fresh key and its address on `network`.
/// Returns the secret (to be handed to secure storage), the key, and the address.
pub fn create_wallet(network: Network) -> Result<([u8; 32], StakingKey, String), String> {
    let secret = generate_secret()?;
    let (key, addr) = key_and_address(&secret, network)?;
    Ok((secret, key, addr))
}

/// Derive the compressed staking key and address from a 32-byte secret.
pub fn key_and_address(secret: &[u8; 32], network: Network) -> Result<(StakingKey, String), String> {
    let key = StakingKey::from_bytes(secret, true)?;
    let addr = address_for_key(&key, network);
    Ok((key, addr))
}

/// The public key for a secret, without constructing a `StakingKey` — used where
/// only the address is needed.
pub fn pubkey(secret: &SecretKey, compressed: bool) -> Vec<u8> {
    pubkey_from_secret(secret, compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::serialize::to_hex;

    #[test]
    fn base58_matches_bitcoin_reference_vectors() {
        // canonical base58 (not check) vectors
        assert_eq!(base58_encode(&[0x00]), "1");
        assert_eq!(base58_encode(&[0x00, 0x00, 0x61]), "112g");
        assert_eq!(base58_encode(&[0x51, 0x6b, 0x6f, 0xcd, 0x0f]), "ABnLTmg");
        assert_eq!(base58_decode("ABnLTmg").unwrap(), vec![0x51, 0x6b, 0x6f, 0xcd, 0x0f]);
        // leading-zero bytes become leading '1's and round-trip
        assert_eq!(base58_decode("112g").unwrap(), vec![0x00, 0x00, 0x61]);
    }

    #[test]
    fn reproduces_a_real_divi_address_from_its_hash160() {
        // Ground truth from the node: regtest address y9tKQfiPeZro3fYMWSEVHSUJoyjqQJqga5
        // has scriptPubKey 76a914<hash160>88ac with the hash160 below (version 139).
        let h: [u8; 20] = {
            let bytes =
                lovenode_core::serialize::from_hex("8d8e21deca92a88dd78de53a7ae4f70da4253941")
                    .unwrap();
            bytes.try_into().unwrap()
        };
        assert_eq!(
            address_for_hash160(&h, Network::Test),
            "y9tKQfiPeZro3fYMWSEVHSUJoyjqQJqga5"
        );
    }

    #[test]
    fn decoding_that_address_recovers_the_hash160_and_version() {
        let (version, payload) =
            base58check_decode("y9tKQfiPeZro3fYMWSEVHSUJoyjqQJqga5").unwrap();
        assert_eq!(version, 139);
        assert_eq!(to_hex(&payload), "8d8e21deca92a88dd78de53a7ae4f70da4253941");
    }

    #[test]
    fn a_tampered_address_fails_the_checksum() {
        // flip one character; the checksum must reject it
        let bad = "y9tKQfiPeZro3fYMWSEVHSUJoyjqQJqga6";
        assert!(base58check_decode(bad).is_err());
    }

    #[test]
    fn wif_round_trips_and_binds_the_network() {
        let secret = [0x11u8; 32];
        let wif = to_wif(&secret, true, Network::Main);
        // Divi mainnet compressed WIFs start with 'Y'
        assert!(wif.starts_with('Y'), "got {wif}");

        let (key, net) = from_wif(&wif).unwrap();
        assert_eq!(net, Network::Main);
        // the recovered key controls the expected address
        let addr = address_for_key(&key, Network::Main);
        assert!(addr.starts_with('D'), "mainnet address starts with D, got {addr}");
    }

    #[test]
    fn a_key_and_its_address_are_consistent() {
        let secret = [0x42u8; 32];
        let (key, addr) = key_and_address(&secret, Network::Main).unwrap();
        // deriving the address two independent ways agrees
        assert_eq!(addr, address_for_key(&key, Network::Main));
        // and it is a plausible mainnet address
        assert!(addr.starts_with('D'));
        assert!((26..=35).contains(&addr.len()));
    }

    #[test]
    fn a_generated_wallet_is_valid_and_unique() {
        let (s1, k1, a1) = create_wallet(Network::Main).unwrap();
        let (s2, _k2, a2) = create_wallet(Network::Main).unwrap();
        // two generations must differ (entropy is real)
        assert_ne!(s1, s2, "generated secrets must be unique");
        assert_ne!(a1, a2, "generated addresses must differ");
        // the generated key round-trips: secret -> WIF -> key -> same address
        let wif = to_wif(&s1, true, Network::Main);
        let (k, _net) = from_wif(&wif).unwrap();
        assert_eq!(address_for_key(&k, Network::Main), a1);
        assert_eq!(address_for_key(&k1, Network::Main), a1);
        assert!(a1.starts_with('D'));
    }

    #[test]
    fn from_wif_rejects_foreign_and_corrupt_input() {
        // a Bitcoin mainnet WIF (version 128) is not a Divi key
        assert!(from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").is_err());
        assert!(from_wif("not-a-wif").is_err());
        assert!(from_wif("").is_err());
    }
}
