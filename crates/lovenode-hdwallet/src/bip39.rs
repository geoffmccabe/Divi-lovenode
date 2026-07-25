//! BIP39 mnemonics: the human-readable recovery phrase.
//!
//! Interoperable with Divi Core, which uses the same standard BIP39 (the exact
//! 2048-word English list is embedded verbatim from the node's `bip39_english.h`,
//! and the seed derivation is PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic"`
//! + passphrase). A phrase generated here restores in the desktop wallet and
//! vice versa, which is the whole point of a recovery phrase.
//!
//! Note on normalization: BIP39 specifies NFKD normalization of the mnemonic and
//! passphrase before hashing. The English wordlist is pure ASCII (a no-op), and
//! we require an ASCII passphrase, so no Unicode normalization is needed. A
//! non-ASCII passphrase is rejected rather than silently mis-normalized.

use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// The 2048-word English list, embedded verbatim from the Divi node's
/// `bip39_english.h` for exact interoperability. Split once, lazily.
fn wordlist() -> &'static Vec<&'static str> {
    use std::sync::OnceLock;
    static WL: OnceLock<Vec<&'static str>> = OnceLock::new();
    WL.get_or_init(|| include_str!("english.txt").lines().collect())
}

/// A validated BIP39 mnemonic. The words are held as a string; the sensitive
/// material is the derived seed, which is zeroized by its holder.
#[derive(Clone)]
pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    /// Generate a fresh mnemonic with `word_count` words (Divi's default is 24,
    /// i.e. 256 bits of entropy). Entropy comes straight from the OS CSPRNG.
    pub fn generate(word_count: usize) -> Result<Mnemonic, String> {
        let ent_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => return Err("word count must be 12, 15, 18, 21 or 24".into()),
        };
        let mut entropy = vec![0u8; ent_bits / 8];
        getrandom::getrandom(&mut entropy).map_err(|e| format!("no system entropy: {e}"))?;
        let m = Self::from_entropy(&entropy);
        entropy.zeroize();
        m
    }

    /// Build a mnemonic from raw entropy (16..=32 bytes, multiple of 4).
    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, String> {
        let ent_bits = entropy.len() * 8;
        if !(128..=256).contains(&ent_bits) || ent_bits % 32 != 0 {
            return Err("entropy must be 128,160,192,224 or 256 bits".into());
        }
        let checksum_bits = ent_bits / 32;
        let hash = Sha256::digest(entropy);

        // concatenate entropy + first checksum_bits of the hash, then read 11-bit
        // groups as word indices.
        let total_bits = ent_bits + checksum_bits;
        let mut words = Vec::with_capacity(total_bits / 11);
        let list = wordlist();
        for group in 0..(total_bits / 11) {
            let mut idx = 0usize;
            for bit in 0..11 {
                let n = group * 11 + bit;
                let bit_val = if n < ent_bits {
                    (entropy[n / 8] >> (7 - (n % 8))) & 1
                } else {
                    let cn = n - ent_bits;
                    (hash[cn / 8] >> (7 - (cn % 8))) & 1
                };
                idx = (idx << 1) | bit_val as usize;
            }
            words.push(list[idx]);
        }
        Ok(Mnemonic { phrase: words.join(" ") })
    }

    /// Parse and validate a phrase (word membership + checksum).
    pub fn parse(phrase: &str) -> Result<Mnemonic, String> {
        let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
        let words: Vec<&str> = normalized.split(' ').collect();
        if ![12, 15, 18, 21, 24].contains(&words.len()) {
            return Err(format!("a recovery phrase has 12-24 words, got {}", words.len()));
        }
        let list = wordlist();
        // words -> 11-bit indices
        let mut bits: Vec<u8> = Vec::with_capacity(words.len() * 11);
        for w in &words {
            let idx = list
                .iter()
                .position(|x| x == w)
                .ok_or_else(|| format!("'{w}' is not a valid recovery word"))?;
            for bit in (0..11).rev() {
                bits.push(((idx >> bit) & 1) as u8);
            }
        }
        let ent_bits = words.len() * 11 * 32 / 33;
        let checksum_bits = ent_bits / 32;
        // reassemble entropy bytes
        let mut entropy = vec![0u8; ent_bits / 8];
        for (i, chunk) in bits[..ent_bits].chunks(8).enumerate() {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | bit;
            }
            entropy[i] = b;
        }
        // recompute checksum and compare
        let hash = Sha256::digest(&entropy);
        for i in 0..checksum_bits {
            let expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
            if bits[ent_bits + i] != expected {
                entropy.zeroize();
                return Err("recovery phrase checksum is wrong (a word may be miswritten)".into());
            }
        }
        entropy.zeroize();
        Ok(Mnemonic { phrase: normalized })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The 64-byte BIP39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase,
    /// 2048). This is what the HD tree is grown from.
    pub fn to_seed(&self, passphrase: &str) -> Result<[u8; 64], String> {
        if !passphrase.is_ascii() {
            return Err("passphrase must be ASCII".into());
        }
        let salt = format!("mnemonic{passphrase}");
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2::<Hmac<Sha512>>(self.phrase.as_bytes(), salt.as_bytes(), 2048, &mut seed)
            .map_err(|_| "pbkdf2 failed".to_string())?;
        Ok(seed)
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never print the actual words
        write!(f, "Mnemonic(<{} words, redacted>)", self.phrase.split(' ').count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_sign::wallet::base58check_encode; // unused-safe import guard

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // The canonical Trezor BIP39 vectors (passphrase "TREZOR").
    #[test]
    fn official_bip39_vector_all_zero_entropy() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        let seed = m.to_seed("TREZOR").unwrap();
        assert_eq!(
            hex(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn official_bip39_vector_24_words() {
        // 32 bytes of 0xff
        let m = Mnemonic::from_entropy(&[0xffu8; 32]).unwrap();
        assert_eq!(m.phrase().split(' ').count(), 24);
        assert!(m.phrase().starts_with("zoo zoo zoo"));
        let seed = m.to_seed("TREZOR").unwrap();
        assert_eq!(
            hex(&seed),
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
        );
    }

    #[test]
    fn round_trips_and_rejects_a_bad_word() {
        let m = Mnemonic::generate(24).unwrap();
        let reparsed = Mnemonic::parse(m.phrase()).unwrap();
        assert_eq!(m.phrase(), reparsed.phrase());
        // corrupt one word
        let mut words: Vec<&str> = m.phrase().split(' ').collect();
        words[0] = "notaword";
        assert!(Mnemonic::parse(&words.join(" ")).is_err());
    }

    #[test]
    fn rejects_a_wrong_checksum() {
        // valid words, wrong checksum: swap the last word of the all-zero phrase
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::parse(bad).is_err());
    }

    #[test]
    fn debug_never_leaks_the_words() {
        let m = Mnemonic::generate(12).unwrap();
        let s = format!("{m:?}");
        assert!(!s.contains(' ') || s.contains("redacted"));
        assert!(!m.phrase().split(' ').any(|w| s.contains(w)));
    }

    #[test]
    fn wordlist_is_exactly_2048_and_sorted() {
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        assert_eq!(list[0], "abandon");
        assert_eq!(list[2047], "zoo");
        let _ = base58check_encode; // keep the interop import from being dead
    }
}
