//! # lovenode-keystore — where the wallet's seed lives
//!
//! The single most sensitive question in the whole app is *where the secret is
//! kept and who can use it*. Since the wallet became recovery-phrase based
//! ([`lovenode_hdwallet`]), the secret stored is the **64-byte BIP39 seed** the
//! whole key tree is derived from — not a single key. This crate makes that one
//! small, explicit contract ([`KeyStore`]) so the platform-specific secure
//! storage is the only thing that varies between desktop, Android and iOS.
//!
//! ## The contract
//!
//! - The seed is **generated or restored once** (from a 12-word phrase) and
//!   thereafter **never leaves** the secure store in plaintext. On Android that
//!   means the Android Keystore encrypts it at rest; on iOS, the Keychain /
//!   Secure Enclave. Those backends implement [`KeyStore`] with a thin FFI shim
//!   in the app shell — not here.
//! - This crate ships only an in-memory [`DevKeyStore`] for development and
//!   tests. It is **not** secure storage and says so loudly.
//!
//! ## Why the seed materialises in memory
//!
//! Divi block/transaction signing needs the secp256k1 secret in-process at the
//! instant of signing. So the honest contract is: the seed is *stored* in secure
//! hardware and *loaded* into memory (via [`load_wallet`]) to derive the key that
//! signs, then dropped/zeroized.

use lovenode_hdwallet::{HdWallet, Mnemonic};
use lovenode_sign::wallet::Network;
use zeroize::Zeroize;

/// How many receiving addresses to derive and cache when a wallet is set up —
/// the standard BIP44 gap limit. These are what the relay watches and what the
/// UI shows; they are public and safe to hold outside the secure element.
pub const GAP_LIMIT: u32 = 20;

/// Create a brand-new wallet: generate a 12-word phrase, store its seed, cache
/// the receiving addresses, and return the phrase to show the user ONCE for
/// backup. Refuses if a wallet already exists, so one is never silently
/// overwritten.
pub fn setup_new_wallet(ks: &dyn KeyStore, network: Network) -> Result<Mnemonic, String> {
    if ks.has_wallet() {
        return Err("a wallet already exists on this device".into());
    }
    let (wallet, mnemonic) = HdWallet::generate(network)?;
    stash(ks, &wallet)?;
    Ok(mnemonic)
}

/// Restore a wallet from a recovery phrase (and optional passphrase). Validates
/// the phrase, stores the seed, and caches the receiving addresses.
pub fn restore_from_phrase(
    ks: &dyn KeyStore,
    phrase: &str,
    passphrase: &str,
    network: Network,
) -> Result<(), String> {
    if ks.has_wallet() {
        return Err("a wallet already exists on this device".into());
    }
    let mnemonic = Mnemonic::parse(phrase)?;
    let wallet = HdWallet::from_mnemonic(&mnemonic, passphrase, network)?;
    stash(ks, &wallet)
}

/// Store a wallet's seed and cache its addresses, zeroizing the plaintext seed.
fn stash(ks: &dyn KeyStore, wallet: &HdWallet) -> Result<(), String> {
    let mut seed = wallet.seed();
    let stored = ks.store_seed(&seed);
    seed.zeroize();
    stored?;
    ks.set_addresses(wallet.receiving_addresses(GAP_LIMIT)?);
    Ok(())
}

/// Load the HD wallet from the stored seed, to derive keys and addresses. The
/// caller drops it as soon as it is done; the seed is zeroized on drop.
pub fn load_wallet(ks: &dyn KeyStore, network: Network) -> Result<HdWallet, String> {
    let mut seed = ks.load_seed()?;
    let wallet = HdWallet::from_seed(seed, network);
    seed.zeroize();
    Ok(wallet)
}

/// A place a wallet seed is stored. Implementations back onto platform secure
/// storage; this crate provides only a development stand-in.
pub trait KeyStore {
    /// True once a seed has been stored.
    fn has_wallet(&self) -> bool;

    /// Store the 64-byte BIP39 seed. Overwrites any existing seed, so callers
    /// must confirm with the user before replacing one.
    fn store_seed(&self, seed: &[u8; 64]) -> Result<(), String>;

    /// Load the seed. On a real backend this is the point at which the OS may
    /// require user presence (biometric / device unlock).
    fn load_seed(&self) -> Result<[u8; 64], String>;

    /// The cached receiving addresses, if present. `None` means "unlock to see".
    fn public_addresses(&self) -> Option<Vec<String>>;

    /// Cache the public receiving addresses (public data; safe outside the
    /// secure element so the UI can show them without unlocking).
    fn set_addresses(&self, addresses: Vec<String>);

    /// Permanently remove the seed. Irreversible; the UI must double-confirm.
    fn wipe(&self) -> Result<(), String>;
}

/// An in-memory keystore for development and tests. **NOT secure storage** — the
/// seed sits in ordinary process memory. A production build must replace this
/// with a platform backend (Android Keystore / iOS Keychain).
pub struct DevKeyStore {
    inner: std::sync::Mutex<Option<Stored>>,
}

struct Stored {
    seed: [u8; 64],
    addresses: Vec<String>,
}

impl Default for DevKeyStore {
    fn default() -> Self {
        Self { inner: std::sync::Mutex::new(None) }
    }
}

impl DevKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for DevKeyStore {
    fn has_wallet(&self) -> bool {
        self.inner.lock().expect("keystore lock").is_some()
    }

    fn store_seed(&self, seed: &[u8; 64]) -> Result<(), String> {
        let mut guard = self.inner.lock().expect("keystore lock");
        if let Some(mut old) = guard.take() {
            old.seed.zeroize(); // wipe any prior seed before overwriting
        }
        *guard = Some(Stored { seed: *seed, addresses: Vec::new() });
        Ok(())
    }

    fn load_seed(&self) -> Result<[u8; 64], String> {
        let guard = self.inner.lock().expect("keystore lock");
        let s = guard.as_ref().ok_or("no wallet has been set up yet")?;
        Ok(s.seed)
    }

    fn public_addresses(&self) -> Option<Vec<String>> {
        self.inner.lock().expect("keystore lock").as_ref().map(|s| s.addresses.clone())
    }

    fn set_addresses(&self, addresses: Vec<String>) {
        if let Some(s) = self.inner.lock().expect("keystore lock").as_mut() {
            s.addresses = addresses;
        }
    }

    fn wipe(&self) -> Result<(), String> {
        // zeroize the seed before dropping it
        if let Some(mut s) = self.inner.lock().expect("keystore lock").take() {
            s.seed.zeroize();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_sign::wallet::address_for_key;

    #[test]
    fn setup_creates_a_usable_wallet_and_shows_a_12_word_phrase() {
        let ks = DevKeyStore::new();
        assert!(!ks.has_wallet());
        let phrase = setup_new_wallet(&ks, Network::Main).unwrap();
        assert_eq!(phrase.phrase().split(' ').count(), 12);
        assert!(ks.has_wallet());
        // the cached addresses match what the seed derives
        let addrs = ks.public_addresses().unwrap();
        assert_eq!(addrs.len(), GAP_LIMIT as usize);
        assert!(addrs[0].starts_with('D'));
        let wallet = load_wallet(&ks, Network::Main).unwrap();
        assert_eq!(wallet.receiving_address(0).unwrap(), addrs[0]);
    }

    #[test]
    fn setup_refuses_to_overwrite_an_existing_wallet() {
        let ks = DevKeyStore::new();
        setup_new_wallet(&ks, Network::Main).unwrap();
        assert!(setup_new_wallet(&ks, Network::Main).is_err());
    }

    #[test]
    fn restore_from_phrase_recovers_the_same_addresses() {
        // set up a wallet, take its phrase, restore into a fresh keystore, and
        // confirm the receiving addresses are identical.
        let ks1 = DevKeyStore::new();
        let phrase = setup_new_wallet(&ks1, Network::Main).unwrap();
        let a1 = ks1.public_addresses().unwrap();

        let ks2 = DevKeyStore::new();
        restore_from_phrase(&ks2, phrase.phrase(), "", Network::Main).unwrap();
        let a2 = ks2.public_addresses().unwrap();
        assert_eq!(a1, a2, "the same phrase must recover the same addresses");
    }

    #[test]
    fn restore_rejects_a_bad_phrase() {
        let ks = DevKeyStore::new();
        assert!(restore_from_phrase(&ks, "not a real phrase at all nope", "", Network::Main).is_err());
        assert!(!ks.has_wallet());
    }

    #[test]
    fn load_before_setup_is_a_clear_error() {
        let ks = DevKeyStore::new();
        assert!(load_wallet(&ks, Network::Main).is_err());
    }

    #[test]
    fn wipe_removes_the_wallet() {
        let ks = DevKeyStore::new();
        setup_new_wallet(&ks, Network::Main).unwrap();
        ks.wipe().unwrap();
        assert!(!ks.has_wallet());
        assert!(load_wallet(&ks, Network::Main).is_err());
    }

    #[test]
    fn loaded_wallet_signs_for_a_derived_address() {
        let ks = DevKeyStore::new();
        setup_new_wallet(&ks, Network::Test).unwrap();
        let wallet = load_wallet(&ks, Network::Test).unwrap();
        let key = wallet.receiving_key(0).unwrap();
        // the derived key controls the first cached address
        assert_eq!(address_for_key(&key, Network::Test), ks.public_addresses().unwrap()[0]);
    }
}
