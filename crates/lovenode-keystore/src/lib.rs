//! # lovenode-keystore — where the staking key lives
//!
//! The single most sensitive question in the whole app is *where the private key
//! is kept and who can use it*. This crate makes that one small, explicit
//! contract ([`KeyStore`]) rather than something smeared through the UI, so the
//! platform-specific secure storage is the only thing that varies between
//! desktop, Android and iOS.
//!
//! ## The contract
//!
//! - The key is **generated or imported once** and thereafter **never leaves**
//!   the secure store in plaintext. On Android that means the private key is
//!   held by the **Android Keystore**, hardware-backed where available; on iOS,
//!   the **Keychain / Secure Enclave**. Those backends implement [`KeyStore`]
//!   with a thin JNI / FFI shim in the app shell — not here.
//! - This crate ships only an in-memory [`DevKeyStore`] for development and
//!   tests. It is **not** secure storage and says so loudly; a real build must
//!   supply a platform backend.
//!
//! ## Why the key still materialises as a `StakingKey`
//!
//! Divi block signing needs the secp256k1 secret in-process at the instant of
//! signing (there is no "sign this on the secure element" path for arbitrary
//! block hashes today). So the honest contract is: the key is *stored* in secure
//! hardware and *loaded* into memory only to sign, then dropped. A future
//! improvement is to push the actual ECDSA into the secure element; the trait is
//! shaped to allow that later without changing callers.

use lovenode_sign::StakingKey;

/// A place a staking key is stored. Implementations back onto platform secure
/// storage; this crate provides only a development stand-in.
pub trait KeyStore {
    /// True once a key has been stored.
    fn has_key(&self) -> bool;

    /// Store a freshly generated or imported key. Overwrites any existing key,
    /// so callers must confirm with the user before replacing one.
    fn store(&self, secret: &[u8; 32], compressed: bool) -> Result<(), String>;

    /// Load the key for signing. On a real backend this is the point at which
    /// the OS may require user presence (biometric / device unlock).
    fn load(&self) -> Result<StakingKey, String>;

    /// The public address string(s) this key controls, if the store caches them
    /// so the UI can show them without unlocking. `None` means "unlock to see".
    fn public_addresses(&self) -> Option<Vec<String>>;

    /// Permanently remove the key. Irreversible; the UI must double-confirm.
    fn wipe(&self) -> Result<(), String>;
}

/// An in-memory keystore for development and tests. **NOT secure storage** — the
/// key sits in ordinary process memory. A production build must replace this
/// with a platform backend (Android Keystore / iOS Keychain).
pub struct DevKeyStore {
    inner: std::sync::Mutex<Option<Stored>>,
}

struct Stored {
    secret: [u8; 32],
    compressed: bool,
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

    /// Attach the public addresses for the stored key (the shell computes these
    /// from the node when the wallet is set up).
    pub fn set_addresses(&self, addresses: Vec<String>) {
        if let Some(s) = self.inner.lock().expect("keystore lock").as_mut() {
            s.addresses = addresses;
        }
    }
}

impl KeyStore for DevKeyStore {
    fn has_key(&self) -> bool {
        self.inner.lock().expect("keystore lock").is_some()
    }

    fn store(&self, secret: &[u8; 32], compressed: bool) -> Result<(), String> {
        // Validate the secret is a usable key before storing it.
        StakingKey::from_bytes(secret, compressed)?;
        *self.inner.lock().expect("keystore lock") =
            Some(Stored { secret: *secret, compressed, addresses: Vec::new() });
        Ok(())
    }

    fn load(&self) -> Result<StakingKey, String> {
        let guard = self.inner.lock().expect("keystore lock");
        let s = guard.as_ref().ok_or("no staking key has been set up yet")?;
        StakingKey::from_bytes(&s.secret, s.compressed)
    }

    fn public_addresses(&self) -> Option<Vec<String>> {
        self.inner
            .lock()
            .expect("keystore lock")
            .as_ref()
            .map(|s| s.addresses.clone())
    }

    fn wipe(&self) -> Result<(), String> {
        *self.inner.lock().expect("keystore lock") = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_loads_and_wipes() {
        let ks = DevKeyStore::new();
        assert!(!ks.has_key());

        ks.store(&[0x42; 32], true).unwrap();
        assert!(ks.has_key());

        // the loaded key round-trips to a usable signer
        let key = ks.load().unwrap();
        assert_eq!(key.public_key().len(), 33, "compressed pubkey");

        ks.set_addresses(vec!["DAddr".into()]);
        assert_eq!(ks.public_addresses().unwrap(), vec!["DAddr".to_string()]);

        ks.wipe().unwrap();
        assert!(!ks.has_key());
        assert!(ks.load().is_err(), "no key after wipe");
    }

    #[test]
    fn rejects_an_invalid_secret() {
        let ks = DevKeyStore::new();
        // all-zero secret is not a valid secp256k1 key
        assert!(ks.store(&[0u8; 32], true).is_err());
        assert!(!ks.has_key(), "nothing stored on a bad key");
    }

    #[test]
    fn loading_before_setup_is_a_clear_error_not_a_panic() {
        let ks = DevKeyStore::new();
        let err = ks.load().unwrap_err();
        assert!(err.contains("no staking key"), "got: {err}");
    }
}
