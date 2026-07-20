//! The registry of connected devices and the coins the relay watches for them.
//!
//! One hard rule: **addresses only, never keys**. A registration that carries
//! anything key-shaped is rejected outright, so a bug or a malicious client can
//! never trick the relay into holding key material it should never see.

use crate::protocol::Registration;
use lovenode_core::StakeCandidate;
use std::collections::HashMap;

/// A registered device: its token, the addresses it asked us to watch, and the
/// eligible coins we last found for it.
#[derive(Clone, Debug, Default)]
pub struct Device {
    pub token: String,
    pub addresses: Vec<String>,
    pub coins: Vec<StakeCandidate>,
}

/// Maximum addresses a single device may register — a bound so one client cannot
/// make the per-block scan arbitrarily expensive on the shared node.
pub const MAX_ADDRESSES_PER_DEVICE: usize = 64;

/// Validate a registration before accepting it.
///
/// Rejects empty and oversized address sets, and — the point of this function —
/// anything that looks like a private key or extended key. Divi WIF keys begin
/// with a small set of prefixes and are ~52 chars; xprv-style keys are longer
/// still. A public address is far shorter. We reject on length and known key
/// prefixes rather than trying to positively validate an address here.
pub fn validate_registration(reg: &Registration) -> Result<(), String> {
    if reg.device_token.trim().is_empty() {
        return Err("registration has no device token".into());
    }
    if reg.addresses.is_empty() {
        return Err("registration watches no addresses".into());
    }
    if reg.addresses.len() > MAX_ADDRESSES_PER_DEVICE {
        return Err(format!(
            "registration lists {} addresses, over the {MAX_ADDRESSES_PER_DEVICE} limit",
            reg.addresses.len()
        ));
    }
    for a in &reg.addresses {
        if looks_like_key_material(a) {
            return Err(
                "registration contains something that looks like a private key; the relay \
                 must only ever be given public addresses"
                    .into(),
            );
        }
        // A Divi base58 address is ~34 chars; reject the obviously-wrong.
        let len = a.trim().len();
        if !(20..=64).contains(&len) {
            return Err(format!("'{a}' is not a plausible address"));
        }
    }
    Ok(())
}

/// Heuristic: does this string look like a secret rather than an address?
fn looks_like_key_material(s: &str) -> bool {
    let t = s.trim();
    // Divi mainnet WIF keys start with 'Y' (compressed) and are ~52 chars;
    // extended private keys are ~111 chars. Public addresses are ~34 and start
    // with 'D'. Anything long, or with an obvious key prefix, is refused.
    t.len() >= 50
        || t.starts_with("xprv")
        || t.starts_with("tprv")
        || t.to_ascii_lowercase().contains("private")
}

/// The set of registered devices.
#[derive(Default)]
pub struct Registry {
    devices: HashMap<String, Device>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept (or update) a registration. Returns the stored device.
    pub fn register(&mut self, reg: Registration) -> Result<&Device, String> {
        validate_registration(&reg)?;
        let token = reg.device_token.clone();
        self.devices.insert(
            token.clone(),
            Device { token: token.clone(), addresses: reg.addresses, coins: Vec::new() },
        );
        Ok(self.devices.get(&token).expect("just inserted"))
    }

    pub fn remove(&mut self, token: &str) {
        self.devices.remove(token);
    }

    pub fn get(&self, token: &str) -> Option<&Device> {
        self.devices.get(token)
    }

    /// Replace the eligible-coin list for a device (called after a chain scan).
    pub fn set_coins(&mut self, token: &str, coins: Vec<StakeCandidate>) {
        if let Some(d) = self.devices.get_mut(token) {
            d.coins = coins;
        }
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Every address any device watches, deduplicated — one query covers all.
    pub fn all_addresses(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        for d in self.devices.values() {
            for a in &d.addresses {
                seen.insert(a.clone());
            }
        }
        seen.into_iter().collect()
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(token: &str, addrs: &[&str]) -> Registration {
        Registration {
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
            device_token: token.into(),
        }
    }

    const ADDR: &str = "DTaddZU8Xy1234567890abcdefghij"; // ~30 chars, address-shaped

    #[test]
    fn accepts_a_normal_registration() {
        let mut r = Registry::new();
        assert!(r.register(reg("dev1", &[ADDR])).is_ok());
        assert_eq!(r.len(), 1);
        assert_eq!(r.all_addresses(), vec![ADDR.to_string()]);
    }

    #[test]
    fn refuses_anything_that_looks_like_a_private_key() {
        let mut r = Registry::new();
        // a WIF-length secret
        let wif = "YU8mNq2kProper52CharSecretKeyValueGoesHere0123456789";
        assert!(r.register(reg("dev", &[wif])).is_err(), "must reject a WIF");
        // an extended private key
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert!(r.register(reg("dev", &[xprv])).is_err(), "must reject an xprv");
        // the word 'private' anywhere
        assert!(r.register(reg("dev", &["my private thing here 123456"])).is_err());
    }

    #[test]
    fn bounds_the_address_count_and_rejects_empties() {
        let mut r = Registry::new();
        assert!(r.register(reg("dev", &[])).is_err(), "empty address set");
        assert!(r.register(reg("", &[ADDR])).is_err(), "empty token");

        let many: Vec<String> =
            (0..MAX_ADDRESSES_PER_DEVICE + 1).map(|i| format!("{ADDR}{i:03}")).collect();
        let too_many = Registration { addresses: many, device_token: "dev".into() };
        assert!(r.register(too_many).is_err(), "over the per-device limit");
    }

    #[test]
    fn all_addresses_deduplicates_across_devices() {
        let mut r = Registry::new();
        let a2 = "DSecondAddr234567890abcdefghij";
        r.register(reg("dev1", &[ADDR, a2])).unwrap();
        r.register(reg("dev2", &[ADDR])).unwrap(); // shares ADDR
        assert_eq!(r.all_addresses().len(), 2, "the shared address counts once");
    }

    #[test]
    fn re_registering_replaces_and_coins_can_be_updated() {
        let mut r = Registry::new();
        r.register(reg("dev", &[ADDR])).unwrap();
        r.set_coins("dev", vec![StakeCandidate {
            prevout_hash: [1u8; 32],
            prevout_n: 0,
            value_sats: 100,
            coinstake_start_time: 1,
        }]);
        assert_eq!(r.get("dev").unwrap().coins.len(), 1);
        // re-registering resets the device
        r.register(reg("dev", &[ADDR])).unwrap();
        assert_eq!(r.get("dev").unwrap().coins.len(), 0);
        assert_eq!(r.len(), 1, "same token updates in place");
    }
}
