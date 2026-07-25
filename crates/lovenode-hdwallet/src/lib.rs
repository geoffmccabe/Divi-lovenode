//! # lovenode-hdwallet — recovery phrase + HD key derivation
//!
//! A Divi HD wallet from a BIP39 recovery phrase, **interoperable with Divi
//! Core**: same wordlist, same seed derivation, same BIP44 path
//! `m/44'/301'/account'/change/index` (coin type 301 on mainnet, 1 on
//! testnet/regtest). A phrase created here restores in the desktop wallet, and a
//! desktop phrase restores here — the only honest meaning of "recovery phrase".
//!
//! The wallet holds the seed (sensitive) and derives keys on demand. It exposes
//! the same [`lovenode_sign::StakingKey`] the rest of the app already uses, so
//! staking, signing and address code are unchanged — only *where the key comes
//! from* moves from "a single random key" to "derived from a phrase".

pub mod bip32;
pub mod bip39;

use bip32::{hardened, ExtKey};
pub use bip39::Mnemonic;
use lovenode_sign::wallet::{address_for_key, Network};
use lovenode_sign::StakingKey;
use zeroize::Zeroize;

/// Divi's SLIP-44 coin type per network (from the node's `chainparams.cpp`).
fn coin_type(network: Network) -> u32 {
    match network {
        Network::Main => 301,
        Network::Test => 1,
    }
}

/// An HD wallet: a seed plus the network it addresses.
pub struct HdWallet {
    seed: [u8; 64],
    network: Network,
}

impl HdWallet {
    /// Create a brand-new wallet: generate a 12-word phrase and return both the
    /// wallet and the phrase to show the user ONCE for backup.
    ///
    /// 12 words (128 bits of entropy) is the chosen default for LoveNode -- easier
    /// to write down and still far beyond any brute-force reach. Interop is
    /// unaffected: restoring accepts any valid length, so a 12-word LoveNode phrase
    /// still restores in the desktop wallet, and a 24-word desktop phrase still
    /// restores here.
    pub fn generate(network: Network) -> Result<(HdWallet, Mnemonic), String> {
        let mnemonic = Mnemonic::generate(12)?;
        let wallet = Self::from_mnemonic(&mnemonic, "", network)?;
        Ok((wallet, mnemonic))
    }

    /// Restore a wallet from a phrase (and optional passphrase).
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, network: Network) -> Result<HdWallet, String> {
        let seed = mnemonic.to_seed(passphrase)?;
        Ok(HdWallet { seed, network })
    }

    /// Restore directly from a raw 64-byte seed (e.g. reloaded from the keystore).
    pub fn from_seed(seed: [u8; 64], network: Network) -> HdWallet {
        HdWallet { seed, network }
    }

    /// The raw seed, to hand to secure storage. Caller must zeroize its copy.
    pub fn seed(&self) -> [u8; 64] {
        self.seed
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Derive the key at `m/44'/301'/account'/change/index`.
    fn derive(&self, account: u32, change: u32, index: u32) -> Result<StakingKey, String> {
        let master = ExtKey::master(&self.seed)?;
        let path = [
            hardened(44),
            hardened(coin_type(self.network)),
            hardened(account),
            change,
            index,
        ];
        let node = master.derive_path(&path)?;
        // Divi keys are compressed.
        StakingKey::from_bytes(&node.secret.secret_bytes(), true)
    }

    /// The `index`-th receiving key (account 0, external chain 0). This is what
    /// funds arrive on and what stakes.
    pub fn receiving_key(&self, index: u32) -> Result<StakingKey, String> {
        self.derive(0, 0, index)
    }

    /// The `index`-th receiving address.
    pub fn receiving_address(&self, index: u32) -> Result<String, String> {
        Ok(address_for_key(&self.receiving_key(index)?, self.network))
    }

    /// The first `n` receiving addresses — what a fresh wallet registers with the
    /// relay and shows the user.
    pub fn receiving_addresses(&self, n: u32) -> Result<Vec<String>, String> {
        (0..n).map(|i| self.receiving_address(i)).collect()
    }

    /// The `index`-th change key (account 0, internal chain 1), for send change
    /// outputs.
    pub fn change_key(&self, index: u32) -> Result<StakingKey, String> {
        self.derive(0, 1, index)
    }
}

impl Drop for HdWallet {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl std::fmt::Debug for HdWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HdWallet(network={:?}, seed=<redacted>)", self.network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_restore_round_trip_gives_identical_addresses() {
        let (w1, phrase) = HdWallet::generate(Network::Main).unwrap();
        let w2 = HdWallet::from_mnemonic(&phrase, "", Network::Main).unwrap();
        // restoring the phrase reproduces the same wallet
        for i in 0..5 {
            assert_eq!(w1.receiving_address(i).unwrap(), w2.receiving_address(i).unwrap());
        }
        // addresses are mainnet and distinct per index
        let a0 = w1.receiving_address(0).unwrap();
        let a1 = w1.receiving_address(1).unwrap();
        assert!(a0.starts_with('D'));
        assert_ne!(a0, a1);
    }

    #[test]
    fn default_generation_is_12_words() {
        let (_w, phrase) = HdWallet::generate(Network::Main).unwrap();
        assert_eq!(phrase.phrase().split(' ').count(), 12, "LoveNode phrases are 12 words");
    }

    #[test]
    fn a_passphrase_changes_the_wallet() {
        let phrase = Mnemonic::generate(24).unwrap();
        let plain = HdWallet::from_mnemonic(&phrase, "", Network::Main).unwrap();
        let with_pass = HdWallet::from_mnemonic(&phrase, "extra", Network::Main).unwrap();
        assert_ne!(
            plain.receiving_address(0).unwrap(),
            with_pass.receiving_address(0).unwrap(),
            "the BIP39 passphrase must produce a different wallet"
        );
    }

    #[test]
    fn seed_round_trips_through_storage() {
        let (w, _) = HdWallet::generate(Network::Test).unwrap();
        let seed = w.seed();
        let reloaded = HdWallet::from_seed(seed, Network::Test);
        assert_eq!(w.receiving_address(0).unwrap(), reloaded.receiving_address(0).unwrap());
    }

    #[test]
    fn matches_the_real_divi_node_addresses() {
        // Ground truth: the Divi node was given this exact phrase (regtest,
        // coin type 1) and produced these addresses at m/44'/1'/0'/0/{1,2,3}.
        // Our derivation must reproduce them, or a recovery phrase would NOT
        // restore the same coins between LoveNode and the desktop wallet.
        let phrase =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let m = Mnemonic::parse(phrase).unwrap();
        let w = HdWallet::from_mnemonic(&m, "", Network::Test).unwrap();
        assert_eq!(w.receiving_address(1).unwrap(), "xwDDs9DzQ5YRzKTRts8yYKVEzAuUSpKWqz");
        assert_eq!(w.receiving_address(2).unwrap(), "yFjUKo2PLiA6bPqJuK4HFvjPMiS9zLD1MT");
        assert_eq!(w.receiving_address(3).unwrap(), "yCWpxjmxhy3byUEYSn6mo8JAEHdEBRcPGg");
    }

    #[test]
    fn mainnet_and_testnet_derive_different_coins() {
        let phrase = Mnemonic::generate(24).unwrap();
        let main = HdWallet::from_mnemonic(&phrase, "", Network::Main).unwrap();
        let test = HdWallet::from_mnemonic(&phrase, "", Network::Test).unwrap();
        // different coin_type in the path -> different keys
        assert_ne!(
            main.receiving_key(0).unwrap().public_key(),
            test.receiving_key(0).unwrap().public_key()
        );
    }
}
