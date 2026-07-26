//! Detecting incoming payments so the relay can ping the receiver.
//!
//! Pure logic: given a transaction and the addresses a device asked us to watch,
//! find the outputs that pay it and whether the transaction is a Fast Send. The
//! enrichment that needs outside data — the sender's address (a node lookup), the
//! USD value (a price feed), and a human-readable name (the name registry) — is
//! injected by the caller, so this stays testable without any of them.

use lovenode_core::tx::Transaction;
use lovenode_sign::wallet::{base58check_decode, Network};
use std::collections::HashMap;

/// The Fast Send marker, carried in an OP_META output (`0x6a <len> DFS1`).
pub const FAST_MARKER: &[u8] = b"DFS1";

/// True if this transaction carries the Fast Send marker.
pub fn is_fast_send(tx: &Transaction) -> bool {
    tx.vout.iter().any(|o| {
        o.script_pubkey.first() == Some(&0x6a) && o.script_pubkey.ends_with(FAST_MARKER)
    })
}

/// One detected incoming payment: the receiving address and the amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub address: String,
    pub amount_sats: i64,
}

/// The P2PKH scriptPubKey for an address, or None if it doesn't parse for this
/// network. Used to match transaction outputs against watched addresses.
pub fn address_script(address: &str, network: Network) -> Option<Vec<u8>> {
    let (version, payload) = base58check_decode(address.trim()).ok()?;
    let expected = match network {
        Network::Main => 30,
        Network::Test => 139,
    };
    if version != expected || payload.len() != 20 {
        return None;
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&payload);
    Some(lovenode_sign::p2pkh_script(&h))
}

/// Find every output of `tx` that pays one of `watched` addresses. Returns the
/// receiving address and amount for each — so a device is told only about coins
/// landing on ITS OWN addresses, never anyone else's.
pub fn payments_to(tx: &Transaction, watched: &[String], network: Network) -> Vec<Incoming> {
    // address -> its scriptPubKey, once
    let scripts: HashMap<Vec<u8>, &String> = watched
        .iter()
        .filter_map(|a| address_script(a, network).map(|s| (s, a)))
        .collect();

    tx.vout
        .iter()
        .filter_map(|o| {
            scripts
                .get(&o.script_pubkey)
                .map(|addr| Incoming { address: (*addr).clone(), amount_sats: o.value })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::tx::{OutPoint, Transaction, TxIn, TxOut};

    // build a tx paying `amount` to `addr`'s script, optionally with the fast marker
    fn tx_paying(addr: &str, amount: i64, fast: bool) -> Transaction {
        let mut vout = vec![TxOut {
            value: amount,
            script_pubkey: address_script(addr, Network::Test).unwrap(),
        }];
        if fast {
            let mut m = vec![0x6a, FAST_MARKER.len() as u8];
            m.extend_from_slice(FAST_MARKER);
            vout.push(TxOut { value: 0, script_pubkey: m });
        }
        Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint { hash: [0x11; 32], n: 0 },
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            vout,
            lock_time: 0,
        }
    }

    // a real regtest address (version 139)
    const MINE: &str = "y9tKQfiPeZro3fYMWSEVHSUJoyjqQJqga5";
    const OTHER: &str = "yFjUKo2PLiA6bPqJuK4HFvjPMiS9zLD1MT";

    #[test]
    fn detects_a_payment_to_a_watched_address() {
        let tx = tx_paying(MINE, 100_00000000, false);
        let found = payments_to(&tx, &[MINE.to_string()], Network::Test);
        assert_eq!(found, vec![Incoming { address: MINE.into(), amount_sats: 100_00000000 }]);
        assert!(!is_fast_send(&tx));
    }

    #[test]
    fn recognises_a_fast_send() {
        let tx = tx_paying(MINE, 50_00000000, true);
        assert!(is_fast_send(&tx));
        assert_eq!(payments_to(&tx, &[MINE.to_string()], Network::Test).len(), 1);
    }

    #[test]
    fn ignores_payments_to_addresses_we_do_not_watch() {
        // privacy: a device is never told about a payment to someone else's address
        let tx = tx_paying(OTHER, 100_00000000, true);
        let found = payments_to(&tx, &[MINE.to_string()], Network::Test);
        assert!(found.is_empty(), "must not report another address's payment");
    }

    #[test]
    fn a_bad_address_simply_matches_nothing() {
        let tx = tx_paying(MINE, 1, false);
        let found = payments_to(&tx, &["not-an-address".to_string()], Network::Test);
        assert!(found.is_empty());
    }
}
