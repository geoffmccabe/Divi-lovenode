//! The Divi proof-of-stake win-check.
//!
//! This is a faithful port of `divi/src/ProofOfStakeCalculator.cpp`. It is the
//! whole reason a phone can stake: the check needs **no blockchain data and no
//! private key** — just a handful of small public values.
//!
//! Reference (Divi core):
//! ```text
//! CDataStream ss(SER_GETHASH, 0);
//! ss << stakeModifier << coinstakeStartTime << prevout.n << prevout.hash << hashproofTimestamp;
//! return Hash(ss.begin(), ss.end());
//! ```
//! and the target test:
//! ```text
//! coinAgeWeight = (uint256(nValueIn) * nTimeWeight) / COIN / 400;
//! target = coinAgeTarget; target.MultiplyBy(coinAgeWeight);   // false => always hit
//! return hashProofOfStake < target;
//! ```
//!
//! Any change here is consensus-critical: it must stay byte-identical to the
//! C++ implementation or every stake this software produces is invalid.

use crate::u256::U256;
use sha2::{Digest, Sha256};

/// Satoshis per DIVI (`COIN` in Divi core).
pub const COIN: i64 = 100_000_000;

/// `MAXIMUM_COIN_AGE_WEIGHT_FOR_STAKING` — one week minus one hour, in seconds.
/// Coin age stops accruing weight past this point.
pub const MAX_COIN_AGE_WEIGHT: i64 = 60 * 60 * 24 * 7 - 60 * 60; // 601_200

/// Everything needed to test one coin for a win. All public data.
#[derive(Clone, Debug)]
pub struct StakeCandidate {
    /// Transaction id of the coin being staked, in **internal byte order**
    /// (the raw 32 bytes — NOT the reversed hex an explorer shows).
    pub prevout_hash: [u8; 32],
    /// Output index of the coin being staked.
    pub prevout_n: u32,
    /// Value of the coin, in satoshis.
    pub value_sats: i64,
    /// Block time of the coin's first confirming block (`coinstakeStartTime`).
    pub coinstake_start_time: u32,
}

/// The network-side values, refreshed once per block.
#[derive(Clone, Copy, Debug)]
pub struct NetworkTip {
    /// The current stake modifier.
    pub stake_modifier: u64,
    /// Difficulty target in compact form (`nBits`).
    pub bits: u32,
}

/// Serialize exactly as `CDataStream(SER_GETHASH, 0) << ...` does, then
/// double-SHA256. 52 bytes total: 8 + 4 + 4 + 32 + 4.
pub fn stake_hash(
    stake_modifier: u64,
    coinstake_start_time: u32,
    prevout_n: u32,
    prevout_hash: &[u8; 32],
    hashproof_timestamp: u32,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&stake_modifier.to_le_bytes());
    buf.extend_from_slice(&coinstake_start_time.to_le_bytes());
    buf.extend_from_slice(&prevout_n.to_le_bytes());
    buf.extend_from_slice(prevout_hash);
    buf.extend_from_slice(&hashproof_timestamp.to_le_bytes());
    debug_assert_eq!(buf.len(), 52);

    let first = Sha256::digest(&buf);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Coin-age weight, capped at [`MAX_COIN_AGE_WEIGHT`]. Negative (timestamp
/// before the coin existed) clamps to zero, which can never hit a target.
pub fn coin_age_weight(hashproof_timestamp: u32, coinstake_start_time: u32) -> i64 {
    let elapsed = hashproof_timestamp as i64 - coinstake_start_time as i64;
    elapsed.clamp(0, MAX_COIN_AGE_WEIGHT)
}

/// `stakeTargetHit`: does this proof hash meet the weighted target?
///
/// Returns true when the target multiplication overflows, mirroring Divi's
/// behaviour on minimal-difficulty regtest (an unbounded target always hits).
pub fn target_hit(proof_hash: &[u8; 32], value_sats: i64, bits: u32, time_weight: i64) -> bool {
    if value_sats <= 0 || time_weight <= 0 {
        return false;
    }
    // (value * timeWeight) / COIN / 400 — done in i128 so it cannot overflow;
    // the result is bounded well below u64::MAX for any real Divi amount.
    let weight = (value_sats as i128 * time_weight as i128) / COIN as i128 / 400;
    if weight <= 0 {
        return false;
    }
    let Ok(weight_u64) = u64::try_from(weight) else {
        return true; // absurdly large weight => unbounded target => hit
    };

    let Some(base_target) = U256::set_compact(bits) else {
        return true; // exponent overflow => unbounded target
    };
    match base_target.checked_mul_u64(weight_u64) {
        // Overflow means the target exceeds 2^256, i.e. every hash is below it.
        None => true,
        Some(target) => U256::from_le_bytes(proof_hash) < target,
    }
}

/// Full win-check for one coin at one candidate timestamp.
/// Returns the proof hash when the coin wins, `None` otherwise.
pub fn check_win(
    tip: &NetworkTip,
    coin: &StakeCandidate,
    hashproof_timestamp: u32,
) -> Option<[u8; 32]> {
    let hash = stake_hash(
        tip.stake_modifier,
        coin.coinstake_start_time,
        coin.prevout_n,
        &coin.prevout_hash,
        hashproof_timestamp,
    );
    let weight = coin_age_weight(hashproof_timestamp, coin.coinstake_start_time);
    if target_hit(&hash, coin.value_sats, tip.bits, weight) {
        Some(hash)
    } else {
        None
    }
}

/// Sweep one coin across a window of candidate timestamps (inclusive).
/// This is the entire "am I winning?" search — a few dozen hashes per block.
pub fn search_window(
    tip: &NetworkTip,
    coin: &StakeCandidate,
    from_time: u32,
    to_time: u32,
) -> Option<(u32, [u8; 32])> {
    (from_time..=to_time).find_map(|t| check_win(tip, coin, t).map(|h| (t, h)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin() -> StakeCandidate {
        StakeCandidate {
            prevout_hash: [0xab; 32],
            prevout_n: 1,
            value_sats: 1_000 * COIN,
            coinstake_start_time: 1_700_000_000,
        }
    }

    #[test]
    fn stake_hash_is_52_bytes_of_input_double_sha256() {
        // Independently construct the expected preimage and digest.
        let mut expect = Vec::new();
        expect.extend_from_slice(&7u64.to_le_bytes());
        expect.extend_from_slice(&11u32.to_le_bytes());
        expect.extend_from_slice(&3u32.to_le_bytes());
        expect.extend_from_slice(&[0x5c; 32]);
        expect.extend_from_slice(&13u32.to_le_bytes());
        assert_eq!(expect.len(), 52, "kernel preimage must be exactly 52 bytes");
        let d1 = Sha256::digest(&expect);
        let d2 = Sha256::digest(d1);

        let got = stake_hash(7, 11, 3, &[0x5c; 32], 13);
        assert_eq!(&got[..], &d2[..]);
    }

    /// Vectors produced by a C++ oracle compiled against Divi's OWN
    /// `CDataStream` and `Hash` (libbitcoin_util + libbitcoin_crypto), running
    /// the function body copied verbatim from `ProofOfStakeCalculator.cpp`.
    /// The oracle also confirmed the serialized preimage is exactly 52 bytes.
    ///
    /// This is the go/no-go proof that the Rust port is byte-identical to the
    /// node. If any of these fail, every stake this software produces is
    /// invalid — do not ship. Regenerate with `stakehash_ref` (see PROTOCOL.md).
    #[test]
    fn matches_the_cpp_node_byte_for_byte() {
        fn hex(b: &[u8; 32]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        let counting: [u8; 32] = std::array::from_fn(|i| i as u8);

        // stake_hash(modifier, coinstake_start_time, prevout_n, prevout_hash, hashproof_timestamp)
        assert_eq!(
            hex(&stake_hash(7, 11, 3, &[0x5c; 32], 13)),
            "85b7d6edde91abc3a897595521ee02dd61ebf563ec0ca8368bedda9e57d4afb7"
        );
        assert_eq!(
            hex(&stake_hash(0x0123_4567_89ab_cdef, 1_700_000_000, 0, &[0x11; 32], 1_700_003_600)),
            "3422a499d35fc61045b70af32d052e29c5bc620d6ef1868950ae6e24d8bc9516"
        );
        assert_eq!(
            hex(&stake_hash(0, 0, 0, &[0x00; 32], 0)),
            "a2fcf96babc27f6c7f411942179ae4618f78c6e01c2d804e6995a1c22849152a"
        );
        assert_eq!(
            hex(&stake_hash(u64::MAX, u32::MAX, u32::MAX, &[0xff; 32], u32::MAX)),
            "c842d3ce49ec0f4adced46b2a0e8d876049cc3b8685682336346f7b6f361e506"
        );
        // byte-order canary: internal byte i == i, so any endianness slip shows
        assert_eq!(
            hex(&stake_hash(1, 4, 3, &counting, 2)),
            "b3db92f47773a8240ef17d55a0c3c6430dac3a0f41a42e9b7a81217dfa2b0dff"
        );
    }

    #[test]
    fn field_order_matters() {
        // Swapping any two fields must change the hash — guards against a
        // silently-reordered serialization, which would invalidate every stake.
        let base = stake_hash(1, 2, 3, &[0u8; 32], 4);
        assert_ne!(base, stake_hash(2, 1, 3, &[0u8; 32], 4));
        assert_ne!(base, stake_hash(1, 2, 4, &[0u8; 32], 3));
        assert_ne!(base, stake_hash(1, 3, 2, &[0u8; 32], 4));
    }

    #[test]
    fn coin_age_weight_caps_and_clamps() {
        assert_eq!(coin_age_weight(1_000, 400), 600);
        assert_eq!(coin_age_weight(u32::MAX, 0), MAX_COIN_AGE_WEIGHT);
        // timestamp before the coin existed cannot earn weight
        assert_eq!(coin_age_weight(100, 500), 0);
    }

    #[test]
    fn zero_weight_or_value_never_wins() {
        assert!(!target_hit(&[0u8; 32], 0, 0x1d00_ffff, 600));
        assert!(!target_hit(&[0u8; 32], 100 * COIN, 0x1d00_ffff, 0));
        // and a coin at its own start time has no age, so it cannot win
        let c = coin();
        let tip = NetworkTip { stake_modifier: 42, bits: 0x1d00_ffff };
        assert!(check_win(&tip, &c, c.coinstake_start_time).is_none());
    }

    #[test]
    fn easier_target_wins_more_often_than_harder_target() {
        let c = coin();
        let easy = NetworkTip { stake_modifier: 42, bits: 0x2100_ffff }; // huge target
        let hard = NetworkTip { stake_modifier: 42, bits: 0x0100_0001 }; // tiny target
        let start = c.coinstake_start_time + 3_600;
        let easy_hits = (start..start + 200)
            .filter(|t| check_win(&easy, &c, *t).is_some())
            .count();
        let hard_hits = (start..start + 200)
            .filter(|t| check_win(&hard, &c, *t).is_some())
            .count();
        assert!(easy_hits > hard_hits, "easy={easy_hits} hard={hard_hits}");
        assert_eq!(hard_hits, 0, "a near-zero target must never be hit");
    }

    #[test]
    fn more_stake_never_wins_less_often() {
        // Weight scales linearly with value, so a bigger coin hits a superset
        // of the timestamps a smaller coin hits (same hash, larger target).
        let tip = NetworkTip { stake_modifier: 99, bits: 0x1e00_ffff };
        let small = StakeCandidate { value_sats: 10 * COIN, ..coin() };
        let big = StakeCandidate { value_sats: 10_000 * COIN, ..coin() };
        let start = small.coinstake_start_time + 7_200;
        for t in start..start + 500 {
            if check_win(&tip, &small, t).is_some() {
                assert!(check_win(&tip, &big, t).is_some(), "big coin must also win at {t}");
            }
        }
    }

    #[test]
    fn search_window_finds_the_first_winning_timestamp() {
        let c = coin();
        let tip = NetworkTip { stake_modifier: 5, bits: 0x2100_ffff }; // very easy
        let start = c.coinstake_start_time + 3_600;
        let (t, hash) = search_window(&tip, &c, start, start + 100).expect("should win");
        assert!((start..=start + 100).contains(&t));
        assert_eq!(check_win(&tip, &c, t), Some(hash));
        // and it is genuinely the FIRST such timestamp
        for earlier in start..t {
            assert!(check_win(&tip, &c, earlier).is_none());
        }
    }
}
