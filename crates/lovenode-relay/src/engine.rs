//! The search engine: for each new block, test every registered coin for a win.
//!
//! This is the work that would otherwise run on the phone. Doing it here is what
//! keeps phones cool and keeps the app inside Apple's and Google's rules, which
//! both permit crypto work performed **off device** while banning on-device
//! mining. The engine needs no private keys — the win-check is pure public math.

use crate::chain::StakingTip;
use crate::protocol::WinNotice;
use lovenode_core::{search_window, StakeCandidate};
use lovenode_rewards::{on_stake_win, AwardSink, AwardState, NfdAward, RewardPolicy, StakeWin};

/// A registered staker: who to notify, and which coins are theirs.
#[derive(Clone, Debug)]
pub struct Staker {
    pub device_token: String,
    pub payout_address: String,
    pub coins: Vec<StakeCandidate>,
}

/// A win found by the engine, ready to send to the owning device.
#[derive(Clone, Debug)]
pub struct FoundWin {
    pub device_token: String,
    pub notice: WinNotice,
    pub proof_hash: [u8; 32],
}

/// How far ahead of the tip we are willing to search for a winning timestamp.
/// Divi targets 60-second blocks; searching a slightly wider window costs
/// nothing (a few dozen hashes) and tolerates clock skew.
pub const DEFAULT_SEARCH_AHEAD_SECS: u32 = 90;

pub struct Engine {
    pub search_ahead_secs: u32,
}

impl Default for Engine {
    fn default() -> Self {
        Self { search_ahead_secs: DEFAULT_SEARCH_AHEAD_SECS }
    }
}

impl Engine {
    /// Search every staker's coins against the current tip.
    ///
    /// `now` is the current unix time; the window runs from `now` forward, so a
    /// win is always in the present or near future — never backdated.
    pub fn search(&self, tip: &StakingTip, stakers: &[Staker], now: u32) -> Vec<FoundWin> {
        let from = now.max(tip.tip_time.saturating_add(1));
        let to = from.saturating_add(self.search_ahead_secs);

        let mut wins = Vec::new();
        for staker in stakers {
            // Take the EARLIEST winning timestamp across all of this staker's
            // coins, not merely the first coin that wins somewhere in the window.
            // On a 60-second target, publishing seconds later than necessary is a
            // large chance of being beaten to the height -- pure lost earnings.
            let best = staker
                .coins
                .iter()
                .filter_map(|coin| {
                    search_window(&tip.tip, coin, from, to).map(|(ts, h)| (ts, h, coin))
                })
                .min_by_key(|(ts, _, _)| *ts);

            if let Some((ts, proof_hash, coin)) = best {
                {
                    wins.push(FoundWin {
                        device_token: staker.device_token.clone(),
                        proof_hash,
                        notice: WinNotice {
                            height: tip.height + 1,
                            prev_block_hash: display_hex(&tip.tip_hash),
                            bits: tip.tip.bits,
                            stake_modifier: tip.tip.stake_modifier,
                            prevout_txid: display_hex(&coin.prevout_hash),
                            prevout_n: coin.prevout_n,
                            value_sats: coin.value_sats,
                            coinstake_start_time: coin.coinstake_start_time,
                            hashproof_timestamp: ts,
                            mempool_txs_hex: Vec::new(),
                        },
                    });
                }
            }
        }
        wins
    }

    /// Called once a staked block is accepted: offer the win to the NFD hook.
    ///
    /// Award handling is intentionally downstream of block acceptance and can
    /// never affect whether a block is produced.
    pub fn award_for_accepted_block(
        &self,
        policy: &dyn RewardPolicy,
        sink: &dyn AwardSink,
        state: &AwardState,
        staker: &Staker,
        block_hash: [u8; 32],
        proof_hash: [u8; 32],
        height: u64,
        block_time: u32,
        stake_value_sats: i64,
    ) -> Option<NfdAward> {
        let win = StakeWin {
            block_height: height,
            block_hash,
            proof_hash,
            block_time,
            staker_address: staker.payout_address.clone(),
            stake_value_sats,
        };
        on_stake_win(policy, sink, &win, state)
    }
}

/// Internal byte order → the reversed hex form used in RPC and explorers.
pub fn display_hex(internal: &[u8; 32]) -> String {
    internal.iter().rev().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::hash_from_display_hex;
    use lovenode_core::{NetworkTip, COIN};
    use lovenode_rewards::{DiminishingPolicy, MemorySink, RollSource, PPM};

    fn tip(bits: u32) -> StakingTip {
        StakingTip {
            height: 1_000,
            tip_hash: [0x22; 32],
            tip_time: 1_700_000_000,
            tip: NetworkTip { stake_modifier: 777, bits },
        }
    }

    fn staker(value_sats: i64) -> Staker {
        Staker {
            device_token: "device-1".into(),
            payout_address: "DPayout".into(),
            coins: vec![StakeCandidate {
                prevout_hash: [0x33; 32],
                prevout_n: 2,
                value_sats,
                coinstake_start_time: 1_699_000_000, // well-aged
            }],
        }
    }

    #[test]
    fn hex_conversion_round_trips() {
        let internal = [0x9au8; 32];
        assert_eq!(hash_from_display_hex(&display_hex(&internal)).unwrap(), internal);
    }

    #[test]
    fn an_easy_target_produces_a_win_that_the_phone_can_verify() {
        let e = Engine::default();
        let wins = e.search(&tip(0x2100_ffff), &[staker(1_000 * COIN)], 1_700_000_100);
        assert_eq!(wins.len(), 1, "easy target should yield a win");
        // the notice must independently verify on the device
        assert!(wins[0].notice.verify_win().is_ok());
        assert_eq!(wins[0].notice.height, 1_001, "block builds on the tip");
    }

    #[test]
    fn a_hard_target_produces_no_wins() {
        let e = Engine::default();
        let wins = e.search(&tip(0x0100_0001), &[staker(1_000 * COIN)], 1_700_000_100);
        assert!(wins.is_empty());
    }

    #[test]
    fn wins_are_never_backdated_before_the_tip() {
        let e = Engine::default();
        let t = tip(0x2100_ffff);
        // even if "now" is behind the tip, the window starts after the tip
        let wins = e.search(&t, &[staker(1_000 * COIN)], 1_600_000_000);
        for w in &wins {
            assert!(w.notice.hashproof_timestamp > t.tip_time);
        }
    }

    #[test]
    fn each_staker_yields_at_most_one_win_per_block() {
        let e = Engine::default();
        let mut s = staker(1_000 * COIN);
        // give the staker several winning coins
        s.coins = (0..5)
            .map(|i| StakeCandidate { prevout_n: i, ..s.coins[0].clone() })
            .collect();
        let wins = e.search(&tip(0x2100_ffff), &[s], 1_700_000_100);
        assert_eq!(wins.len(), 1, "only one block can be staked per height");
    }

    #[test]
    fn picks_the_earliest_winning_timestamp_not_the_first_winning_coin() {
        // With several winning coins, publishing at the earliest possible second
        // matters: on a 60-second target, a later timestamp is a real chance of
        // losing the height to another staker.
        let e = Engine::default();
        let mut s = staker(1_000 * COIN);
        s.coins = (0..40)
            .map(|i| StakeCandidate { prevout_n: i, ..s.coins[0].clone() })
            .collect();
        let t = tip(0x1e00_ffff); // hard enough that coins win at differing times
        let now = 1_700_000_100;
        let wins = e.search(&t, &[s.clone()], now);

        if let Some(w) = wins.first() {
            let from = now.max(t.tip_time + 1);
            let earliest = s
                .coins
                .iter()
                .filter_map(|c| lovenode_core::search_window(&t.tip, c, from, from + 90))
                .map(|(ts, _)| ts)
                .min()
                .expect("at least one win");
            assert_eq!(
                w.notice.hashproof_timestamp, earliest,
                "must publish at the earliest winning second"
            );
        }
    }

    #[test]
    fn award_hook_runs_after_acceptance_and_is_optional() {
        let e = Engine::default();
        let s = staker(1_000 * COIN);
        let sink = MemorySink::default();
        let state = AwardState { program_start_time: 1_700_000_000, total_awarded: 0 };

        let always = DiminishingPolicy {
            initial_chance_ppm: PPM,
            half_life_days: 30.0,
            floor_chance_ppm: 0,
            max_total_awards: None,
            min_stake_sats: 0,
            series: "genesis".into(),
            roll_source: RollSource::StakeProof,
        };
        let got = e.award_for_accepted_block(
            &always, &sink, &state, &s, [0x44; 32], [0x77; 32], 1_001, 1_700_000_060, 1_000 * COIN,
        );
        assert!(got.is_some());
        assert_eq!(sink.awards.lock().unwrap().len(), 1);

        let never = DiminishingPolicy { initial_chance_ppm: 0, ..always };
        let none = e.award_for_accepted_block(
            &never, &sink, &state, &s, [0x55; 32], [0x88; 32], 1_002, 1_700_000_120, 1_000 * COIN,
        );
        assert!(none.is_none(), "a zero chance must never award");
    }
}
