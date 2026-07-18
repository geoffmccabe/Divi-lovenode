//! # lovenode-rewards — NFD award hooks
//!
//! When a LoveNode user wins a stake, they may also be awarded an **NFD**
//! (Non-Fungible-DIVI) for the forthcoming Divi Card Game. The chance of an
//! award **diminishes over time**, so early supporters of the network get the
//! better odds.
//!
//! ## What this crate is (and deliberately is not)
//!
//! This is the **hook layer only**. It decides *whether* a win earns an NFD and
//! emits an award event. It does **not** mint anything, does not know the NFD
//! on-chain record format, and does not talk to a chain — that belongs to the
//! NFD/Divi Collectibles workstream. Keeping the two apart means the card-game
//! design can change completely without touching any staking code.
//!
//! Two traits are the seam:
//! - [`RewardPolicy`] — decides *if* and *what* is awarded. Swap in your own.
//! - [`AwardSink`] — receives awards (log today, NFD mint later).
//!
//! ## Filling in the details later
//!
//! [`NfdAward`] intentionally carries only a `series`, a `tier` and the audit
//! fields. Card characteristics (art, stats, rarity tables, set membership…)
//! are yours to define; add them to `NfdAward` or carry them in `attributes`
//! without changing the staking path.

use sha2::{Digest, Sha256};

/// Parts-per-million denominator used for all chances (1_000_000 = 100%).
pub const PPM: u64 = 1_000_000;

/// Seconds in a day, for the decay curve.
const SECS_PER_DAY: f64 = 86_400.0;

/// The context of a single stake win, handed to a [`RewardPolicy`].
#[derive(Clone, Debug)]
pub struct StakeWin {
    pub block_height: u64,
    /// Hash of the block this user just staked, internal byte order.
    pub block_hash: [u8; 32],
    /// Block timestamp (unix seconds).
    pub block_time: u32,
    /// The address that won the stake — the prospective NFD recipient.
    pub staker_address: String,
    /// Size of the winning stake, in satoshis.
    pub stake_value_sats: i64,
}

/// A decision to award an NFD. Characteristics are intentionally open-ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NfdAward {
    /// Which collection/series this belongs to (e.g. a card set).
    pub series: String,
    /// Placeholder rarity/tier label — define real tiers later.
    pub tier: String,
    /// Free-form characteristics, so the card game can evolve without a
    /// breaking change here. Keys and meaning are yours to define.
    pub attributes: Vec<(String, String)>,
    /// The roll that produced this award, and the chance that applied — both
    /// recorded so any award can be audited or independently re-checked.
    pub roll: u64,
    pub chance_ppm: u64,
}

/// Running program state the policy may consult.
#[derive(Clone, Copy, Debug)]
pub struct AwardState {
    /// Unix time the award program started (t=0 for the decay curve).
    pub program_start_time: u32,
    /// How many NFDs have been awarded so far, across all users.
    pub total_awarded: u64,
}

/// Decides whether a stake win earns an NFD. Implement this to define the game.
pub trait RewardPolicy: Send + Sync {
    fn evaluate(&self, win: &StakeWin, state: &AwardState) -> Option<NfdAward>;
}

/// Receives awards. Log them today; mint real NFDs later by swapping this out.
pub trait AwardSink: Send + Sync {
    fn record(&self, win: &StakeWin, award: &NfdAward) -> Result<(), String>;
}

/// How the per-win random roll is derived.
///
/// The choice is a real trade-off, so it is explicit rather than baked in:
#[derive(Clone, Debug)]
pub enum RollSource {
    /// Derived from the block hash. **Publicly verifiable** — anyone can
    /// recompute the roll and confirm an award was legitimate.
    ///
    /// Caveat: a staker can in principle nudge their block hash to fish for a
    /// better roll, but only by first *winning a stake*, so attempts are rate
    /// limited by their stake weight. Acceptable for a cosmetic game item;
    /// use [`RollSource::ServerSecret`] if awards ever carry real value.
    BlockHash,
    /// HMAC-style roll mixing in a server secret. **Not** publicly verifiable,
    /// but cannot be ground by the staker at all.
    ServerSecret(Vec<u8>),
}

impl RollSource {
    /// Deterministic 64-bit roll for this win.
    pub fn roll(&self, win: &StakeWin) -> u64 {
        let mut h = Sha256::new();
        h.update(b"lovenode/nfd/v1");
        h.update(win.block_hash);
        h.update(win.block_height.to_le_bytes());
        if let RollSource::ServerSecret(secret) = self {
            h.update(secret);
        }
        let d = h.finalize();
        u64::from_le_bytes(d[0..8].try_into().expect("sha256 yields 32 bytes"))
    }
}

/// The built-in policy: a chance that **halves every `half_life_days`**, so the
/// odds diminish over the life of the program.
///
/// `chance(t) = max(floor_ppm, initial_chance_ppm * 0.5 ^ (days_elapsed / half_life_days))`
///
/// All fields are placeholders to be tuned later — none of the staking code
/// depends on their values.
#[derive(Clone, Debug)]
pub struct DiminishingPolicy {
    /// Chance at program start, in parts-per-million.
    pub initial_chance_ppm: u64,
    /// Days for the chance to halve.
    pub half_life_days: f64,
    /// Chance never drops below this (set 0 to decay toward nothing).
    pub floor_chance_ppm: u64,
    /// Optional hard cap on total awards ever. `None` = uncapped.
    pub max_total_awards: Option<u64>,
    /// Only stakes at or above this size are eligible (0 = any).
    pub min_stake_sats: i64,
    /// Series label stamped onto awards.
    pub series: String,
    pub roll_source: RollSource,
}

impl DiminishingPolicy {
    /// The chance, in ppm, that applies at a given moment.
    pub fn chance_ppm_at(&self, now: u32, state: &AwardState) -> u64 {
        let elapsed = now.saturating_sub(state.program_start_time) as f64 / SECS_PER_DAY;
        let decayed = if self.half_life_days > 0.0 {
            self.initial_chance_ppm as f64 * 0.5_f64.powf(elapsed / self.half_life_days)
        } else {
            self.initial_chance_ppm as f64
        };
        (decayed.round().max(0.0) as u64)
            .max(self.floor_chance_ppm)
            .min(PPM)
    }
}

impl RewardPolicy for DiminishingPolicy {
    fn evaluate(&self, win: &StakeWin, state: &AwardState) -> Option<NfdAward> {
        if let Some(cap) = self.max_total_awards {
            if state.total_awarded >= cap {
                return None;
            }
        }
        if win.stake_value_sats < self.min_stake_sats {
            return None;
        }
        let chance_ppm = self.chance_ppm_at(win.block_time, state);
        if chance_ppm == 0 {
            return None;
        }
        let roll = self.roll_source.roll(win);
        if roll % PPM >= chance_ppm {
            return None;
        }
        Some(NfdAward {
            series: self.series.clone(),
            // Placeholder: real tier/rarity tables get defined with the card game.
            tier: "standard".to_string(),
            attributes: Vec::new(),
            roll,
            chance_ppm,
        })
    }
}

/// A sink that just collects awards in memory — useful for tests and for
/// running the program in "observe only" mode before NFD minting exists.
#[derive(Default)]
pub struct MemorySink {
    pub awards: std::sync::Mutex<Vec<(String, NfdAward)>>,
}

impl AwardSink for MemorySink {
    fn record(&self, win: &StakeWin, award: &NfdAward) -> Result<(), String> {
        self.awards
            .lock()
            .map_err(|_| "award log poisoned".to_string())?
            .push((win.staker_address.clone(), award.clone()));
        Ok(())
    }
}

/// Wire a policy to a sink. This is the single call the relay makes after a win,
/// so award handling can never block or break block production.
pub fn on_stake_win(
    policy: &dyn RewardPolicy,
    sink: &dyn AwardSink,
    win: &StakeWin,
    state: &AwardState,
) -> Option<NfdAward> {
    let award = policy.evaluate(win, state)?;
    if let Err(e) = sink.record(win, &award) {
        // An award is a bonus; never let it interfere with staking.
        eprintln!("lovenode-rewards: failed to record award: {e}");
    }
    Some(award)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DiminishingPolicy {
        DiminishingPolicy {
            initial_chance_ppm: 500_000, // 50% at launch, for clear testing
            half_life_days: 30.0,
            floor_chance_ppm: 0,
            max_total_awards: None,
            min_stake_sats: 0,
            series: "genesis".into(),
            roll_source: RollSource::BlockHash,
        }
    }

    fn win_at(height: u64, time: u32, seed: u8) -> StakeWin {
        StakeWin {
            block_height: height,
            block_hash: [seed; 32],
            block_time: time,
            staker_address: "DTestAddress".into(),
            stake_value_sats: 1_000 * 100_000_000,
        }
    }

    const T0: u32 = 1_800_000_000;
    fn state() -> AwardState {
        AwardState { program_start_time: T0, total_awarded: 0 }
    }

    #[test]
    fn chance_halves_every_half_life() {
        let p = policy();
        let s = state();
        assert_eq!(p.chance_ppm_at(T0, &s), 500_000);
        let one_half_life = T0 + (30.0 * SECS_PER_DAY) as u32;
        assert_eq!(p.chance_ppm_at(one_half_life, &s), 250_000);
        let two_half_lives = T0 + (60.0 * SECS_PER_DAY) as u32;
        assert_eq!(p.chance_ppm_at(two_half_lives, &s), 125_000);
    }

    #[test]
    fn chance_respects_floor_and_never_exceeds_100_percent() {
        let mut p = policy();
        p.floor_chance_ppm = 1_000;
        let far_future = T0 + (3_650.0 * SECS_PER_DAY) as u32;
        assert_eq!(p.chance_ppm_at(far_future, &state()), 1_000);

        p.initial_chance_ppm = 5_000_000; // nonsense input
        assert_eq!(p.chance_ppm_at(T0, &state()), PPM);
    }

    #[test]
    fn awards_get_rarer_over_time() {
        // Same population of wins, evaluated at launch vs much later.
        let p = policy();
        let s = state();
        let count_at = |offset_days: f64| {
            let t = T0 + (offset_days * SECS_PER_DAY) as u32;
            (0u8..=255)
                .filter(|seed| p.evaluate(&win_at(1, t, *seed), &s).is_some())
                .count()
        };
        let launch = count_at(0.0);
        let later = count_at(120.0); // four half-lives => ~1/16 the chance
        assert!(launch > later, "launch={launch} later={later}");
        assert!(launch > 0, "some awards must land at launch");
    }

    #[test]
    fn roll_is_deterministic_and_auditable() {
        let p = policy();
        let s = state();
        let w = win_at(42, T0, 7);
        let a = p.evaluate(&w, &s);
        let b = p.evaluate(&w, &s);
        assert_eq!(a, b, "same win must always produce the same decision");
        if let Some(award) = a {
            // the recorded roll must reproduce independently
            assert_eq!(award.roll, RollSource::BlockHash.roll(&w));
        }
    }

    #[test]
    fn different_blocks_roll_differently() {
        let a = RollSource::BlockHash.roll(&win_at(1, T0, 1));
        let b = RollSource::BlockHash.roll(&win_at(1, T0, 2));
        let c = RollSource::BlockHash.roll(&win_at(2, T0, 1));
        assert_ne!(a, b, "different block hash => different roll");
        assert_ne!(a, c, "different height => different roll");
    }

    #[test]
    fn server_secret_changes_the_roll_and_stays_stable() {
        let w = win_at(1, T0, 3);
        let public = RollSource::BlockHash.roll(&w);
        let secret = RollSource::ServerSecret(b"topsecret".to_vec());
        assert_ne!(public, secret.roll(&w));
        assert_eq!(secret.roll(&w), secret.roll(&w));
    }

    #[test]
    fn cap_and_minimum_stake_are_enforced() {
        let mut p = policy();
        p.initial_chance_ppm = PPM; // always win, to isolate the gates
        let w = win_at(1, T0, 9);

        p.max_total_awards = Some(10);
        let capped = AwardState { program_start_time: T0, total_awarded: 10 };
        assert!(p.evaluate(&w, &capped).is_none(), "cap must stop awards");
        let under = AwardState { program_start_time: T0, total_awarded: 9 };
        assert!(p.evaluate(&w, &under).is_some());

        p.max_total_awards = None;
        p.min_stake_sats = w.stake_value_sats + 1;
        assert!(p.evaluate(&w, &state()).is_none(), "small stakes are ineligible");
    }

    #[test]
    fn sink_receives_awards_and_never_breaks_staking() {
        let mut p = policy();
        p.initial_chance_ppm = PPM;
        let sink = MemorySink::default();
        let w = win_at(1, T0, 5);
        let awarded = on_stake_win(&p, &sink, &w, &state());
        assert!(awarded.is_some());
        assert_eq!(sink.awards.lock().unwrap().len(), 1);

        // A failing sink must not suppress the award decision itself.
        struct Failing;
        impl AwardSink for Failing {
            fn record(&self, _: &StakeWin, _: &NfdAward) -> Result<(), String> {
                Err("sink down".into())
            }
        }
        assert!(on_stake_win(&p, &Failing, &w, &state()).is_some());
    }
}
