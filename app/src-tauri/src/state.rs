//! App state and the small, plain-data view the UI renders.
//!
//! The UI is deliberately dumb: it shows what these structs say and calls the
//! commands. All judgement lives in the tested Rust crates below it.

use serde::Serialize;

/// The single status object the UI polls. Every field is something the user
/// genuinely needs to see — nothing is inferred or dressed up.
#[derive(Clone, Debug, Serialize, Default)]
pub struct StakingStatus {
    /// Has a staking key been set up on this device?
    pub has_wallet: bool,
    /// Is the client currently connected to a relay?
    pub connected: bool,
    /// The relay we're pointed at (hosted, or a user's own desktop).
    pub relay_url: String,
    /// How many of this device's coins the relay reports as eligible to stake.
    pub eligible_coins: usize,
    /// Blocks this device has won since the app started.
    pub blocks_won: u64,
    /// A short, honest one-line status for the UI header.
    pub headline: String,
    /// The most recent events, newest first, for the activity list.
    pub recent: Vec<ActivityLine>,
}

/// One line in the activity feed. Kept factual: what happened, when.
#[derive(Clone, Debug, Serialize)]
pub struct ActivityLine {
    pub kind: String, // "won" | "submitted" | "declined" | "info" | "error"
    pub detail: String,
    pub unix_time: u64,
}

/// The user-facing expectations copy. Surfaced as data so the UI can't quietly
/// drop the honest caveats — this project must never imply reliable income.
#[derive(Clone, Debug, Serialize)]
pub struct Disclosures {
    pub lines: Vec<String>,
}

impl Disclosures {
    pub fn standard() -> Self {
        Self {
            lines: vec![
                "Rewards are proportional to how much DIVI you stake. A small stake wins rarely — sometimes not for a long time. This is normal and not a fault.".into(),
                "Your phone must stay plugged in and the app open to keep staking. Running overnight uses battery and can age it over time.".into(),
                "Staking uses a small amount of mobile data. Prefer Wi‑Fi where you can.".into(),
                "Your keys never leave this phone. The relay can only cost you a missed reward, never your coins.".into(),
            ],
        }
    }
}
