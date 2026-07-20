//! Orchestration: turning a win into a published block.
//!
//! This is the relay's actual job, expressed independently of any network
//! transport. The device that holds the key is represented by the [`StakeSigner`]
//! trait, so the same flow drives a real phone over a socket, an embedded signer
//! inside DD69, or a test double — and Phase 2's Android app only has to
//! implement one small interface.
//!
//! The relay is untrusted by design. Everything in here is arranged so that the
//! relay proposes and the signer disposes: the relay never sees a key, and every
//! value that decides where money goes is checked on the signer's side against
//! what the signer independently knows.

use crate::chain::{staking_tip, StakingTip};
use crate::engine::{Engine, FoundWin, Staker};
use crate::protocol::{SignedStake, StakeOutcome, WinNotice};
use crate::rpc::NodeRpc;
use serde_json::json;

/// Whatever holds the staking key: a phone, an embedded desktop signer, a test.
///
/// The relay hands over *ingredients* and receives *signed material*. It never
/// asks for a signature over bytes of its own choosing — see `docs/SECURITY.md`.
pub trait StakeSigner {
    /// Build and sign the coinstake and block header for this win.
    ///
    /// Implementations **must** independently verify the notice before signing:
    /// re-check the win ([`WinNotice::verify_win`]), and confirm the coinstake
    /// returns at least what they know their coin to be worth. A signer that
    /// trusts the relay's `value_sats` can be robbed outright.
    fn sign_win(&self, notice: &WinNotice) -> Result<SignedStake, String>;

    /// Which device this signer answers for, matched against `FoundWin`.
    fn device_token(&self) -> &str;
}

/// One relay cycle: look for wins, get them signed, publish them.
pub struct RelaySession {
    pub engine: Engine,
    /// Refuse to act on a tip older than this many seconds. A win computed
    /// against a stale parent is dead on arrival, so producing one only wastes
    /// the signer's battery and the height.
    pub max_tip_age_secs: u32,
}

impl Default for RelaySession {
    fn default() -> Self {
        Self { engine: Engine::default(), max_tip_age_secs: 300 }
    }
}

/// What happened to one win over a full cycle.
#[derive(Debug)]
pub struct CycleResult {
    pub device_token: String,
    pub height: u64,
    pub outcome: StakeOutcome,
}

impl RelaySession {
    /// Run one pass: fetch the tip, search, and for each win ask the owning
    /// signer to sign, then submit.
    pub fn run_once(
        &self,
        rpc: &NodeRpc,
        signers: &[&dyn StakeSigner],
        stakers: &[Staker],
        now: u32,
    ) -> Result<Vec<CycleResult>, String> {
        let tip = staking_tip(rpc)?;
        self.check_tip_fresh(&tip, now)?;

        let wins = self.engine.search(&tip, stakers, now);
        let mut results = Vec::new();
        for win in wins {
            let Some(signer) = signers.iter().find(|s| s.device_token() == win.device_token)
            else {
                continue; // that device isn't connected right now
            };
            results.push(self.complete(rpc, *signer, &win));
        }
        Ok(results)
    }

    /// Reject a tip that has gone stale, rather than searching against it.
    pub fn check_tip_fresh(&self, tip: &StakingTip, now: u32) -> Result<(), String> {
        let age = now.saturating_sub(tip.tip_time);
        if age > self.max_tip_age_secs {
            return Err(format!(
                "chain tip is {age}s old (limit {}); refusing to search against a stale \
                 modifier — any win would be for the wrong parent block",
                self.max_tip_age_secs
            ));
        }
        Ok(())
    }

    /// Ask the signer to sign one win, then submit the result.
    fn complete(&self, rpc: &NodeRpc, signer: &dyn StakeSigner, win: &FoundWin) -> CycleResult {
        let outcome = match signer.sign_win(&win.notice) {
            Ok(signed) => self.submit(rpc, &signed),
            // A refusal is the signer protecting itself; it is not an error here.
            Err(e) => StakeOutcome::Rejected { reason: format!("signer declined: {e}") },
        };
        CycleResult {
            device_token: win.device_token.clone(),
            height: win.notice.height,
            outcome,
        }
    }

    /// Publish a signed stake through the node.
    pub fn submit(&self, rpc: &NodeRpc, signed: &SignedStake) -> StakeOutcome {
        match rpc.call(
            "submitstakeblock",
            json!([
                signed.coinstake_hex,
                signed.block_signature,
                signed.header_time,
                signed.merkle_root
            ]),
        ) {
            Ok(v) => match v.as_str() {
                Some(hash) => StakeOutcome::Accepted { block_hash: hash.to_string() },
                None => StakeOutcome::Rejected { reason: "node returned no block hash".into() },
            },
            // Losing the race is the normal case, not a fault: another staker got
            // the height first. Distinguish it so it isn't logged as an error.
            Err(e) if is_stale(&e) => StakeOutcome::Stale,
            Err(e) => StakeOutcome::Rejected { reason: e },
        }
    }
}

/// Did we simply lose the height to someone else?
fn is_stale(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("stale") || e.contains("prevblk") || e.contains("inconclusive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovenode_core::{NetworkTip, COIN};

    fn tip(age_secs: u32, now: u32) -> StakingTip {
        StakingTip {
            height: 1_000,
            tip_hash: [0x22; 32],
            tip_time: now - age_secs,
            tip: NetworkTip { stake_modifier: 777, bits: 0x2100_ffff },
        }
    }

    struct Refusing;
    impl StakeSigner for Refusing {
        fn sign_win(&self, _: &WinNotice) -> Result<SignedStake, String> {
            Err("coinstake returns less than my coin is worth".into())
        }
        fn device_token(&self) -> &str {
            "device-1"
        }
    }

    #[test]
    fn a_stale_tip_is_refused_before_any_searching() {
        let s = RelaySession::default();
        let now = 1_700_000_000;
        assert!(s.check_tip_fresh(&tip(10, now), now).is_ok());
        let err = s.check_tip_fresh(&tip(3_600, now), now).unwrap_err();
        assert!(err.contains("stale"), "got: {err}");
    }

    #[test]
    fn a_signer_refusing_is_recorded_not_treated_as_a_relay_error() {
        // The signer declining is the security model working. It must surface as
        // an outcome, never crash the cycle or get retried into submission.
        let s = RelaySession::default();
        let win = FoundWin {
            device_token: "device-1".into(),
            proof_hash: [0u8; 32],
            notice: WinNotice {
                height: 1_001,
                prev_block_hash: "aa".repeat(32),
                bits: 0x2100_ffff,
                stake_modifier: 777,
                prevout_txid: "bb".repeat(32),
                prevout_n: 0,
                value_sats: 1_000 * COIN,
                coinstake_start_time: 1_699_000_000,
                hashproof_timestamp: 1_700_000_100,
                mempool_txs_hex: vec![],
            },
        };
        let rpc = NodeRpc::new("127.0.0.1", 1, "u", "p"); // never contacted
        let r = s.complete(&rpc, &Refusing, &win);
        match r.outcome {
            StakeOutcome::Rejected { reason } => assert!(reason.contains("declined"), "{reason}"),
            other => panic!("expected a recorded refusal, got {other:?}"),
        }
    }

    #[test]
    fn losing_the_race_is_stale_not_an_error() {
        // Another staker taking the height is normal and must not be logged as a
        // fault, or the logs drown in false alarms.
        assert!(is_stale("submitstakeblock: prevblk-not-found"));
        assert!(is_stale("block is STALE"));
        assert!(!is_stale("merkle root mismatch"));
        assert!(!is_stale("cannot reach the Divi node"));
    }
}
