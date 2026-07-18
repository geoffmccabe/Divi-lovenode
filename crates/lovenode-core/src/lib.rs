//! # lovenode-core
//!
//! The Divi proof-of-stake win-check, and nothing else.
//!
//! This crate is deliberately tiny and dependency-light: it performs **no I/O**,
//! holds **no keys**, and never touches the network or the chain. That is what
//! lets the same code run on a phone, in the relay, and in tests.
//!
//! It is a port of `divi/src/ProofOfStakeCalculator.cpp` and is
//! **consensus-critical**: if it diverges from the C++ node by a single byte,
//! every stake produced from it is invalid. Treat changes accordingly, and
//! re-run the cross-check against a live node (see `docs/PROTOCOL.md`) before
//! shipping any modification.
//!
//! ```
//! use lovenode_core::{NetworkTip, StakeCandidate, search_window};
//!
//! let tip = NetworkTip { stake_modifier: 0x0123_4567_89ab_cdef, bits: 0x1e00_ffff };
//! let coin = StakeCandidate {
//!     prevout_hash: [0x11; 32],
//!     prevout_n: 0,
//!     value_sats: 500 * lovenode_core::COIN,
//!     coinstake_start_time: 1_700_000_000,
//! };
//! // Sweep one minute of candidate timestamps for a win.
//! let _ = search_window(&tip, &coin, 1_700_003_600, 1_700_003_660);
//! ```

pub mod block;
pub mod kernel;
pub mod serialize;
pub mod tx;
pub mod u256;

pub use kernel::{
    check_win, coin_age_weight, search_window, stake_hash, target_hit, NetworkTip, StakeCandidate,
    COIN, MAX_COIN_AGE_WEIGHT,
};
pub use block::{merkle_root, BlockHeader};
pub use serialize::{display_hex, dsha256, from_hex, hash_from_display_hex, to_hex};
pub use tx::{OutPoint, Transaction, TxIn, TxOut};
pub use u256::U256;
