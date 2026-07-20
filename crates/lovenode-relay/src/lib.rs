//! LoveNode relay library: node adapter, win-search engine, and the phone
//! protocol. Split from the binary so the engine can be tested and reused.
//!
//! The relay is deliberately powerless: it holds no keys, and the protocol is
//! designed so it can never obtain a signature over bytes of its choosing.
//! See `protocol.rs` for that contract.

pub mod chain;
pub mod engine;
pub mod protocol;
pub mod rpc;
pub mod registry;
pub mod server;
pub mod session;
pub mod wire;
