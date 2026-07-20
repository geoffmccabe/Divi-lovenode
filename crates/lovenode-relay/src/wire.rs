//! The framed messages a phone and the relay exchange, and the transport seam.
//!
//! Kept separate from any socket implementation so the message contract is
//! testable on its own and does not drag an async runtime into the crate. A real
//! WebSocket, an embedded in-process channel (DD69), and a test double all
//! implement the same [`Transport`].
//!
//! Every message is a tagged JSON object, so the protocol can grow fields
//! without silent misinterpretation.

use crate::protocol::{Registration, SignedStake, StakeOutcome, WinNotice};
use serde::{Deserialize, Serialize};

/// Phone → relay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Register the addresses to watch (addresses only — never keys).
    Register(Registration),
    /// The signed pieces for a win the relay sent.
    Signed(SignedStake),
    /// Keep-alive; the relay answers with [`ServerMsg::Pong`].
    Ping,
}

/// Relay → phone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Registration accepted; here is how many coins are currently eligible.
    Registered { eligible_coins: usize },
    /// One of your coins won — here are the ingredients to sign.
    Win(WinNotice),
    /// What happened to a stake you signed.
    Outcome { height: u64, outcome: StakeOutcome },
    /// A message was rejected; `detail` says why.
    Error { detail: String },
    Pong,
}

impl ClientMsg {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ClientMsg serializes")
    }
    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("bad client message: {e}"))
    }
}

impl ServerMsg {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ServerMsg serializes")
    }
    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("bad server message: {e}"))
    }
}

/// One connection to a device, framed as whole messages. Deliberately minimal
/// and blocking: the caller decides its own concurrency model (a thread per
/// connection today; an async task if this ever needs thousands of them).
pub trait Transport: Send {
    /// Send one message to the device. Errors are terminal for this connection.
    fn send(&mut self, msg: &ServerMsg) -> Result<(), String>;
    /// Block until the next message, or `Ok(None)` on a clean close.
    fn recv(&mut self) -> Result<Option<ClientMsg>, String>;
}

#[cfg(test)]
pub mod testing {
    //! An in-memory transport for driving the full relay loop without a socket.
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A loopback pair: what the relay sends lands in the client's inbox.
    #[derive(Clone, Default)]
    pub struct MemoryTransport {
        pub to_client: Arc<Mutex<VecDeque<ServerMsg>>>,
        pub to_relay: Arc<Mutex<VecDeque<ClientMsg>>>,
    }

    impl MemoryTransport {
        /// Queue a message as if the client had sent it.
        pub fn client_sends(&self, msg: ClientMsg) {
            self.to_relay.lock().unwrap().push_back(msg);
        }
        /// Take what the relay has sent to the client.
        pub fn drain_to_client(&self) -> Vec<ServerMsg> {
            self.to_client.lock().unwrap().drain(..).collect()
        }
    }

    impl Transport for MemoryTransport {
        fn send(&mut self, msg: &ServerMsg) -> Result<(), String> {
            self.to_client.lock().unwrap().push_back(msg.clone());
            Ok(())
        }
        fn recv(&mut self) -> Result<Option<ClientMsg>, String> {
            Ok(self.to_relay.lock().unwrap().pop_front())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_through_json_tagged() {
        let reg = ClientMsg::Register(Registration {
            addresses: vec!["DAddr".into()],
            device_token: "tok".into(),
        });
        let json = reg.to_json();
        assert!(json.contains("\"type\":\"register\""), "tagged: {json}");
        assert_eq!(ClientMsg::from_json(&json).unwrap(), reg);

        let pong = ServerMsg::Pong;
        assert_eq!(ServerMsg::from_json(&pong.to_json()).unwrap(), pong);
    }

    #[test]
    fn an_unknown_message_type_is_rejected_not_guessed() {
        assert!(ClientMsg::from_json(r#"{"type":"drain_wallet"}"#).is_err());
        assert!(ClientMsg::from_json("not json").is_err());
        assert!(ServerMsg::from_json("{}").is_err());
    }

    #[test]
    fn the_client_can_never_send_a_win_or_outcome() {
        // Those are relay-authored. A client message shaped like one must not
        // deserialize as a ClientMsg — the type split is the guarantee.
        assert!(ClientMsg::from_json(r#"{"type":"win"}"#).is_err());
        assert!(ClientMsg::from_json(r#"{"type":"outcome"}"#).is_err());
    }
}
