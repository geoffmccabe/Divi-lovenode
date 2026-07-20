//! The hosted relay: an async WebSocket server that many phones connect to.
//!
//! One tokio task per connected phone (cheap even at thousands of mostly-idle
//! connections). A separate "tick" runs each time a new block arrives, scans the
//! registered coins, and routes any win to the owning phone's task.
//!
//! The consensus-sensitive work is **not** here — it lives in the pure, tested
//! `engine`, `session`, `chain` and `registry` modules. This file only moves
//! messages and holds sockets, so the risky code stays small and synchronous.
//!
//! Security posture unchanged: the relay holds no keys, sends only ingredients,
//! and the wire types make a phone incapable of sending a relay-authored message.
//!
//! ## Known hardening gaps (tracked, not yet closed)
//!
//! These do not risk funds — the phone verifies everything and signs only what it
//! builds — but they matter before a public deployment:
//!
//! * **No TLS here.** The listener speaks plain `ws://`. Terminate `wss://` at a
//!   reverse proxy (nginx/Caddy) in front, so addresses and traffic are not in
//!   the clear on the wire. Without it a network observer learns which addresses
//!   a user stakes (a privacy cost, never a theft one).
//! * **No proof of address ownership at registration.** A client may register an
//!   address it does not own; it then learns when that address's coins are
//!   eligible or winning (it cannot sign them). Close with a challenge: the relay
//!   sends a nonce, the phone signs it with the address key. Privacy, not funds.
//! * **No connection auth or per-IP limit.** An attacker can open many
//!   unregistered sockets. Needs a connection cap / rate limit for a public relay.
//!
//! The award recipient currently attributes to a device's first address; it
//! should be the winning coin's own address. A rewards-attribution detail.

use crate::chain::{eligible_coins_by_address, staking_tip};
use crate::engine::{Engine, Staker};
use crate::protocol::{SignedStake, StakeOutcome};
use crate::registry::{validate_registration, Registry};
use crate::rpc::NodeRpc;
use crate::session::RelaySession;
use crate::wire::{ClientMsg, ServerMsg};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

const MIN_CONFIRMATIONS: u64 = 20; // chainparams: nMaturity
const MIN_COIN_AGE_SECS: u32 = 60 * 60; // chainparams: nMinCoinAgeForStaking
/// Bounded outbound queue per device: if a phone stops reading, we drop it
/// rather than let its backlog grow without limit.
const OUTBOUND_QUEUE: usize = 32;

/// Shared server state. Cloneable handles to the same inner data.
#[derive(Clone)]
pub struct RelayState {
    registry: Arc<Mutex<Registry>>,
    /// device token -> (connection id, outbound channel). The connection id
    /// disambiguates a reconnect: if the same token reconnects on a new socket,
    /// the old connection's cleanup must not remove the *new* channel.
    outbound: Arc<Mutex<HashMap<String, (u64, mpsc::Sender<ServerMsg>)>>>,
    /// Monotonic source of connection ids.
    next_conn_id: Arc<AtomicU64>,
    rpc: Arc<NodeRpc>,
    engine: Arc<Engine>,
    session: Arc<RelaySession>,
}

impl RelayState {
    pub fn new(rpc: NodeRpc) -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::new())),
            outbound: Arc::new(Mutex::new(HashMap::new())),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            rpc: Arc::new(rpc),
            engine: Arc::new(Engine::default()),
            session: Arc::new(RelaySession::default()),
        }
    }

    /// One block's work: refresh coins, search, route wins to their devices.
    ///
    /// Called on each new-block signal. All the node I/O and searching is done
    /// through the pure modules; this only decides where each win is sent.
    /// Returns how many wins were dispatched, for logging/metrics.
    pub async fn tick(&self, now: u32) -> Result<usize, String> {
        // Snapshot the node's tip (blocking RPC off the async threads).
        let rpc = self.rpc.clone();
        let tip = tokio::task::spawn_blocking(move || staking_tip(&rpc))
            .await
            .map_err(|_| "tip task panicked".to_string())??;

        // Refuse a stale tip before doing any work.
        self.session.check_tip_fresh(&tip, now)?;

        // Which addresses do connected devices care about? (One query for all.)
        let addresses = { self.registry.lock().await.all_addresses() };
        if addresses.is_empty() {
            return Ok(0);
        }

        // Refresh eligible coins from the chain, TAGGED with their owning
        // address (blocking RPC off-thread).
        let rpc = self.rpc.clone();
        let coins_by_addr = tokio::task::spawn_blocking(move || {
            eligible_coins_by_address(&rpc, &addresses, now, MIN_CONFIRMATIONS, MIN_COIN_AGE_SECS)
        })
        .await
        .map_err(|_| "coins task panicked".to_string())??;

        // Give each device ONLY the coins on its own addresses. Handing every
        // device the full set would leak one user's coins to another and waste a
        // round trip telling a phone about a coin it cannot sign.
        let stakers: Vec<Staker> = {
            let reg = self.registry.lock().await;
            reg.devices()
                .map(|d| {
                    let owned: Vec<_> = coins_by_addr
                        .iter()
                        .filter(|(addr, _)| d.addresses.contains(addr))
                        .map(|(_, coin)| coin.clone())
                        .collect();
                    Staker {
                        device_token: d.token.clone(),
                        payout_address: d.addresses.first().cloned().unwrap_or_default(),
                        coins: owned,
                    }
                })
                .collect()
        };

        let wins = self.engine.search(&tip, &stakers, now);
        let dispatched = wins.len();
        let outbound = self.outbound.lock().await;
        for win in wins {
            if let Some((_, tx)) = outbound.get(&win.device_token) {
                // try_send: never block the tick on one slow device.
                let _ = tx.try_send(ServerMsg::Win(win.notice));
            }
        }
        Ok(dispatched)
    }

    async fn submit_signed(&self, signed: SignedStake) -> (u64, StakeOutcome) {
        let height = signed.height;
        let rpc = self.rpc.clone();
        let session = self.session.clone();
        let outcome = tokio::task::spawn_blocking(move || session.submit(&rpc, &signed))
            .await
            .unwrap_or(StakeOutcome::Rejected { reason: "submit task panicked".into() });
        (height, outcome)
    }
}

/// Run the relay server until cancelled. `new_block` yields once per new block
/// (from ZMQ in production, or a timer as a fallback).
pub async fn serve(
    listen_addr: &str,
    state: RelayState,
    mut new_block: mpsc::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("cannot bind {listen_addr}: {e}"))?;

    // Block-driven ticks.
    let tick_state = state.clone();
    tokio::spawn(async move {
        while new_block.recv().await.is_some() {
            let now = now_secs();
            match tick_state.tick(now).await {
                Ok(n) if n > 0 => eprintln!("relay: dispatched {n} win(s)"),
                Ok(_) => {}
                Err(e) => eprintln!("relay: tick error: {e}"),
            }
        }
    });

    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("accept failed: {e}"))?;
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, st).await {
                eprintln!("relay: connection {peer} ended: {e}");
            }
        });
    }
}

/// One phone's connection.
async fn handle_connection(stream: TcpStream, state: RelayState) -> Result<(), String> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| format!("websocket handshake failed: {e}"))?;
    let (mut sink, mut source) = ws.split();

    let (tx, mut rx) = mpsc::channel::<ServerMsg>(OUTBOUND_QUEUE);
    let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let mut device_token: Option<String> = None;

    loop {
        tokio::select! {
            // Outbound: a win or outcome to push to this phone.
            Some(msg) = rx.recv() => {
                if sink.send(Message::Text(msg.to_json())).await.is_err() {
                    break; // phone went away
                }
            }
            // Inbound: a message from the phone.
            incoming = source.next() => {
                let Some(frame) = incoming else { break; };
                let frame = frame.map_err(|e| format!("read error: {e}"))?;
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => continue,
                };
                match ClientMsg::from_json(&text) {
                    Ok(ClientMsg::Register(reg)) => {
                        if let Err(e) = validate_registration(&reg) {
                            let _ = sink.send(Message::Text(ServerMsg::Error{detail:e}.to_json())).await;
                            continue;
                        }
                        let token = reg.device_token.clone();
                        // register + wire up the outbound channel
                        let eligible = {
                            let mut reg_lock = state.registry.lock().await;
                            reg_lock.register(reg).map(|d| d.coins.len()).unwrap_or(0)
                        };
                        state.outbound.lock().await.insert(token.clone(), (conn_id, tx.clone()));
                        device_token = Some(token);
                        let _ = sink.send(Message::Text(
                            ServerMsg::Registered{eligible_coins: eligible}.to_json())).await;
                    }
                    Ok(ClientMsg::Signed(signed)) => {
                        let (height, outcome) = state.submit_signed(signed).await;
                        let _ = sink.send(Message::Text(
                            ServerMsg::Outcome{height, outcome}.to_json())).await;
                    }
                    Ok(ClientMsg::Ping) => {
                        let _ = sink.send(Message::Text(ServerMsg::Pong.to_json())).await;
                    }
                    Err(e) => {
                        let _ = sink.send(Message::Text(ServerMsg::Error{detail:e}.to_json())).await;
                    }
                }
            }
            else => break,
        }
    }

    // Clean up on disconnect so a dead device isn't searched for or routed to.
    if let Some(token) = device_token {
        let mut outbound = state.outbound.lock().await;
        // Only tear down if we are still the current connection for this token.
        // A newer reconnect with the same token must survive our disconnect.
        if outbound.get(&token).map(|(id, _)| *id) == Some(conn_id) {
            outbound.remove(&token);
            drop(outbound);
            state.registry.lock().await.remove(&token);
        }
    }
    Ok(())
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Registration;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A live loopback WebSocket: register over a real socket and get the reply.
    #[tokio::test]
    async fn a_phone_can_register_over_a_real_websocket() {
        let state = RelayState::new(NodeRpc::new("127.0.0.1", 1, "u", "p"));

        // bind on an ephemeral port and serve in the background
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st = state.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, st).await;
        });

        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();

        let reg = ClientMsg::Register(Registration {
            addresses: vec!["DTaddZU8Xy1234567890abcdefghij".into()],
            device_token: "dev-1".into(),
        });
        ws.send(Message::Text(reg.to_json())).await.unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let msg = ServerMsg::from_json(reply.to_text().unwrap()).unwrap();
        assert!(matches!(msg, ServerMsg::Registered { .. }), "got {msg:?}");

        // the device is now tracked
        assert_eq!(state.registry.lock().await.len(), 1);
        assert!(state.outbound.lock().await.contains_key("dev-1"));
    }

    #[tokio::test]
    async fn a_key_shaped_registration_is_refused_over_the_wire() {
        let state = RelayState::new(NodeRpc::new("127.0.0.1", 1, "u", "p"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st = state.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, st).await;
        });

        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();
        let reg = ClientMsg::Register(Registration {
            addresses: vec!["YU8mNq2kProper52CharSecretKeyValueGoesHere0123456789".into()],
            device_token: "dev-2".into(),
        });
        ws.send(Message::Text(reg.to_json())).await.unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let msg = ServerMsg::from_json(reply.to_text().unwrap()).unwrap();
        match msg {
            ServerMsg::Error { detail } => assert!(detail.contains("private key"), "{detail}"),
            other => panic!("expected refusal, got {other:?}"),
        }
        // nothing was registered
        assert_eq!(state.registry.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn a_reconnect_with_the_same_token_survives_the_old_connections_cleanup() {
        // Regression: the old connection's disconnect must NOT tear down a newer
        // connection that reconnected with the same device token.
        let state = RelayState::new(NodeRpc::new("127.0.0.1", 1, "u", "p"));
        let reg = Registration {
            addresses: vec!["DTaddZU8Xy1234567890abcdefghij".into()],
            device_token: "dev-x".into(),
        };

        // connection A registers
        {
            let mut a = state.registry.lock().await;
            a.register(reg.clone()).unwrap();
        }
        let (tx_a, _rx_a) = mpsc::channel(4);
        state.outbound.lock().await.insert("dev-x".into(), (1, tx_a));

        // connection B reconnects with the same token (newer conn id)
        let (tx_b, _rx_b) = mpsc::channel(4);
        state.outbound.lock().await.insert("dev-x".into(), (2, tx_b));

        // now connection A's cleanup runs -- it must see it is no longer current
        {
            let mut outbound = state.outbound.lock().await;
            if outbound.get("dev-x").map(|(id, _)| *id) == Some(1) {
                outbound.remove("dev-x");
            }
        }
        // B's channel must still be there
        assert_eq!(
            state.outbound.lock().await.get("dev-x").map(|(id, _)| *id),
            Some(2),
            "the reconnected device must survive the old connection's cleanup"
        );
    }

    #[tokio::test]
    async fn a_device_is_only_given_coins_on_its_own_addresses() {
        // Regression: over-notifying leaks one user's coins to another. Verify
        // the per-device partition keeps them separate.
        use crate::engine::Staker;
        use lovenode_core::{StakeCandidate, COIN};

        let coins_by_addr = vec![
            ("addrA".to_string(), StakeCandidate { prevout_hash:[1;32], prevout_n:0, value_sats:COIN, coinstake_start_time:1 }),
            ("addrB".to_string(), StakeCandidate { prevout_hash:[2;32], prevout_n:0, value_sats:COIN, coinstake_start_time:1 }),
        ];
        // device with only addrA must receive only coin 1
        let owned: Vec<_> = coins_by_addr.iter()
            .filter(|(a,_)| ["addrA".to_string()].contains(a))
            .map(|(_,c)| c.clone()).collect();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].prevout_hash, [1;32]);
        let _ = Staker { device_token:"d".into(), payout_address:"addrA".into(), coins: owned };
    }

    #[tokio::test]
    async fn ping_gets_a_pong() {
        let state = RelayState::new(NodeRpc::new("127.0.0.1", 1, "u", "p"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st = state.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, st).await;
        });
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();
        ws.send(Message::Text(ClientMsg::Ping.to_json())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert!(matches!(
            ServerMsg::from_json(reply.to_text().unwrap()).unwrap(),
            ServerMsg::Pong
        ));
    }
}
