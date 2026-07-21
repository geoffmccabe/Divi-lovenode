//! The phone's connection to a relay.
//!
//! Registers this device's addresses, then holds a live socket: when a `Win`
//! arrives it drives the [`PhoneStaker`] to sign locally and sends the result
//! back. This is the runtime loop the Android shell calls into; it contains no
//! trust-critical logic of its own — every safety decision is inside
//! `PhoneStaker::build_signed_stake`, which this only invokes.
//!
//! Pure transport plus a tiny state machine, so it is testable against the real
//! relay server over a loopback socket (see the crate's integration test).

use crate::{PhoneStaker, TemplateSource};
use futures_util::{SinkExt, StreamExt};
use lovenode_relay::protocol::{Registration, StakeOutcome};
use lovenode_relay::wire::{ClientMsg, ServerMsg};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// What happened while the client was connected — surfaced to the UI so it can
/// show honest status instead of guessing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    Registered { eligible_coins: usize },
    /// A win arrived and we signed and submitted it.
    Submitted { height: u64 },
    /// The relay told us how a submitted stake resolved.
    Outcome { height: u64, outcome: StakeOutcome },
    /// We declined to sign a win (the security core refused). Not an error on
    /// the network — the device protecting itself.
    Declined { reason: String },
    /// The relay reported a problem with something we sent.
    RelayError { detail: String },
}

/// Run the phone client against `relay_url` until the socket closes or `stop`
/// fires. `on_event` is called for every [`ClientEvent`] so the shell can update
/// the UI. Returns Ok on a clean close.
pub async fn run<T, F>(
    relay_url: &str,
    addresses: Vec<String>,
    device_token: String,
    staker: &PhoneStaker<T>,
    mut on_event: F,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String>
where
    T: TemplateSource,
    F: FnMut(ClientEvent),
{
    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| format!("cannot reach the relay: {e}"))?;

    // Register our addresses (never keys).
    let reg = ClientMsg::Register(Registration { addresses, device_token });
    ws.send(Message::Text(reg.to_json()))
        .await
        .map_err(|e| format!("register failed: {e}"))?;

    // Keep-alive so idle connections aren't reaped by intermediaries.
    let mut keepalive = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() { break; }
            }
            _ = keepalive.tick() => {
                if ws.send(Message::Text(ClientMsg::Ping.to_json())).await.is_err() {
                    return Err("connection lost".into());
                }
            }
            frame = ws.next() => {
                let Some(frame) = frame else { break; };
                let frame = frame.map_err(|e| format!("read error: {e}"))?;
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => continue,
                };
                // The relay is untrusted: a garbage frame must not stop staking.
                // Log-and-continue, exactly as the relay does for bad client input.
                let msg = match ServerMsg::from_json(&text) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg {
                    ServerMsg::Registered { eligible_coins } => {
                        on_event(ClientEvent::Registered { eligible_coins });
                    }
                    ServerMsg::Win(notice) => {
                        // Sign LOCALLY. Every safety rule is inside this call; a
                        // refusal is the device protecting itself, not a fault.
                        match staker.build_signed_stake(&notice) {
                            Ok(signed) => {
                                let height = signed.height;
                                ws.send(Message::Text(ClientMsg::Signed(signed).to_json()))
                                    .await
                                    .map_err(|e| format!("send signed failed: {e}"))?;
                                on_event(ClientEvent::Submitted { height });
                            }
                            Err(reason) => {
                                on_event(ClientEvent::Declined { reason });
                            }
                        }
                    }
                    ServerMsg::Outcome { height, outcome } => {
                        on_event(ClientEvent::Outcome { height, outcome });
                    }
                    ServerMsg::Error { detail } => {
                        on_event(ClientEvent::RelayError { detail });
                    }
                    ServerMsg::Pong => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::honest_staker;
    use lovenode_relay::server::RelayState;
    use lovenode_relay::rpc::NodeRpc;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, watch};

    // The whole Phase 1 + 2 loop over a real loopback socket: the phone connects
    // to the actual relay server, registers, and the connection stands up. (A
    // full win round-trip needs a live node for the template, exercised by the
    // end-to-end example; here we prove the client speaks the server's protocol.)
    #[tokio::test]
    async fn the_phone_client_registers_against_the_real_relay_server() {
        // start the real relay server on an ephemeral port
        let state = RelayState::new(NodeRpc::new("127.0.0.1", 1, "u", "p"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // serve() takes an address; reuse its connection handler via a tiny accept loop
        let (_btx, brx) = mpsc::channel::<()>(1);
        let st = state.clone();
        tokio::spawn(async move {
            // mimic serve()'s accept loop without rebinding
            let _ = serve_on(listener, st, brx).await;
        });

        let (staker, addresses, token) = honest_staker();
        let (_stx, srx) = watch::channel(false);

        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ev = events.clone();

        // run the client briefly, then stop it
        let url = format!("ws://{addr}");
        let handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                run(&url, addresses, token, &staker, move |e| ev.lock().unwrap().push(e), srx),
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.abort();

        let got = events.lock().unwrap().clone();
        assert!(
            got.iter().any(|e| matches!(e, ClientEvent::Registered { .. })),
            "expected a Registered event, got {got:?}"
        );
    }

    // A thin wrapper so the test can serve on an already-bound listener.
    async fn serve_on(
        listener: TcpListener,
        state: RelayState,
        _new_block: mpsc::Receiver<()>,
    ) -> Result<(), String> {
        loop {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let st = state.clone();
            tokio::spawn(async move {
                let _ = lovenode_relay::server::handle_one(stream, st).await;
            });
        }
    }
}
