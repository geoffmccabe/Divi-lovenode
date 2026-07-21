# LoveNode — Android launch handoff (for James)

Hi James. The hard part — the staking engine, signing, the relay, the phone
client, and the wallet setup — is **built and tested** (143 passing Rust tests,
and a real externally-signed block was accepted on a regtest node). What's left is
the Android assembly, which needs a machine with Android Studio + the NDK. This
doc is everything you need to take it from "tested Rust" to "APK on a phone".

Nothing here changes the tested core. You are wiring a shell around it.

## What already works (don't rebuild it)

- `crates/lovenode-core` — the Divi consensus math (win-check, block/tx
  serialization). Validated byte-for-byte against the C++ node.
- `crates/lovenode-sign` — signing + `wallet` (address derivation, WIF, key
  generation). The address code is proven against a real node-produced address.
- `crates/lovenode-phone` — the on-device staker + the client loop. Every safety
  rule lives here; the UI makes no security decisions.
- `crates/lovenode-relay` — the WebSocket relay server. Runs on the Fasthosts
  node next to the scanner.
- `crates/lovenode-keystore` — the key-storage contract, with an in-memory dev
  backend you will replace on Android.
- `app/src-tauri` — the Tauri command surface (create/import wallet, start/stop,
  status). Command logic is unit-tested.
- `app/ui` — a small, honest React UI.

## The three things to build on-device

They are marked in code and each has a scaffold in `app/android-plugin/`.

### 1. Generate the Android project
```
cd app
cd ui && npm install && npm run build && cd ..
cargo tauri android init
cargo tauri android dev     # runs on a connected phone/emulator
```

### 2. Wire the real Keystore backend
`crates/lovenode-keystore` ships `DevKeyStore` (in-memory, NOT secure). Replace it
on Android with the hardware-backed version:

- `app/android-plugin/SecureKeyStore.kt` is the Kotlin, with the design explained
  at the top: a hardware AES-GCM key (never leaves the secure element) encrypts
  the staking secret at rest; it's decrypted only at signing time.
- Expose `store / load / hasKey / setAddresses / addresses / wipe` to Rust through
  a small Tauri plugin (Kotlin ⇄ Rust), and implement `KeyStore` in Rust over that
  bridge. The Rust `KeyStore` trait is the exact contract to satisfy.
- **Until this is done, keep the app off mainnet.** A dev keystore holding a
  real key is not acceptable. There's a spot to gate this.

### Key-unlock timing (important, easy to get wrong)
The Android Keystore backend requires device unlock / biometric to decrypt the
staking secret. Do NOT decrypt per-signature — the phone is locked overnight and
it would fail. Decrypt ONCE when the user taps "Start staking" (present, can
authenticate), hand the secret to the Rust staking session, and hold it in the
foreground-service process for the run. Fully killing the process means the user
re-authenticates next open. This is the normal hot-staking trade-off and it's
explained at `load()` in SecureKeyStore.kt.

### 3. Launch the client task + foreground service
- In the Tauri mobile entry point, after the key is available, spawn the client:
  ```rust
  let staker = PhoneStaker::new(key, device_token, coins, template_source);
  tokio::spawn(lovenode_phone::client::run(
      &relay_url, addresses, device_token, &staker, on_event, stop_rx,
  ));
  ```
  `on_event` pushes `ClientEvent`s into the app status so the UI updates.
- `app/android-plugin/StakingService.kt` is the foreground service that keeps the
  socket alive with the screen off, with the AndroidManifest additions documented
  at the bottom of the file. **The `dataSync` service type must match real
  behaviour — Play reviews it.**

## The relay side (server, not phone)

The relay is `cargo run -p lovenode-relay` — but the socket server (`server.rs`)
is driven by `serve(addr, state, new_block)`. To run it for real you need:
- the patched Divi node (`getstakinginfo`, `getstaketemplate`, `submitstakeblock`
  — on branch `modernize/remove-openssl` of `geoffmccabe/Divi-Blockchain_6.9`),
  built and running with `addressindex=1`;
- a `new_block` signal — wire it to the node's ZMQ `hashblock` (enable
  `ENABLE_ZMQ`), with a ~10s poll as fallback;
- `wss://` termination in front (nginx/Caddy) — the server speaks plain `ws://`.

The relay watches user addresses via `getaddressutxos` (no wallet, no keys), so it
needs that address index — which the scanner reindex also provides. One reindex
serves both projects.

## Things I could not verify (worth your eyes)

- The Kotlin in `app/android-plugin/` is **authored, not compiled**. Treat it as a
  strong first draft, not tested code.
- The Tauri mobile entry point wiring (spawning the client, forwarding events)
  isn't written yet — it depends on the generated project layout.
- Real-device behaviour: battery drain overnight, the foreground-service review,
  and whether the 60-second block timing budget survives real network latency
  (the client sends a Ping keep-alive every 30s; tune if needed).

## The one rule that must survive everything

The phone signs a block hash with the staking key. The relay must **never** be
able to hand the phone bytes to sign — it sends ingredients, the phone builds and
hashes the block itself. That's enforced in `lovenode-phone` and there's a test
that fails the build if a signable-digest field is ever added to the protocol.
Please don't route around it in the shell.

Questions: the design docs are `docs/SECURITY.md`, `docs/PROTOCOL.md`,
`docs/ANDROID-PLAN.md`, and `docs/FOR-OTHER-AGENTS.md`. Thanks for launching this.
