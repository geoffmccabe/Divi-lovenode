# LoveNode — start here (James)

Hi James. This is the simplest possible path from zero to running LoveNode on an
Android phone. The whole staking brain is **built and tested** — you're wrapping
a tested Rust core in an Android shell. Everything you need is in two public
repos, links below.

If you read nothing else: the app lets someone stake DIVI from their phone. The
phone holds the key and signs; a relay server does the searching. It's proven
working — a phone has staked real blocks over a real network connection in
testing. What's left is the Android packaging, which needs your machine.

---

## What to download

Two public GitHub repos. Clone both.

**1. The app + relay (this repo):**
```
git clone https://github.com/geoffmccabe/Divi-lovenode.git
```

**2. The Divi node with the staking RPCs (a specific branch):**
```
git clone -b modernize/remove-openssl https://github.com/geoffmccabe/Divi-Blockchain_6.9.git
```
> The `modernize/remove-openssl` branch matters — the three RPCs LoveNode needs
> (`getstakinginfo`, `getstaketemplate`, `submitstakeblock`) only exist there.

---

## What's proven vs. what you're building

**Proven and tested (143 Rust tests, don't rebuild):**
- The Divi win-check, block/transaction building, and signing — validated
  byte-for-byte against the real node.
- Address derivation and WIF — checked against a real node-produced address.
- The relay server and the phone client — a phone has **staked a real block over
  a live WebSocket** in testing (`cargo run -p lovenode-phone --example wire_stake`).

**You're building (needs Android Studio + the NDK):**
1. Package the Rust as an Android app (`cargo tauri android`).
2. Swap the dev key storage for the real Android Keystore (Kotlin draft provided).
3. Add the foreground service so it stakes with the screen off (Kotlin draft provided).

---

## Quick sanity check (5 minutes, no Android yet)

Prove the core works on your machine before touching Android:

```
cd Divi-lovenode
cargo test            # should print ~143 passing
```

Then the whole-system demo (needs a regtest node — see below, or skip for now):
```
DIVI_DATADIR=~/divi-poe-regtest cargo run -p lovenode-phone --example wire_stake
```
A successful run ends with `ACCEPTED over the wire`.

---

## Build the Android app

### Prereqs
- Android Studio + SDK + NDK (`ANDROID_HOME` and `NDK_HOME` set)
- Rust + the Android targets:
  `rustup target add aarch64-linux-android armv7-linux-androideabi`
- Tauri CLI v2: `cargo install tauri-cli --version '^2'`
- Node.js (for the UI)

### Steps
```
cd Divi-lovenode/app
cd ui && npm install && npm run build && cd ..
cargo tauri android init      # generates the Android Studio project
cargo tauri android dev       # runs on a connected phone / emulator
```
Open the generated project in Android Studio to debug, or `cargo tauri android
build` for a release APK/AAB.

At this point the app runs with the **in-memory dev key store** — fine for
kicking the tyres on testnet, but you must do steps 2 and 3 below before real
money. There's a gate in the code for that.

---

## The three integrations (all documented, drafts provided)

Full detail is in **`app/HANDOFF-JAMES.md`** and **`app/README-ANDROID.md`**.
Short version:

1. **Real key storage.** Replace `DevKeyStore` with the Android Keystore. Kotlin
   draft with the security design explained: `app/android-plugin/SecureKeyStore.kt`.
   (A hardware AES key encrypts the staking secret at rest; decrypted only to
   sign.)
2. **Launch the client loop** from the Tauri mobile entry point — the exact
   `tokio::spawn(...)` snippet is in `app/HANDOFF-JAMES.md`.
3. **Foreground service** so it stakes overnight: `app/android-plugin/StakingService.kt`,
   with the AndroidManifest lines and the Google Play notes (declare
   `foregroundServiceType=dataSync`, position it as a non-custodial wallet with
   remote staking — Play bans on-device mining but allows remote).

---

## Running a relay + node to test against

The phone needs a relay, and the relay needs a Divi node. For testing you can run
both locally.

**Build the node:**
```
cd Divi-Blockchain_6.9/divi
./autogen.sh && ./configure --without-gui && make -C src divid divi-cli
```

**A throwaway regtest node** (instant blocks, fake coins) is the easiest test bed;
`divi-cli setgenerate 1` mines a block. The `wire_stake` example above runs
against exactly this.

**The relay** is `cargo run -p lovenode-relay` — but for a real deployment it wants
the node running with `addressindex=1` and a `wss://` proxy in front. Details in
`app/HANDOFF-JAMES.md` under "The relay side".

For a first Android test you don't need the production relay — point the app at a
local relay + regtest node and confirm the flow end to end.

---

## The one rule to preserve

The phone signs a block hash with the staking key. The relay must **never** be
able to hand the phone bytes to sign — it sends ingredients, the phone builds and
hashes the block itself. This is enforced in `lovenode-phone`, with a test that
fails the build if anyone adds a "sign this" field to the protocol. Please keep it
that way in the shell.

---

## Where everything is

| What | Where |
|---|---|
| This guide | `START-HERE.md` |
| Cold-start handoff (the three integrations, relay setup) | `app/HANDOFF-JAMES.md` |
| Android build detail | `app/README-ANDROID.md` |
| Security rules | `docs/SECURITY.md` |
| Phone↔relay protocol | `docs/PROTOCOL.md` |
| The overall plan | `docs/ANDROID-PLAN.md` |
| How other Divi projects connect | `docs/FOR-OTHER-AGENTS.md` |
| Kotlin drafts | `app/android-plugin/` |

Thanks for launching this. Ping Geoff with anything unclear.
