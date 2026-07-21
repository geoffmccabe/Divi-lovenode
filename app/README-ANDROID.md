# Building LoveNode for Android

The tested Rust core (win-check, signing, client loop, keystore contract) is done
and unit-tested. This is the on-device shell around it. These steps must be run on
a machine with the Android toolchain; they cannot be validated in CI without a
device/emulator.

## Prerequisites
- Rust with the Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi`
- Android Studio + NDK, `ANDROID_HOME` / `NDK_HOME` set
- The Tauri CLI v2: `cargo install tauri-cli --version '^2'`
- A built frontend in `app/ui/dist` (`cd app/ui && npm install && npm run build`)

## Generate the Android project
```
cd app
cargo tauri android init
cargo tauri android dev      # run on a connected device / emulator
cargo tauri android build    # produce the release APK/AAB
```

## The three integrations the shell must supply

The Rust crates define the contracts; the Android host fills them in. Each is
marked in code and listed here so none is forgotten.

### 1. Android Keystore — replace `DevKeyStore`
`lovenode-keystore` ships only an in-memory `DevKeyStore` (NOT secure). A release
build must implement `KeyStore` over the **Android Keystore** via a small Tauri
plugin in Kotlin:
- generate/import the secp256k1 secret into a hardware-backed key where available
- `load()` returns it to Rust only at signing time, gated by device unlock /
  biometric where the user opts in
- `wipe()` deletes it
Until this is done the app must refuse to run against mainnet — a dev keystore on
a phone is not acceptable for real funds.

### 2. Launch the client loop
`start_staking` gates on a wallet existing but does not itself spawn the socket
task, because the tokio runtime and the platform keystore are owned by the host.
Wire it here:
```rust
// in the mobile entry point, after the key is available:
let staker = PhoneStaker::new(key, device_token, coins, template_source);
tokio::spawn(lovenode_phone::client::run(
    &relay_url, addresses, device_token, &staker, on_event, stop_rx,
));
```
`on_event` forwards `ClientEvent`s into the app status so the UI updates.

### 3. Foreground service — stake with the screen off
This is what makes "stake overnight" true on Android. Add a **foreground service**
with a persistent notification:
- Declare a foreground service type that matches real behaviour. `dataSync` is the
  honest fit (the app maintains a synced connection to a server). Play reviews this
  declaration — it must be accurate; do not claim a type you don't use.
- Request the battery-optimisation exemption so the OS doesn't suspend the socket.
- Keep bytes minimal; prefer Wi‑Fi.

## Play listing — position it correctly
List LoveNode as a **non-custodial wallet with remote staking**. Google Play bans
on-device crypto *mining* but permits apps that *remotely manage* it — which is
exactly this design: the relay does all searching, the phone only signs. Do **not**
describe it as "run a node" or "mine on your phone".

## Honest UX obligations (enforced in code, keep them in the UI)
`disclosures()` returns the required caveats as data. Show them at onboarding and
keep them reachable: rewards scale with stake (a small stake wins rarely), the
phone must stay open and charging, mobile data has a cost, and keys never leave the
device. Never imply reliable nightly income.

## iOS
Apple does not permit background execution for this, so iOS is an app-open
companion only, and wallet apps must ship from an **organization** developer
account. Deferred until the Android product is proven and the developer account
clears.
