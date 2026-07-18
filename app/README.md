# LoveNode phone client (scaffold)

Tauri 2 mobile app. **Not built yet** — this directory documents what it must be, so the
security contract is fixed before any code lands.

## What it does

1. Generates/imports a staking key into **iOS Keychain / Android Keystore**. Keys never leave.
2. Registers its **addresses only** with the relay.
3. Holds a live connection and idles. No search loop — the relay does the searching, which is
   what keeps the phone cool and keeps the app inside Apple's and Google's rules.
4. On a win notice: verifies the claim, builds the coinstake and block header **itself**,
   signs, returns them. See `../docs/PROTOCOL.md`.

## Non-negotiables (see ../docs/SECURITY.md)

- **Never sign a digest supplied by the relay.** Build and hash the header on device.
- Verify the win locally (`WinNotice::verify_win`) before signing anything.
- Verify the coinstake spends the user's own coin back to the user's own address.
- Reuse `lovenode-core` for the win-check — do not reimplement the consensus math.

## Platform notes

- **Android:** foreground service (with the persistent notification) keeps the connection
  alive with the screen off. Android 14+ requires a declared service type that matches real
  behaviour — `dataSync` is the plausible fit, and Play reviews the declaration.
- **iOS:** no background execution for this. Model is "plug in, leave the app open", with the
  idle timer disabled. Do not promise background staking.
- Apple requires wallet apps to ship from an **organization** account, not an individual one.

## UX obligations

This is aimed at people with very little money. The app must:

- show **realistic** expected earnings (rewards scale with stake; small stakes win rarely),
- disclose that it needs to stay open and charging,
- disclose mobile-data use and prefer Wi-Fi,
- never imply reliable nightly income.

## Reusing the desktop UI

The Divi Desktop 6.9 React UI can be carried over for look and feel. The *node-driving* parts
of that app do not apply here — LoveNode never runs a node.
