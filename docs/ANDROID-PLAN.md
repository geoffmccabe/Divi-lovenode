# LoveNode — phased plan to a working Android staker

Android-first, deliberately: it is the only platform where "stake overnight while
you sleep" is literally true (foreground service, screen off). iOS follows later
as an app-open companion.

**Where we are:** the engine is built and proven — the win-check, block and
transaction serialization, and signing are each validated against real chain data
(93 tests). What does not exist: the phone app, the relay's transport, block
assembly, and an end-to-end proof.

Phases are in dependency order. Each has an exit criterion; do not start the next
until the previous one meets it.

---

## Phase 0 — Close the correctness gate ⚠ critical path

**Goal:** prove a block signed **entirely outside the node** is accepted by the
network. Everything after this assumes it works; if it doesn't, we want to know
now, not after an app exists.

### Two node RPCs are required first

Both are additive and read/write only — **no consensus change, no fork** — but
neither exists today (verified against the source):

**1. A stake template.** Masternode, treasury and lottery payments are
consensus-validated (`BlockIncentivesPopulator::FillBlockPayee`,
`masternode-payments.cpp`). A block that pays the wrong masternode is rejected.
We must **not** reimplement that selection — it is exactly the kind of
consensus-critical logic that silently drifts. The node must tell us the required
coinstake outputs:

```
getstaketemplate <txid> <vout> <value>  ->  {
  coinstake_outputs: [ {value, scriptPubKey}, ... ],   // incentives + stake split
  transactions:      [ "<raw hex>", ... ],             // to include
  coinbase_hex:      "...",
  version, bits, tip_hash, tip_time
}
```

`getblocktemplate` already exists and may be extendable rather than written from
scratch — check whether it is PoS-aware before deciding.

**2. A submit path.** Divi has `getblocktemplate` but **no `submitblock`**, so
there is currently no way to publish an externally-assembled block at all:

```
submitstakeblock <coinstake_hex> <block_signature> <header fields>  ->  block hash | error
```

Assembling inside the node (rather than accepting a whole raw block) means the
node re-derives the merkle root and validates before broadcast, so a malformed
submission is rejected cleanly instead of wasting a win.

### Then drive it end to end on regtest
1. Pick a mature UTXO; run the win-search until it hits.
2. Fetch the stake template.
3. Build the coinstake **in Rust**, with the template's required outputs.
4. Verify our own share comes back to us (`coinstake_pays_to`), then sign —
   **out of process**, simulating the phone.
5. Build the header in Rust, hash it locally, sign it.
6. Submit. 

**Exit criterion:** the block is accepted and extends the chain.

**Risks that could surface here (and only here):**
- Stake timestamp rules — `PoSTransactionCreator` applies an `nHashDrift`
  allowance; our candidate timestamp must fall inside what the node accepts.
- Coinbase shape for PoS blocks.
- Lottery/superblocks have extra payment requirements; the template must cover
  them, or we skip staking on those heights initially.

---

## Phase 1 — The relay service

**Goal:** a service that finds wins for registered devices and turns their
signatures into published blocks.

- Registration: **addresses only** — reject anything resembling key material.
- Per-block loop: fetch tip → load eligible coins (20 confirmations, 1 hour old)
  → sweep the search window.
- Transport: a persistent WebSocket. **Not** push notifications — wake-up is
  seconds-to-never and would lose most 60-second block races.
- On a win: send ingredients only (never a digest to sign), receive the signed
  coinstake and block signature, submit via Phase 0.
- Persistence for registrations and award state.
- Hardening: authentication, strict rate limits, abuse protection, and **hard
  isolation from anything custodial** — this service must not share a wallet or a
  host with customer funds.

**Exit criterion:** a device (simulated by a test client) stakes a regtest block
end to end over the wire.

---

## Phase 2 — The Android app

**Goal:** the real thing, in your hand.

- Tauri 2 Android project. `lovenode-core` and `lovenode-sign` compile as-is for
  `aarch64-linux-android` — they are pure Rust with no platform assumptions, which
  is why they were built dependency-light.
- Key generation/import into the **Android Keystore**; keys never leave, never
  transmitted, never backed up to the relay.
- Registration, then a persistent connection that idles.
- On a win notice: `verify_win()` locally → build coinstake and header → confirm
  payback to self → sign → return. All of this logic already exists and is tested.
- UI kept deliberately small: staking status, balance, recent wins, settings.
  Reuse DD69's design tokens so the wallet and staker look like one family.

**Exit criterion:** an APK sideloaded onto your phone stakes a regtest block.

---

## Phase 3 — Android platform behaviour & Play compliance

- **Foreground service** with the persistent notification — this is what allows
  staking with the screen off. Android 14+ requires a **declared service type that
  matches actual behaviour**; `dataSync` is the honest fit (the app maintains a
  synced connection). Play reviews this declaration, so it must be accurate.
- Battery-optimisation exemption prompt, and honest disclosure of what running
  overnight costs (battery wear, mobile data).
- Prefer Wi-Fi; keep bytes minimal.
- **Play listing position: a non-custodial wallet with remote staking.** Play
  bans on-device mining but permits apps that *remotely manage* it — which is
  exactly our architecture, since the relay does all searching and the phone only
  signs. Do not describe it as "run a node" or "mine".

**Exit criterion:** installable build that survives a full night plugged in.

---

## Phase 4 — NFD rewards

The hooks are built and tested; only the game details are missing.

- You supply: initial chance, half-life, floor, any lifetime cap, minimum stake,
  and the card characteristics.
- Decide the roll source: **block-hash** (publicly auditable — anyone can verify
  an award was legitimate) or **server-secret** (ungrindable). Public is the
  default; switch it if NFDs ever carry real value.
- Connect `AwardSink` to real NFD minting once the Divi Collectibles workstream
  can mint. Until then it logs, which is a fine way to run the program in
  observe-only mode and check the rates look right before anything is minted.

---

## Phase 5 — Beta with real money

- Start on a small mainnet stake with a handful of devices.
- Watch: wins produced vs wins accepted (orphan rate tells you if the timing
  budget is real), battery drain over a night, data used, relay uptime.
- Only widen once the orphan rate is understood.

---

## Bottlenecks worth naming

Rather than guess at durations, here is what actually gates progress:

1. **Phase 0's two node RPCs.** Everything is blocked behind them. They are small
   and additive, but they are node C++ work and need care.
2. **The 60-second timing budget.** A win must be signed and returned in roughly a
   second. If real-world round trips push the orphan rate high, the design needs
   revisiting — this is the main thing Phase 5 measures.
3. **Play's foreground-service review.** The declared type must match behaviour.
   Getting this wrong means rejection, not a warning.
4. **iOS, when the developer account clears** — Apple will not permit background
   staking regardless, so it stays an app-open companion. Do not promise otherwise.
