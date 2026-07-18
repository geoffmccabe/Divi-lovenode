# Divi LoveNode

**Stake DIVI from a phone. No blockchain download, no melted battery, no app-store trouble.**

LoveNode lets someone whose only computer is a phone stake their DIVI overnight, earn
rewards, and help secure the Divi network — without the 6+ GB chain and without the phone
doing any heavy work.

> **Status: foundation built and tested; not yet running against a live chain.**
> The consensus math, the award hooks, and the relay engine are implemented and covered by
> tests. The phone app is a scaffold. One small node-side RPC is still required (§ Blockers).

---

## Why this is possible at all

The calculation that decides whether one of your coins wins the right to make a block does
**not touch the blockchain and does not use your private key**. From Divi's
`ProofOfStakeCalculator.cpp`:

```
ss << stakeModifier << coinstakeStartTime << prevout.n << prevout.hash << hashproofTimestamp
```

Fifty-two bytes in, one double-SHA256 out, compared against a target weighted by the coin's
size and age. That's the whole thing — ported verbatim in [`lovenode-core`](crates/lovenode-core).

Because that check needs no private key, **the relay can do the searching** and the phone
only has to sign when it actually wins.

## Architecture: the server searches, the phone signs

```
 ┌── relay (untrusted) ───────────────┐        ┌── phone (holds the keys) ──┐
 │ watches the chain                  │        │                            │
 │ each block: sweep registered coins │        │                            │
 │        │ a coin wins               │        │                            │
 │        └──── ingredients ────────────────►  │ builds coinstake + header  │
 │                                    │        │ ITSELF, verifies, signs    │
 │  ◄──── signed coinstake + sig ──────────────┤                            │
 │ assembles block, broadcasts        │        │                            │
 └────────────────────────────────────┘        └────────────────────────────┘
```

This shape is not an accident — it solves both hard constraints at once:

- **Phones stay cool.** No polling loop, no search on device. The phone idles on one
  connection and does a few milliseconds of signing only when it wins.
- **App stores stay happy.** Apple (Guideline 3.1.5(b)) and Google Play both ban *on-device*
  crypto mining and both explicitly allow the work being done **off device**. Here the phone
  performs no mining-like computation at all — it is a wallet that signs.

**Trade-off, stated plainly:** the relay learns which addresses a user stakes (a privacy
cost). It never gains any ability to move their funds.

## Security: the one rule everything depends on

Divi signs the **block hash** with the staking key (`BlockSigning.cpp`). So if the relay were
allowed to hand the phone a 32-byte digest to sign, a compromised relay could send the
sighash of a transaction spending the user's coins and turn the reply into a spend.

**Therefore the relay never sends anything to be signed.** It sends raw ingredients; the phone
assembles the coinstake and block header, hashes them locally, and signs only what it built.
[`protocol.rs`](crates/lovenode-relay/src/protocol.rs) encodes this, and a test fails the
build if anyone ever adds a signable-digest field. Full rules in [docs/SECURITY.md](docs/SECURITY.md).

## Layout

```
crates/lovenode-core     the win-check. No I/O, no keys, no chain. Consensus-critical.
crates/lovenode-rewards  NFD (Divi NFT) award hooks — pluggable policy + sink.
crates/lovenode-relay    node adapter, per-block search engine, phone protocol.
app/                     phone client (Tauri 2 mobile) — scaffold.
docs/                    protocol and security contracts.
```

Everything is split so the risky parts stay small and auditable: the consensus math is one
dependency-light crate, and the award game cannot touch the staking path.

## NFD card-game hooks

Stake winners can be awarded an **NFD** (Non-Fungible-DIVI) for the forthcoming Divi Card
Game, with a chance that **diminishes over time** so early supporters get the better odds.

The hooks are built and tested; the game details are deliberately left open:

- `RewardPolicy` — decides *if* and *what* is awarded. `DiminishingPolicy` ships as the
  default: a chance that halves every `half_life_days`, with an optional floor, an optional
  hard cap on total awards, and a minimum stake size.
- `AwardSink` — where awards go. Logs today; swap in real NFD minting later.
- `RollSource` — either publicly verifiable (derived from the block hash, so anyone can
  audit an award) or server-secret (ungrindable). An explicit choice, not a hidden default.

Nothing here mints anything or knows the NFD on-chain format — that stays with the Divi
Collectibles workstream, so the card game can change completely without touching staking.

## Blockers

**The node needs one small read-only RPC.** The stake modifier lives in
`CBlockIndex::nStakeModifier` and is not exposed by any existing RPC (verified against the
source). The relay needs:

```
getstakinginfo -> { height, tip_hash, stake_modifier, bits, tip_time }
```

This changes no validation rule and needs no fork — it only surfaces a value the node already
computes. Until it lands, `lovenode-relay check` will tell you exactly that.

## Platform reality

| | Android | iOS |
|---|---|---|
| Overnight, screen off | ✅ foreground service | ❌ not permitted by Apple |
| Realistic model | plug in, leave running | plug in, **leave the app open** |

Android is the real product. iOS works while the app is open and charging. This is policy,
not silicon — don't promise iOS background staking.

## Honest expectations

Rewards are proportional to stake. Someone with a small balance wins **rarely**. This is aimed
at people with little money, so the app must show realistic expectations and must never imply
meaningful nightly income. Overnight charging also ages a battery, and mobile data costs money
on prepaid plans. All of that gets disclosed in the client.

## Running what exists

```sh
cargo test                                     # 36 tests across the workspace
DIVI_DATADIR=~/.divi cargo run -p lovenode-relay -- check
DIVI_DATADIR=~/.divi cargo run -p lovenode-relay -- watch <address>...
```

## Licence

MIT, matching Divi Core.
