# Divi LoveNode

**Stake DIVI from a phone. No blockchain download, no melted battery, no app-store trouble.**

LoveNode lets someone whose only computer is a phone stake their DIVI overnight, earn
rewards, and help secure the Divi network — without the 6+ GB chain and without the phone
doing any heavy work.

> **Status: consensus layer proven against real chain data.** The win-check is
> byte-identical to Divi's C++ implementation; block headers, merkle roots and
> transactions all reproduce real blocks exactly. What remains before a full
> end-to-end stake is on-device signing (secp256k1) and the relay transport.

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
crates/lovenode-core     win-check + block/transaction serialization. No I/O, no
                         keys, no chain. Consensus-critical.
crates/lovenode-sign     on-device signing (libsecp256k1). All key handling.
crates/lovenode-c2pa     Divi anchors as C2PA Content Credentials.
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

## Node requirement (built)

The stake modifier is not exposed by any RPC in stock `divid`, so a small **read-only**
`getstakinginfo` was added to the node (`rpcblockchain.cpp`, modernize branch). It changes no
validation rule and needs no fork.

It deliberately does **not** return `tip->nStakeModifier`: it mirrors the node's own hardened
modifier path, walking back to the most recent block that actually generated one. Live proof —
the tip was height 729 while the correct modifier came from 727, so the naive version would
have been silently wrong.

```
$ lovenode-relay check
height         : 729
stake modifier : 556175766445949947
bits           : 0x207fffff
>>> relay can see the staking tip; search is ready.
```

## What is proven, and how

Every consensus-critical piece is checked against something external, not against
my own reading of the source:

| Piece | Proven by |
|---|---|
| Stake win-check | byte-identical to a C++ oracle compiled against Divi's own libraries |
| Block header + hash | reproduces a real block hash (v4, 112-byte header) |
| Merkle root | reproduces a real block's merkle root |
| Transaction serialization | re-emits a real transaction's raw bytes exactly |
| Stake modifier | read live from a patched node (`getstakinginfo`) |

Two traps worth knowing, both caught this way: Divi v4 headers are **112 bytes**
(an accumulator checkpoint follows the nonce — hashing the usual 80 gives a wrong
hash every time), and the correct stake modifier is **not** `tip->nStakeModifier`
but the most recent block that actually generated one.

## C2PA Content Credentials

A Divi anchor is carried inside a standard **C2PA Content Credential** via the
`love.divi.poe` assertion, so anchored content verifies in Adobe's ecosystem,
newsroom tooling and camera firmware — software that has never heard of Divi.

C2PA deliberately uses **no blockchain**; it signs with X.509 certificates. That
has one structural weakness: certificates expire, get revoked, and their
authorities eventually disappear, taking the credential's meaning with them. An
anchor does not rot. C2PA proves *who signed and what was done*; the anchor
proves *by when it existed*. Spec: [docs/C2PA-ASSERTION.md](docs/C2PA-ASSERTION.md).

Two things that spec is blunt about, because both are easy to get wrong:
embedding a manifest changes the file's bytes, so the anchored hash is either of
the pre-manifest or post-manifest asset and **which one must be recorded**; and
neither C2PA nor a blockchain can prove the camera saw reality rather than a
convincing screen.

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

## Working on another Divi project?

Read **[docs/FOR-OTHER-AGENTS.md](docs/FOR-OTHER-AGENTS.md)** — what exists, which
crates to depend on, the node RPCs added, the hard-won facts about Divi's block
format that break naive implementations, and the security rules to inherit.

## Licence

MIT, matching Divi Core.
