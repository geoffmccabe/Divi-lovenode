# LoveNode — integration brief for other agents

**Read this if you are working on another Divi project and might need to touch,
depend on, or interoperate with LoveNode.** It covers what exists, what is
proven, what the interfaces are, and what is likely to change.

Repo: `geoffmccabe/Divi-lovenode` (public). Related node work lives in
`geoffmccabe/Divi-Blockchain_6.9`, branch `modernize/remove-openssl`.

---

## 1. What LoveNode is

A way to **stake DIVI from a phone** without the phone holding the blockchain.

The enabling fact, verified in `ProofOfStakeCalculator.cpp`: the calculation that
decides whether a coin wins a block hashes only five small public values and
**needs no private key and no chain data**:

```
stakeModifier | coinstakeStartTime | prevout.n | prevout.hash | hashproofTimestamp
```

So the work splits cleanly: **a relay does the searching** (public math, no keys),
and **the phone only signs** when one of its coins wins.

That shape is not incidental — it is what keeps phones cool (they idle until they
win) and what keeps the app inside Apple's and Google's rules, since both ban
*on-device* crypto mining but permit the work being done **off device**.

**Storage on the phone: none.** No blocks, no chainstate. Just a key and its own
UTXO list.

---

## 2. Status — what is real

**Proven, not asserted.** Each consensus-critical piece is validated against real
chain data rather than against a reading of the source:

| Piece | How it was proven |
|---|---|
| Stake win-check | byte-identical to a C++ oracle compiled against Divi's own libraries |
| Block header + hash | reproduces a real block's hash |
| Merkle root | reproduces a real block's merkle root |
| Transaction serialization | parses a real coinstake and re-emits it byte-for-byte |
| Sighash | **the node's own signature verifies against the hash we compute** |
| **End to end** | **a block signed entirely outside the node was accepted and became the chain tip** (regtest height 750) |

~96 tests. **Phase 0 (the correctness gate) is closed.**

**Not built yet:** the Android app, the relay's network transport, registration,
and persistence. The engine exists; the product does not.

---

## 3. Crates — what to depend on

Deliberately split so the risky parts stay small and auditable.

| Crate | Purpose | Depend on it if… |
|---|---|---|
| `lovenode-core` | Win-check, block/transaction serialization, U256. **No I/O, no keys, no chain.** Only dependency is `sha2`. | you need to parse/build Divi blocks or transactions, or test a stake |
| `lovenode-sign` | Signing: sighash, coinstake and block signatures. Uses **libsecp256k1**, the same C library the node uses. | you need to sign Divi transactions or blocks |
| `lovenode-relay` | Node RPC client, chain adapter, per-block search engine, phone protocol. Library + thin binary. | you need to talk to a Divi node, or embed the relay |
| `lovenode-rewards` | NFD award hooks (policy + sink traits). **Mints nothing.** | you are building the NFD/card-game side |
| `lovenode-c2pa` | Divi PoE anchors as C2PA Content Credentials. | you are working on PoE or content provenance |

`lovenode-core` and `lovenode-sign` are pure Rust with no platform assumptions and
compile for `aarch64-linux-android` — that was intentional.

---

## 4. Node RPCs added (Divi-Blockchain_6.9, `modernize/remove-openssl`)

Three RPCs, all **additive — no consensus change, no fork**. If you run a node for
another project and want these, you need that branch's build.

### `getstakinginfo`
Returns the tip and the **stake modifier**, which no existing RPC exposed.

⚠ It does **not** return `tip->nStakeModifier`. It mirrors the node's hardened
modifier path and walks back to the most recent block that actually *generated* a
modifier. Observed live: tip at height 729, correct modifier from 727. The naive
version is silently wrong.

⚠ The modifier is a **16-hex string, not a number** — it is a full 64-bit value and
JSON numbers pass through doubles in many parsers, which would corrupt the low bits.

### `getstaketemplate <txid> <vout> <address>`
Returns an **unsigned** coinstake built by the node's own reward and incentive
logic, plus header fields. Signs nothing, spends nothing, needs no key.

Use it rather than building coinstakes yourself: masternode/treasury/lottery
payments are **consensus-validated**, and guessing them means every block you
produce is rejected.

⚠ Read `staker_credit` / `staker_reward`, not `subsidy_stake_reward`. Where
`Fork::DeprecateMasternodes` is active the masternode share also goes to the
staker, so the real gain is **498** (228 stake + 270 masternode), not 228.

### `submitstakeblock <coinstake_hex> <block_signature> <ntime> <merkle_root>`
Assembles and submits a PoS block from externally-produced signatures. The node
rebuilds the deterministic coinbase, recomputes the merkle root and **rejects a
mismatch**, and recomputes `nBits` rather than trusting it.

---

## 5. Facts about Divi you can reuse

Learned the hard way; each of these silently breaks naive implementations.

- **Block headers are 112 bytes, not 80.** For `nVersion > 3` an
  `nAccumulatorCheckpoint` follows the nonce, and `GetHash()` covers it. Hashing
  the usual 80 gives a wrong hash *every time*, with no error.
- **Blocks below version 4 use `HashQuark`**, a different algorithm. `lovenode-core`
  refuses them rather than mis-hashing.
- **Transactions have no `nTime`.** It is commented out in
  `primitives/transaction.h` — the format is plain Bitcoin. Adding one because
  "PoS chains have it" corrupts everything.
- **The PoS coinbase is fully deterministic from the block height**
  (`scriptSig = <height> <CScriptNum(1)>`), so anyone can rebuild it unaided.
- **A coinstake is marked by an empty first output** (value 0, empty script).
- **Staking rewards:** a stake win yields the staker **498** and the treasury
  **250** — 748 new coins per block. A naive explorer that reads coinstake outputs
  as reward overstates it ~21× because outputs include the staker's own returned coins.
- **Staking rules:** 60-second target spacing, 20-confirmation maturity, 1-hour
  minimum coin age.
- **No cold staking / delegation exists** anywhere in the source.
- **Hash byte order:** RPC and explorers show hashes *reversed* relative to how
  they are hashed. Use `serialize::hash_from_display_hex` / `display_hex`.

---

## 6. Security model — the rule that matters most

`BlockSigning.cpp` signs `block.GetHash()` with the **staking key**. So if a relay
could hand the phone a 32-byte digest to sign, a compromised relay could send the
**sighash of a transaction spending the user's coins** and convert the reply into a
spend — compact `(r,s)` re-encodes as DER. That is theft, not lost earnings.

**Therefore: the relay never sends anything to be signed.** It sends ingredients;
the phone builds and hashes the coinstake and header itself.

If you integrate with LoveNode, inherit these:

1. **Never add a "sign these bytes" entry point.** `lovenode-sign::sign_block`
   takes a `BlockHeader` and hashes it internally, deliberately. A test fails the
   build if a signable-digest field is added to the protocol.
2. **Verify before signing.** `coinstake_pays_to` checks value returns to the
   signer's own script. This is not ceremonial — during Phase 0 it caught a bad
   key and refused to sign.
3. **Keys never leave the device**; the relay gets **addresses only**.
4. **Treat the relay as hostile** and check the worst case is only lost earnings.

---

## 7. Roadmap

- **Phase 0 — correctness gate. ✅ DONE.** Externally-signed block accepted.
- **Phase 1 — relay service.** Registration, per-block loop, WebSocket transport,
  block submission, hardening.
- **Phase 2 — Android app** (Tauri 2). Keystore, persistent connection, signing.
- **Phase 3 — Play compliance.** Foreground service, listing position.
- **Phase 4 — NFD rewards wiring.**
- **Phase 5 — measured beta.**

iOS stays an app-open companion: Apple does not permit background staking.

### Deployment (decided)
Two, from one library: **hosted** on the Fasthosts node that runs the scanner
(serves phone-only users), and **embedded in DD69** (a user's own desktop relays
for their own phone — more private, addresses never leave their machine).

---

## 8. If your project is…

**The NFD / Divi Collectibles workstream.** `lovenode-rewards` decides *whether* a
stake win earns an NFD and emits an event; it mints nothing and knows nothing about
the on-chain record. Implement `AwardSink` to receive awards when minting exists.
Agreed schedule: **25% at launch, halving monthly, floor 1 in 64** (reached at
month 4). Chance is **per stake win**, not per day. `RollSource` is an explicit
choice: block-hash (publicly auditable) or server-secret (ungrindable).

**The scanner / explorer (`scan.divi.love`).** The relay will run on the same node.
Two things: (a) the `addressindex` reindex you need also lets the relay read user
UTXOs via `getaddressutxos` with **no wallet access** — one reindex serves both,
and the patched binary should ship in the same outage; (b) that node has already
suffered `divid` rpcthreads starvation, so the relay is built to cache and back
off. If you see thread pressure, tell us. Also: `lovenode-core` now parses blocks
correctly including the 112-byte header, if you ever need raw parsing.

**DD69 (the desktop wallet).** The relay is designed to be embedded in DD69 so a
desktop can relay for its owner's phone. Same library, different wiring. DD69 will
also need a **relay setting** in the phone app (hosted by default, own desktop
optional).

**Anything touching PoE / content provenance.** `lovenode-c2pa` carries a Divi
anchor inside a standard C2PA Content Credential (`love.divi.poe`). Note the
**ordering problem**: embedding a manifest changes the file's bytes, so the anchored
hash is either pre- or post-manifest and **which one must be recorded**
(`anchor_mode`). Also note that neither C2PA nor a blockchain proves a camera saw
reality rather than a screen — do not let product copy claim otherwise.

---

## 9. Stability

`lovenode-core` and `lovenode-sign` are consensus-critical and are the most stable —
but any change to them must be re-validated against a live node, not just unit
tested. The relay protocol (`protocol.rs`) **will change** as the transport lands;
do not depend on its wire format yet. `lovenode-rewards` traits are stable; the
card-game specifics are not defined.

Questions: ask in the LoveNode session, or read `docs/ANDROID-PLAN.md` (plan),
`docs/SECURITY.md` (rules), `docs/PROTOCOL.md` (phone↔relay).
