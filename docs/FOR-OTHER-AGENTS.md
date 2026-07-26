# LoveNode — integration brief for other agents

**Read this if you are working on another Divi project and might need to touch,
depend on, or interoperate with LoveNode.** It covers what exists, what is
proven, what the interfaces are, and what is likely to change.

Repo: `geoffmccabe/Divi-lovenode` (public). Related node work lives in
`geoffmccabe/Divi-Blockchain_6.9`, branch `modernize/remove-openssl`.

Last updated: 2026-07 (recovery-phrase / HD wallet landed; over-the-wire staking
proven).

---

## 1. What LoveNode is

A way to **stake DIVI from a phone** without the phone holding the blockchain,
built out into a **full mobile Divi wallet** (send/receive/history/PoE, staking,
and later a network map).

The enabling fact, verified in `ProofOfStakeCalculator.cpp`: the calculation that
decides whether a coin wins a block hashes only five small public values and
**needs no private key and no chain data**:

```
stakeModifier | coinstakeStartTime | prevout.n | prevout.hash | hashproofTimestamp
```

So the work splits cleanly: **a relay does the searching** (public math, no keys),
and **the phone only signs** when one of its coins wins. That shape keeps phones
cool (they idle until they win) and keeps the app inside Apple's and Google's
rules, which ban *on-device* mining but permit the work being done off device.

**Storage on the phone: none.** No blocks, no chainstate. A seed, its derived
addresses, and their UTXO list (fetched from the relay).

---

## 2. Status — what is real (as of this update)

**Proven, not asserted.** Each critical piece is validated against real chain
data or the real node, not against a reading of the source:

| Piece | How it was proven |
|---|---|
| Stake win-check | byte-identical to a C++ oracle compiled against Divi's own libraries |
| Block header + hash | reproduces a real block's hash (112-byte v4 header) |
| Merkle root | reproduces a real block's merkle root |
| Transaction serialization | parses a real coinstake and re-emits it byte-for-byte |
| Sighash | the node's own signature verifies against the hash we compute |
| Address / WIF | reproduces a real node-produced address from its hash160 |
| **Recovery phrase (BIP39/BIP44)** | **a known phrase derives byte-for-byte the same addresses the Divi node derives** (coin type 301) |
| **End to end, single process** | a block signed outside the node was accepted (regtest) |
| **End to end, over a real WebSocket** | **the phone client registered with the real relay server over TCP, signed a win locally, and the node accepted the block** |

**~158 tests passing.** Phase 0 (correctness) and Phase 1 (relay transport) are
closed; the Phase 2 Android shell exists.

**Not finished yet:** send/receive/balance/history wallet features (in progress),
the DD69-style UI, and the on-device Android work (secure keystore backend,
foreground service, real-phone testing) which needs the Android toolchain and is
owned by James Encke. The relay is not yet deployed to a live server.

---

## 3. Crates — what to depend on

Deliberately split so the risky parts stay small and auditable.

| Crate | Purpose | Depend on it if… |
|---|---|---|
| `lovenode-core` | Win-check, block/transaction serialization, U256. **No I/O, no keys, no chain.** | you parse/build Divi blocks or transactions, or test a stake |
| `lovenode-sign` | Signing (sighash, coinstake, block) via **libsecp256k1**, plus `wallet` (base58check, address derivation, WIF). | you sign Divi txs/blocks or derive addresses |
| `lovenode-hdwallet` | **BIP39 recovery phrase + BIP32/BIP44 HD derivation, interoperable with Divi Core.** | you need to derive keys/addresses from a phrase, or share a wallet's key tree |
| `lovenode-keystore` | The secure-storage contract (`KeyStore` trait) + an in-memory dev backend. Stores the **64-byte seed**. | you need to store/load a wallet seed behind platform secure storage |
| `lovenode-relay` | Node RPC client, chain adapter, per-block search engine, WebSocket server + phone protocol. | you talk to a Divi node, or embed the relay |
| `lovenode-phone` | The on-device staker (verifies a win, builds+signs a block) and the phone client loop. | you build the phone side or need the staking client |
| `lovenode-rewards` | NFD award hooks (policy + sink traits). **Mints nothing.** | you build the NFD/card-game side |
| `lovenode-c2pa` | Divi PoE anchors as C2PA Content Credentials. | you work on PoE / content provenance |

`lovenode-core`, `lovenode-sign`, and `lovenode-hdwallet` are pure Rust with no
platform assumptions and compile for `aarch64-linux-android`.

---

## 4. The HD wallet — reuse this for ANY Divi wallet

`lovenode-hdwallet` is the piece most likely to be useful to other projects
(DiviGo, DD69, anything that derives Divi keys). It is **proven interoperable with
Divi Core**, so a phrase works in both directions.

- **Wordlist:** the node's exact 2048-word English list (from `bip39_english.h`).
- **Seed:** standard BIP39 (PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic"`+passphrase).
- **Path:** BIP44 `m/44'/<coin>'/account'/change/index`, **coin type 301** on
  mainnet, **1** on testnet/regtest (from the node's `chainparams.cpp`).
- **Default generation: 12 words.** Restore accepts 12/15/18/21/24, so a 12-word
  LoveNode phrase restores in the desktop wallet and a 24-word desktop phrase
  restores here.
- **Note:** the node's `getnewaddress` starts the external chain at **index 1**
  (index 0 is reserved), so `receiving_address(1)` matches the node's first
  address. Keep this in mind if you compare address lists with the node.

API: `HdWallet::generate(network) -> (wallet, Mnemonic)`,
`HdWallet::from_mnemonic(&m, passphrase, network)`, `receiving_key(i)` /
`receiving_address(i)` / `change_key(i)`. The mnemonic is redacted from Debug;
seeds are zeroized on drop.

If you are building another Divi wallet, **use this crate rather than rolling your
own** — it is the only Divi-verified HD implementation we have.

---

## 5. Node RPCs added (Divi-Blockchain_6.9, `modernize/remove-openssl`)

Three RPCs, all **additive — no consensus change, no fork**. To use these you need
that branch's build.

### `getstakinginfo`
Returns the tip and the **stake modifier**, which no existing RPC exposed.
⚠ It does **not** return `tip->nStakeModifier`; it walks back to the most recent
block that actually generated a modifier (observed: tip 729, modifier from 727).
⚠ The modifier is a **16-hex string, not a number** (a full 64-bit value; JSON
doubles corrupt the low bits).

### `getstaketemplate <txid> <vout>`
Returns an **unsigned** coinstake built by the node's own reward/incentive logic,
plus header fields. Use it rather than building coinstakes yourself — the
masternode/treasury/lottery payments are consensus-validated.
⚠ Read `staker_credit` / `staker_reward`, not `subsidy_stake_reward` (where
`DeprecateMasternodes` is active the masternode share also goes to the staker).

### `submitstakeblock <coinstake_hex> <block_signature> <ntime> <merkle_root>`
Assembles and submits a PoS block from externally-produced signatures. The node
rebuilds the deterministic coinbase, recomputes the merkle root and rejects a
mismatch, and recomputes `nBits`.

The relay also uses stock RPCs: `listunspent` / `getaddressutxos` (needs
`addressindex=1`) to find stakeable coins by address, with no wallet access.

---

## 6. Facts about Divi you can reuse

Learned the hard way; each silently breaks naive implementations.

- **Block headers are 112 bytes, not 80** (for `nVersion > 3` an
  `nAccumulatorCheckpoint` follows the nonce, and `GetHash()` covers it).
- **Blocks below version 4 use `HashQuark`**, a different algorithm.
- **Transactions have no `nTime`** — the format is plain Bitcoin.
- **The PoS coinbase is deterministic from the block height**
  (`scriptSig = <height> <CScriptNum(1)>`).
- **A coinstake is marked by an empty first output** (value 0, empty script).
- **Staking rewards:** a win yields the staker **498** and the treasury **250**.
  Reading coinstake outputs as reward overstates it ~21× (outputs include the
  staker's own returned coins).
- **Staking rules:** 60-second target, 20-confirmation maturity, 1-hour min age.
- **No cold staking / delegation** exists in the source.
- **Address version bytes:** mainnet pubkey 30 ('D'), script 13, WIF 212;
  testnet/regtest pubkey 139 ('x'/'y'), WIF 239. **SLIP-44 coin type 301.**
- **Hash byte order:** RPC/explorers show hashes reversed vs how they are hashed
  (`serialize::hash_from_display_hex` / `display_hex`).

---

## 7. Security model — the rule that matters most

`BlockSigning.cpp` signs `block.GetHash()` with the staking key. If a relay could
hand the phone a 32-byte digest to sign, a compromised relay could send the
**sighash of a transaction spending the user's coins** and turn the reply into a
spend. That is theft, not lost earnings.

**Therefore: the relay never sends anything to be signed.** It sends ingredients;
the phone builds and hashes the coinstake and header itself.

If you integrate with LoveNode, inherit these:

1. **Never add a "sign these bytes" entry point.** `sign_block` takes a
   `BlockHeader` and hashes it internally; a test fails the build if a
   signable-digest field is added to the protocol.
2. **Bind value checks to the coin actually being spent.** The staker requires the
   coinstake to spend exactly the coin the win names (single input, matching
   prevout) before trusting its value — this closed a real coin-substitution theft
   where one key controls many UTXOs on an address.
3. **Verify before signing** — `coinstake_returns_at_least` checks the value comes
   back to the signer's own script, against the device's own record, never the
   relay's.
4. **Keys never leave the device**; the relay gets **addresses only**.
5. **Treat the relay as hostile** and check the worst case is only lost earnings.

The Android secure storage encrypts the **64-byte seed** at rest with a
hardware-backed key that requires device unlock; the seed is decrypted once at
"Start staking" and held in the foreground-service process for the session (it
cannot be decrypted while the phone is locked overnight).

---

## 8. Roadmap

- **Phase 0 — correctness gate. ✅** Externally-signed block accepted.
- **Phase 1 — relay service. ✅** Registration, per-block loop, WebSocket
  transport, block submission. Proven over a real socket.
- **Phase 2 — Android shell. ◑** Tauri 2 project, command surface, UI scaffold,
  and recovery-phrase/HD wallet all done. Remaining on-device (James): secure
  keystore backend, foreground service, real-phone testing.
- **v1 wallet backend — in progress.** Recovery phrase ✅ and keystore ✅ done;
  **send, balance, and transaction history** next; then the DD69-style UI.
- **Phase 3 — Play compliance** (foreground service type, listing position).
- **Phase 4 — NFD rewards wiring.**
- **Phase 5 — measured beta.**

iOS stays an app-wake companion (silent push wakes the app to sign): Apple does not
permit long-running background sockets.

### Deployment
Two, from one library: **hosted** on the Fasthosts node that runs the scanner, and
**embedded in DD69** (a user's own desktop relays for their own phone). A cheap
Singapore droplet is planned as a dev relay + an Asian node.

---

## 9. If your project is…

**Another Divi wallet (DiviGo, DD69, etc.).** Use `lovenode-hdwallet` for key
derivation — it is the only Divi-Core-verified HD implementation, so wallets stay
mutually recoverable. Use `lovenode-sign::wallet` for addresses/WIF.

**The NFD / Divi Collectibles workstream.** `lovenode-rewards` decides *whether* a
stake win earns an NFD and emits an event; it mints nothing. Implement `AwardSink`
to receive awards. Agreed schedule: **25% at launch, halving monthly, floor 1 in
64** (month 4), **per stake win**. `RollSource` is an explicit choice: block-hash
(auditable) or server-secret (ungrindable) — default is the ungrindable stake
proof.

**The scanner / explorer (`scan.divi.love`).** The relay runs on the same node.
The `addressindex` reindex you need also lets the relay read user UTXOs via
`getaddressutxos` with **no wallet access** — one reindex serves both. That node
has suffered `divid` rpcthreads starvation before, so the relay caches and backs
off. A **network map** view hosted here is wanted so the phone app (and DD69) can
embed it as a sandboxed iframe.

**DD69 (the desktop wallet).** The relay is designed to embed in DD69 so a desktop
can relay for its owner's phone. The LoveNode mobile UI is being built in DD69's
visual style; whether they eventually share one UI codebase is an open decision.

**Anything touching PoE / content provenance.** `lovenode-c2pa` carries a Divi
anchor inside a standard C2PA Content Credential (`love.divi.poe`). Note the
**ordering problem**: embedding a manifest changes the file's bytes, so record
whether the anchored hash is pre- or post-manifest (`anchor_mode`).

---

## 10. Stability

`lovenode-core`, `lovenode-sign`, and `lovenode-hdwallet` are the most stable, but
any change must be re-validated against a live node, not just unit tested. The
`KeyStore` trait recently changed to store a **seed** (64 bytes), not a key — if
you wired the old `store`/`load`, update to `store_seed`/`load_seed`. The relay
protocol (`protocol.rs` / `wire.rs`) **may still change** as the wallet features
land; do not hard-depend on its wire format yet. `lovenode-rewards` traits are
stable; the card-game specifics are not defined.

Questions: ask in the LoveNode session, or read `docs/SECURITY.md` (rules),
`docs/PROTOCOL.md` (phone↔relay), `docs/ANDROID-PLAN.md` (plan),
`START-HERE.md` / `app/HANDOFF-JAMES.md` (launching the app).
