# LoveNode protocol

The conversation between a phone and the relay, plus the one node change required.

## 0. Node prerequisite (must land first)

The stake modifier is held in `CBlockIndex::nStakeModifier` (`divi/src/chain.h`) and is **not
exposed by any RPC** in stock `divid` — verified by searching the source. The relay needs one
small, **read-only** addition:

```
getstakinginfo -> {
  "height":         <int>,      // tip height
  "tip_hash":       <hex>,      // display order
  "stake_modifier": <uint64>,   // CBlockIndex::nStakeModifier of the tip
  "bits":           <uint32>,   // difficulty for the next block
  "tip_time":       <uint32>    // tip block time
}
```

It reads values the node already computes and stores. **No consensus rule changes, no fork.**
This is the cheapest possible unblock and should be reviewed as a read-only patch.

## 1. Registration (phone → relay)

```json
{ "addresses": ["D...", "D..."], "device_token": "<opaque>" }
```

Addresses only. Sending a private key or xpub is a protocol violation — the relay must reject
anything that looks like key material.

## 2. Per-block search (relay, no phone involvement)

Each new block the relay:

1. calls `getstakinginfo` for the tip,
2. loads each registered user's eligible coins — **20+ confirmations** (`nMaturity`) and
   **1+ hour old** (`nMinCoinAgeForStaking`), both read from `chainparams.cpp`,
3. sweeps candidate timestamps from `max(now, tip_time+1)` forward (default 90s window)
   running `lovenode_core::check_win` for each coin.

That is a few dozen hashes per coin per block — negligible server load, and **zero** phone
involvement. This is what keeps phones cool and keeps all mining-like work off device.

## 3. Win notice (relay → phone)

Sent the moment a coin wins. Ingredients only — **never a digest to sign**:

```json
{
  "height": 1234,
  "prev_block_hash": "<hex>",
  "bits": 503382015,
  "stake_modifier": 1234567890,
  "prevout_txid": "<hex>", "prevout_n": 0,
  "value_sats": 100000000000,
  "coinstake_start_time": 1700000000,
  "hashproof_timestamp": 1700003600,
  "mempool_txs_hex": ["...", "..."]
}
```

On receipt the phone **must**:

1. `verify_win()` — recompute the kernel hash and target locally; abort if the claim is false.
2. Build the coinstake transaction itself, spending its own coin back to its own address.
3. Build the block header itself (including hashing `mempool_txs_hex` into the merkle root).
4. Hash the header locally, and sign **that**.

The phone does not need to validate the relay's proposed transactions: a bad one only gets the
block rejected, costing an attempt — never funds.

## 4. Signed stake (phone → relay)

```json
{
  "height": 1234,
  "coinstake_hex": "<raw signed coinstake>",
  "block_signature": "<sig over the header the phone built>",
  "header_version": 4, "header_time": 1700003600,
  "header_nonce": 0, "merkle_root": "<hex>"
}
```

The header fields are echoed so the relay reassembles **exactly** the block that was signed;
any mismatch simply produces an invalid block.

## 5. Outcome (relay → phone)

`Accepted { block_hash }` · `Stale` (someone else won the height — no loss) ·
`Rejected { reason }` (diagnostics only).

On `Accepted`, the relay offers the win to the NFD award hook. Award handling is strictly
downstream and cannot affect block production.

## Timing

Divi targets **60-second blocks**. A win must be signed and returned within roughly a second
or two, or another staker takes the height. This is why the phone holds a live connection
rather than relying on push notifications — push wake-up is seconds-to-never and would lose
most races. It is also why Android (foreground service) can stake with the screen off while
iOS realistically requires the app to be open.

## Validation gate (before any real money)

The Rust win-check must be proven byte-identical to the C++ node:

1. Take a **real staked block** from the chain and its coinstake prevout.
2. Feed the same `(modifier, coinstake start time, prevout, timestamp)` into
   `lovenode_core::stake_hash`.
3. Confirm the hash matches, and that `target_hit` agrees with the block's acceptance.

Reproducing a historical stake end-to-end is the go/no-go proof for the whole project. Until
it passes, treat every number this software produces as unverified.
