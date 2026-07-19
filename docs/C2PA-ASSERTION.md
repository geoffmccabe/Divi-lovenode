# Divi PoE as a C2PA assertion — `love.divi.poe`

How a Divi Proof-of-Existence anchor is carried inside a **C2PA Content
Credential**, so content anchored on Divi verifies in tooling that has never
heard of Divi (Adobe's ecosystem, newsroom workflows, camera firmware).

## Why combine them at all

C2PA **deliberately uses no blockchain** — it signs with X.509 certificates and
Merkle-tree hashing. That is a sound design with one structural weakness:
certificates expire, get revoked, and the authorities behind them eventually go
away. When that happens the signature's meaning decays, and nothing independent
establishes *when* the content existed.

A chain anchor supplies precisely what PKI cannot: a permanent, non-revocable,
independently checkable timestamp. They are complements:

| Question | Answered by |
|---|---|
| Who signed this, and what was done to it? | C2PA (X.509) |
| By when did this content exist? | Divi anchor |
| Is the file unmodified since signing? | C2PA hard binding |
| Can I still check it in 20 years? | Divi anchor |

Note also what **neither** answers: whether the camera saw reality. C2PA proves
chain of custody *after* capture, not truth. Anyone photographing a convincing
screen produces a genuine credential for a fabricated scene. Say so plainly in
any product built on this.

## ⚠ The ordering problem

Embedding a manifest **changes the file's bytes**. So "hash the file → anchor it
→ put the txid in the manifest" is circular: the hash you anchored is of the file
*before* the manifest existed.

There is no clever way out, only two honest ways through — and which one was used
must be recorded, or a verifier cannot know which bytes to reproduce.

### Mode A — `pre_manifest` (anchor first)
1. Hash the original asset → `H`.
2. Anchor `H` on Divi → `txid`.
3. Build the manifest including this assertion (`document_hash = H`, `txid`).
4. Sign and embed.

`document_hash` refers to **the asset as it was before this manifest was
embedded**. Good when the capture app controls the whole pipeline and can retain
the original.

### Mode B — `post_manifest` (anchor the credential)
1. Build and sign the manifest.
2. Hash the **signed** asset → `H`.
3. Anchor `H`; keep the proof alongside, or add a second manifest that takes the
   first as an ingredient.

Nothing is circular and the anchor covers the credential itself. Good for
after-the-fact anchoring of already-signed content.

**The `anchor_mode` field is mandatory.** Guessing is how these systems become
unverifiable.

## Assertion

Label: **`love.divi.poe`** (reverse-DNS, per the C2PA convention for vendor
assertions — it does not squat the reserved `c2pa.*` namespace).

```json
{
  "version": 1,
  "chain": "divi",
  "network": "main",
  "hash_alg": "sha256",
  "document_hash": "ab...64 hex...",
  "txid": "9046c496...64 hex...",
  "anchor_mode": "pre_manifest"
}
```

| Field | Meaning |
|---|---|
| `version` | Schema version. A verifier must **refuse** versions it does not know rather than guess. |
| `chain` | `"divi"`. |
| `network` | `"main"`, `"testnet"` or `"regtest"`. |
| `hash_alg` | `"sha256"` (the only value defined). |
| `document_hash` | The hash that was anchored, per `anchor_mode`. |
| `txid` | The Divi transaction carrying the anchor. |
| `anchor_mode` | `pre_manifest` or `post_manifest`. |

### Deliberately absent: block height and time

They are **not** stored. They are unknown when the manifest is signed, and a
guessed or stale value is worse than none. A verifier resolves them from the
chain via `txid`, which is authoritative regardless.

## Verifying

1. **Read the manifest** with any C2PA tool. Standard validation (signature,
   hard binding) is unchanged — Divi-unaware tools still work, they simply see
   one assertion they do not interpret.
2. **Fetch the transaction** named by `txid` and locate its OP_META output.
3. **Parse the DVXP record** (`docs/POE-NFT-RECORD-FORMAT.md`, type `0x01`) and
   confirm the anchored hash equals `document_hash`. This is the step that turns
   *"the manifest claims an anchor"* into *"the anchor is really there"* — a
   manifest without it proves nothing about the chain.
4. **Read the block time** as the proven-existed-by timestamp.
5. **Reproduce `document_hash`** from the asset according to `anchor_mode`.

Steps 1–4 are implemented in this crate ([`verify_against_record`]); step 2 needs
chain access, which the relay or any node provides.

### The attack this must stop
A Content Credential pointing at a **real** transaction that anchors *somebody
else's* content. Step 3 catches it; skipping it makes the credential decorative.
There is a test for exactly this case.

## Implementation status

- ✅ Assertion schema, build/parse, structural validation
- ✅ On-chain DVXP record parsing and cross-check
- ⬜ Embedding and signing the manifest — use the official
  [`c2pa`](https://crates.io/crates/c2pa) crate (`contentauth/c2pa-rs`, Adobe /
  CAI). Not reimplemented here; there is no reason to write a second C2PA.

### The certificate dependency, stated up front
Embedding requires an **X.509 signing certificate**. Self-signed certificates
work for development, but for a credential that verifies in other people's tools
the certificate must chain to a CA on the C2PA trust list. That is a real
procurement and cost item, not a coding task — budget for it before promising
interoperable credentials.

## Prior art worth knowing

**Numbers Protocol** already does blockchain-anchored C2PA and is cited by
Adobe's Content Authenticity Initiative as a reference implementation;
**Starling Lab** used related tooling for Reuters' *78 Days* election archive.
This space has a credible incumbent. The sensible position for Divi is
interoperability — anchored content that reads correctly in existing tools —
rather than competing to own content provenance.
