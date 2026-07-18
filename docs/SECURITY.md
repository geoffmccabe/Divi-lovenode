# LoveNode security contract

LoveNode is aimed at people for whom losing their coins would be genuinely serious. These
rules are not style preferences — breaking any one of them turns "you might not earn tonight"
into "your money is gone."

## 1. The phone constructs everything it signs

Divi's `BlockSigning.cpp` signs `block.GetHash()` with the **staking private key**:

```cpp
key.SignCompact(block.GetHash(), block.vchBlockSig);   // or key.Sign(...) for TX_PUBKEY
```

That is a signature over a bare 32-byte digest. If the relay supplied that digest, a
compromised relay could send the **sighash of a transaction spending the user's coins** and
convert the returned signature into a valid spend — the `(r,s)` pair from a compact signature
re-encodes trivially as a DER transaction signature. Compact vs DER is **not** a safety
barrier; it is the same ECDSA signature in a different wrapper.

**Rule:** the relay sends ingredients only. The phone builds the coinstake transaction and the
block header, hashes them on device, and signs only what it built itself.

This is enforced structurally: [`WinNotice`](../crates/lovenode-relay/src/protocol.rs) has no
field capable of carrying a digest, and `win_notice_carries_no_signable_digest` fails the
build if one is ever added.

## 2. The phone verifies the relay's claim before acting

A relay can lie about a win. `WinNotice::verify_win()` recomputes the kernel hash and the
target locally; if the claim doesn't hold, the phone refuses. A dishonest relay can therefore
only waste attempts, never cause an invalid or harmful signature.

## 3. The phone verifies what its coinstake does

Before signing, the coinstake must be checked to spend **the user's own coin** and pay back to
**the user's own address**. This is the difference between "sign my staking transaction" and
"sign away my balance."

## 4. Keys never leave the device

Generated and stored in iOS Keychain / Android Keystore. Never transmitted, never included in
any protocol message, never backed up to the relay. The relay receives **addresses only** —
never a private key and never an extended private key.

## 5. The relay is untrusted infrastructure

Assume it will one day be compromised, and check that the worst outcome is still only lost
earnings. It holds no keys, cannot move funds, and cannot obtain a signature over bytes of its
choosing. It *can*:

- withhold service (user earns nothing),
- feed stale data (wasted attempts),
- observe which addresses a user stakes (**privacy cost — disclose this to users**).

## 6. The consensus math is byte-exact or it is worthless

`lovenode-core` is a port of `ProofOfStakeCalculator.cpp`. A single wrong byte in the
serialization produces stakes that silently never win, or "wins" the network rejects. Before
any real-money use, cross-check the Rust implementation against a live node
(see [PROTOCOL.md](PROTOCOL.md), "Validation gate") — the same discipline used when Divi's
crypto was moved off OpenSSL: prove identical output, don't assume it.

Hash byte order is a classic trap here: RPC and explorers show transaction ids **reversed**
relative to how they are hashed. The kernel must be fed internal order.
`chain::hash_from_display_hex` is the only place that conversion should happen.

## 7. Awards can never affect staking

The NFD hook runs **after** a block is accepted and its failures are swallowed. A bug or
outage in the card game must never cost a user a block.

## Reporting

Security issues: please open a private report rather than a public issue.
