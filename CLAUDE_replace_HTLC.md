# Replacing zfairexchange.sol's HTLC with an Adaptor-Signature / Verifiable-Encryption Scheme

Design exploration (prof-suggested direction) for replacing the current HTLC hashlock
mechanism in `zfairexchange.sol` with a discrete-log-based adaptor-signature construction
applied directly to the Waters activation key. Not yet implemented — this is a design doc,
analogous in status to `so-all-of-this-breezy-lampson.md`.

**Objective is genuine multi-chain support**, not just an Ethereum-only simplification —
confirmed explicitly by the user. The construction must work against any chain with a native
ECDSA or Schnorr adaptor-signature scheme (Bitcoin, most EVM chains, etc.), not only chains
with a pairing precompile. See `CLAUDE_AandFD.md` for the paper background this is modeled on.

## Motivation

Current `zfairexchange.sol` requires the chain to evaluate a full BN254 pairing check
(`e(...) = e(...)`) on-chain to verify a submitted `(sk1,sk2,sk3)` — see "Waters activation key" in `CLAUDE_crypto.md`. This ties ORBIT to chains with a pairing precompile
(effectively just Ethereum/EVM via `alt_bn128`).

Professor's suggestion: replace the on-chain pairing check with an **adaptor-signature-style
verifiable encryption** of `sk3`. The pairing math moves entirely off-chain (checked by the
recipient before they lock funds); the on-chain contract only needs to enforce a generic
"pay out to whoever reveals the discrete log of `Y`" condition — the same primitive behind
Bitcoin/Monero-style atomic swaps ("scriptless scripts").

## Background reading

- Tas et al., *Atomic and Fair Data Exchange via Blockchain* (local copy:
  `Atomic and Fair Data.pdf`, summarized in `CLAUDE_AandFD.md` — read that instead of the PDF)
  — Fair Data Exchange (FDE) protocol; the Bank/Alice flow below is modeled directly on this
  paper's Ethereum protocol (§4.2: server posts commitment → sends encrypted payload + proof
  off-chain → client locks funds → server reveals decryption key on-chain → client decrypts)
  and, for the multi-chain generalization, its Bitcoin/adaptor-signature protocol (Appendix B).
- Aumayr et al., *Generalized Channels from Limited Blockchain Scripts and Adaptor
  Signatures* (local copy: `Generalized Channels.pdf`) — formal adaptor signature syntax
  (`pSign`/`pVrfy`/`Adapt`/`Ext`), ECDSA-based construction (Fig. 5), Schnorr-based
  construction (Appendix B, Fig. 8).

## Core idea: ElGamal-encrypt sk3 under an adaptor statement

Waters activation key recap (BN254 Type-3 pairing, see `CLAUDE_crypto.md`):
`sk1 = g^α·H(tag)^r ∈ G1`, `sk2 = g^r ∈ G1`, `sk3 = g2^r ∈ G2`.

Only `sk3` needs protection — it's the component the pairing check isolates against `g2`.
`sk1`, `sk2` can be sent in the clear.

### The two-hop witness fix (resolves the group-mismatch problem below)

An adaptor signature's statement `Y` must be a discrete-log statement *in the same group as the
target chain's own signature scheme* (secp256k1 for Bitcoin/most EVM ECDSA, whichever curve for
Schnorr) — see `CLAUDE_AandFD.md`'s adaptor-signature section. `sk3` lives in BN254 `G2`, fixed
by Waters IBE. These are different groups, so a single `Y = g^x` cannot serve both as "the
on-chain adaptor statement" and "the ElGamal public key masking `sk3`" the way an earlier draft
of this doc assumed.

Fix: **one secret scalar `x`, hashed into two independent public commitments:**

```
Y_chain  := x · G_chain              (adaptor statement, native to the target chain's own
                                       signature curve — e.g. secp256k1 for Bitcoin/EVM-ECDSA)
Y_bn254  := g2^(H(x) mod r)          (VECK "public key", in G2, r = BN254 scalar field order)
```

Both are published by the Bank up front. `Y_chain` is what the target chain's adaptor-signature
machinery (§B.2 of `CLAUDE_AandFD.md`) actually operates on — no BN254, no pairing precompile
needed on-chain at all. `Y_bn254` is used only off-chain, by Alice, to verify the VECK
ciphertext before she locks any funds. Once the Bank reveals `x` on-chain (via `Adapt`/`Extract`
on the adaptor signature), Alice recovers `H(x) mod r` and can decrypt — see Step 5 below.

**ElGamal ciphertext of sk3**, masked additively (group operation) under `Y_bn254` (no need for
exponential ElGamal since `sk3` is already a group element, not a scalar):
```
c1 := g2^b                (fresh random b)
c2 := Y_bn254^b · sk3
```
Both `Y_bn254`, `c1`, `c2`, `sk3` live in `G2` — this part is group-type-consistent and its
round trip (mask with a known `x`, later decrypt with it) is **confirmed working in code**, see
`thesis_log/elgamal-sk3-veck.md`, Step 1 (`server/poc_adaptor_sig/src/bin/step1_baseline_elgamal.rs`).

**Verification identity — corrected, still being validated (do not treat as settled).** An
earlier version of this doc claimed `e(s3,g2) = e(Y_bn254,c1)^{-1}·e(c2,g2)`, which does **not**
type-check: BN254 here is a Type-3 asymmetric pairing (`e: G1 × G2 → GT`, confirmed by every
pairing call in `server/rustcode/src/lib.rs`), and `Y_bn254`, `c1` both live in `G2` — there is
no defined `e(G2, G2)` operation, and no efficient map from `G2` to `G1` (that asymmetry is the
whole point of using a Type-3 curve). See `thesis_log/elgamal-sk3-veck.md`'s first 2026-08-12
entry for the full writeup of this bug and why it went unnoticed until implementation.

**Current hypothesis (not yet fully confirmed):** publish a *second*, independent commitment to
the same secret `x` — this time in `G1`: `Y_G1 := g^x`. Then, using only public values
(`c1`, `c2`, `Y_G1`, `g`, `sk2`, `param.g2`), bilinearity gives:
```
e(g, c2) = e(g, Y_bn254^b) · e(g, sk3) = e(Y_G1, c1) · e(g, sk3)
  ⇒  e(g, sk3) = e(g, c2) · e(Y_G1, c1)^{-1}
```
which lets Alice check Waters check 1 (`e(sk2,g2) == e(g,sk3)`) as
`e(sk2,g2) == e(g,c2)·e(Y_G1,c1)^{-1}` — computable entirely from public values, without ever
learning `sk3` or `x`. This is Step 2 of Part A, not yet implemented/confirmed.

**Known open risk:** Waters check 2 (`e(g_alpha,g2_beta)·e(h_tag,sk3) == e(sk1,g2)`) may **not**
reduce the same way — the trick above only eliminates `x` from pairings whose `G1` argument is
`g` itself (because `Y_G1 = g^x`, so `e(g,·)^x = e(Y_G1,·)`); `h_tag` is an independent `G1`
generator unrelated to `g`, so `e(h_tag,·)^x` can't obviously be rewritten the same way without
also publishing `h_tag^x` (or a per-tag commitment), which the Bank can't precompute since
`h_tag` depends on the recipient's tag. If this doesn't resolve cleanly, the full
verifiable-encryption property may need a proper NIZK (e.g. Groth-Sahai proofs — literally
designed for proving pairing-product equations about committed group elements) rather than a
one-shot pairing trick. Track resolution in `thesis_log/elgamal-sk3-veck.md`.

## Full protocol (Bank ↔ Alice)

Modeled on the Atomic & Fair Data paper's FDE flow, Bank = server, Alice = client, "data" =
`sk3`:

1. **Bank → Alice (off-chain):** `sk1`, `sk2` in the clear, ElGamal ciphertext
   `(c1,c2) = (g2^b, Y_bn254^b·sk3)`, and the two public commitments `Y_chain = x·G_chain`,
   `Y_bn254 = g2^(H(x))`.
2. **Alice verifies** the Waters equations using the identity above (with `Y_bn254`) —
   confirms the hidden `sk3` is well-formed without decrypting it. dmk is still dormant
   (matches ORBIT's Issuance phase).
3. **Alice locks payment on-chain**, using `Y_chain` as the adaptor statement in a bonding
   transaction shaped like `CLAUDE_AandFD.md`'s §B.2 Bitcoin construction — i.e. spending the
   locked funds before the timelock requires **both** an adaptor signature under `Y_chain` and
   the Bank's own ordinary signature (see the anti-frontrunning note in `CLAUDE_AandFD.md`;
   this is the two-signature fix the original single-signature `withdraw()` design lacked).
4. **Bank claims payment** by computing `σ ← Adapt(pk_σ, σ̂, x)` and broadcasting it alongside
   its own ordinary signature on the same spending transaction — the chain only ever sees an
   ordinary-looking adaptor-signed transaction, not `(sk1,sk2,sk3)` or any BN254 material.
5. **Alice extracts `x`** from the on-chain transaction (`Extract`, in adaptor-signature
   terms), computes `H(x) mod r`, then `c1^{H(x)} = g2^{b·H(x)} = Y_bn254^b`, then:
   ```
   sk3 = c2 / Y_bn254^b = c2 · c1^{-H(x)}
   ```
   Alice now holds a valid `(sk1, sk2, sk3)` — dmk activated.

## Re-delegation for free (Alice → Bob)

Once Alice holds `sk3` in the clear (post-Step 5), she can play the Bank's role for Bob using
the identical primitive:

1. Pick fresh `b'` and a fresh secret `x_Bob` (known only to Bob), publishing the same
   two-hop pair: `Y_Bob,chain = x_Bob·G_chain` and `Y_Bob,bn254 = g2^(H(x_Bob))`.
2. Send Bob `sk1`, `sk2`, and `(c1', c2') = (g2^{b'}, Y_Bob,bn254^{b'}·sk3)`.
3. Bob verifies (Step 2 above), locks payment against `Y_Bob,chain` (same two-signature
   bonding-transaction shape as Step 3 above), and once his transaction reveals `x_Bob`,
   decrypts `sk3` the same way Alice did.

This replaces the current GS-circuit-based offline re-delegation (89 AndroidKeyStore ECDH ops since the 88-bit tag change, see "GS — the re-delegation circuit" in `CLAUDE_crypto.md`) with the same atomic-fair-exchange primitive
used for activation. It's cryptographically equivalent to today's "Option A" (Bob reuses
Alice's exact `(sk1,sk2,sk3)`), except the handoff becomes atomic and fair by construction —
Bob can't be cheated out of a decryptable `sk3` without Alice getting paid, and vice versa —
rather than depending on the server to honestly mediate `/api/redelegate`.

## Consequence: chain generalization

Because the pairing check moves entirely off-chain (Alice/Bob verify it themselves before
locking funds) and the on-chain adaptor statement `Y_chain` lives in the target chain's own
native curve (not BN254), the on-chain contract's job shrinks to a generic "pay out to whoever
produces a valid adaptor-signed spend under `Y_chain`" condition — exactly
`CLAUDE_AandFD.md` §B.2's Bitcoin bonding transaction. This is **not** tied to a
pairing-supporting chain; it only needs the target chain's native signature scheme to support
an ECDSA or Schnorr adaptor-signature construction, which covers most major chains (Bitcoin,
most EVM chains via secp256k1-ECDSA, Taproot/Schnorr chains), not just EVM ones with an
`alt_bn128` precompile. **This is the actual objective — genuine multi-chain support — not an
Ethereum-only simplification.**

## Implementation plan

### Part A — crypto-only proof of concept (no chain, no app)

Standalone Rust test in `server/rustcode` proving the full two-hop-witness loop works, before
touching any blockchain or Android code:

1. Generate a Waters activation key `(sk1, sk2, sk3)` as `garble_waters` already does.
2. Pick a random `x`; compute `Y_chain = x·G_secp256k1` (use `k256` or similar — this is just
   ordinary scalar multiplication, no adaptor signature yet) and `Y_bn254 = g2^(H(x) mod r)`.
3. Mask `sk3`: `(c1, c2) = (g2^b, Y_bn254^b · sk3)`.
4. Verify the bilinear identity `e(sk3,g2) = e(Y_bn254,c1)^{-1}·e(c2,g2)` holds.
5. "Reveal" `x` (simulate the on-chain step — no actual chain involved yet), recompute
   `H(x) mod r`, decrypt `sk3' = c2 · c1^{-H(x)}`, assert `sk3' == sk3`.
6. Assert the recovered `(sk1, sk2, sk3')` still passes both existing Waters pairing checks
   (`e(g,sk3)==e(sk2,g2)` and the main verification equation — see "Waters activation key" in `CLAUDE_crypto.md`).

This is the step with actual research risk — confirms the two-hop witness (one secret scalar,
two unrelated group commitments) is sound before any chain-specific work starts. Zero
blockchain/Android dependency; testable standalone.

### Part B — one concrete adaptor-signature instantiation, on a real chain

Once Part A confirms the VECK side works, implement one full adaptor-signature bonding
transaction for real:

- Recommended: **ECDSA-adaptor on secp256k1** (Aumayr et al., *Generalized Channels* Fig. 5 —
  well-specified, existing Rust crates for ECDSA adaptor signatures exist, and secp256k1 is
  native to both Bitcoin and most EVM chains, so this single instantiation demonstrates
  multi-chain-readiness without committing to Bitcoin Script specifically).
  Schnorr-adaptor (Appendix B, Fig. 8 of the same paper) is the cleaner construction and matches
  Bitcoin Taproot directly, but has less tooling support outside Bitcoin-specific libraries —
  fall back to it only if a Bitcoin-specific demo becomes the priority.
- Implement `pSign`/`pVerify`/`Adapt`/`Extract` for the chosen scheme.
- Build the two-signature bonding transaction shape from `CLAUDE_AandFD.md` §B.2 (adaptor sig
  + Bank's ordinary sig required together) — either on an actual testnet (Bitcoin testnet, or a
  secp256k1-ECDSA-capable EVM testnet) or a local simulated ledger if standing up chain infra
  is its own detour better deferred.
- Confirm the anti-frontrunning property holds: a party who sees the pre-signature cannot
  extract the witness or redirect funds before the Bank's real spend confirms.

### Part C — wire into ORBIT

- Add this as a **new path alongside** (not replacing) the existing `zfairexchange.sol` +
  pairing-check flow, so the current working Waters/RDelegate demo never breaks.
- Server: new endpoint(s) analogous to `/api/delegatedpresig`/`/api/pay`, but returning
  `(Y_chain, Y_bn254, c1, c2)` instead of the current unmasked flow, plus whatever pre-signature
  material the chosen adaptor scheme needs from the Bank.
- Compare against the `beta_secret` stripping fix already done for the current design (see `CLAUDE_crypto.md`) — this design likely also removes any need to send `beta_secret`-derived
  material to Alice, since she decrypts a Bank-prepared ciphertext rather than re-deriving
  `sk3` herself. Confirm once Part A/B are working.
- Re-delegation (Alice → Bob) reuses the identical primitive per the "Re-delegation for free"
  section above — no separate mechanism needed.

## Open questions / not yet resolved

- Concrete on-chain script/contract for the bonding transaction on the Part B target chain —
  Bitcoin Script vs. a minimal EVM contract that just checks an ECDSA-adaptor-completed
  signature recovers to the expected address (no pairing precompile needed either way).
- How `x` (and thus `Y_chain`/`Y_bn254`) is generated per-transaction — today's `hashlock` is
  derived deterministically from `denomination`; `x` needs an analogous per-transaction
  generation/derivation scheme, ideally still tied to `denomination` so `Y_chain` can serve the
  same role `hashlock` does today (binding a lock to a specific coin value).
- No Rust/Solidity/on-chain implementation exists yet — Parts A/B/C above are the plan, not yet
  started.