# CLAUDE_AandFD.md

Reference summary of `Atomic and Fair Data.pdf` (Tas et al., *Atomic and Fair Data Exchange via
Blockchain*). Read this instead of re-reading the PDF for questions about the FDE protocol,
VECK, or the adaptor-signature construction it uses on Bitcoin. Companion to `ORBIT_PAPER.md`
(same "read this, not the PDF" role) — used as the concrete template for
`CLAUDE_replace_HTLC.md`'s multi-chain redesign of ORBIT's HTLC.

## Core idea

**Fair Data Exchange (FDE)**: a client `C` pays a server `S` for a piece of off-chain data,
atomically — `C` gets the data if and only if `S` gets paid. Solved with a **bonding
contract**: `S` proves (via a verifiable-encryption scheme) that a ciphertext it sends `C`
off-chain really does decrypt to the committed data, `C` locks payment on-chain conditioned on
`S` revealing the decryption key, `S` reveals the key on-chain to claim payment, `C` reads the
key back off the chain and decrypts. Two concrete instantiations are given: one using Ethereum
smart contracts directly (§4.2), one using Bitcoin's more limited scripting via **adaptor
signatures** (Appendix B) — the latter is the one relevant to ORBIT's multi-chain goal, since
it shows the same fairness guarantee is achievable without a general-purpose VM or a pairing
precompile.

## Formal syntax (Definition 4.1)

`FDE = (Setup, Com⟨C,S⟩, Vrfy, Exc⟨C,S⟩)`, run relative to a transparent payment environment
`E` (a blockchain):

- `Setup(1^λ) → pp` — public parameters
- `Com⟨C(pp), S(pp, data)⟩ → (com, st_C, st_S)` — `S` commits to `data` without revealing it;
  `com` is posted where `C` can see it
- `Vrfy(pp, com) → 0/1` — anyone can sanity-check the commitment is well-formed
- `Exc⟨C(pp, st_C, tk), S(pp, st_S)⟩ → (data_C, data_S)` — the actual exchange: `C` spends `tk`
  tokens, `S` gets paid `tk` iff `C` gets the correct `data`

**Correctness** (Def 4.2): if both parties are honest, `data_C = data` and `S` receives `tk`.
**Client-fairness** (Def 4.3): a malicious `S` cannot get paid without `C` learning the correct
`data`. **Server-fairness** (Def 4.4): a malicious `C` cannot learn `data` without `S` getting
paid `tk`. Both are atomicity guarantees enforced by the payment environment `E`, not by trust
in the counterparty.

## VECK — Verifiable Encryption under Committed Key

The primitive underneath both instantiations. Roughly `(vk, sk, ct, π) ← Enc(F, com, data)`:
encrypts `data` under a fresh decryption key `sk` (with public counterpart `vk`), and produces
a proof `π` that `ct` is a correct encryption matching the earlier commitment `com` — checkable
via `Verct(com, vk, ct, π) → 0/1` **without knowing `sk`**. Once `sk` is later revealed (by
whatever mechanism the chain enforces), the recipient checks `Verkey(vk, sk) → 0/1` and, if it
holds, computes `Dec(sk, ct) → data`.

This is exactly what ORBIT's ElGamal-in-`G2` masking of `sk3` (see `CLAUDE_replace_HTLC.md`) is
— a VECK instantiation specific to Waters/BN254 secret keys, using the bilinear pairing itself
as the verification circuit instead of a generic SNARK. Nothing in the paper requires a
particular VECK construction; §4.2/Appendix B are generic in `(vk, sk, ct, π)`.

## FDE on Ethereum (§4.2) — smart-contract bonding

1. `S` runs VECK `Enc(F, com, data) → (vk, sk, ct, π)`, posts `vk` on-chain (the "bonding
   contract"), sends `ct`, `π` to `C` off-chain.
2. `C` checks `Verct(com, vk, ct, π)`. If it passes, `C` locks `tk` tokens in the bonding
   contract. The contract pays `S` iff `S` later submits `sk` with `Verkey(vk, sk) = 1`, before
   a timelock; otherwise refunds `C`.
3. `S` checks funds are locked, submits `sk` on-chain before timelock expiry, and is paid.
4. `C` reads `sk` from the chain, computes `data = Dec(sk, ct)`.

Requires the chain to run `Verkey` as a smart-contract predicate — trivial for a
general-purpose VM (EVM), but this is exactly the step that ties ORBIT's current
`zfairexchange.sol` to a pairing-precompile chain (`Verkey` = the Waters pairing check).

## Adaptor signatures (Appendix A.5, Definition A.6)

Defined relative to a signature scheme `Σ = (KeyGen, Sign, Verify)` and a hard relation `R`,
with `(pk_σ, sk_σ) ← KeyGen(1^λ)` and `(Y, y) ∈ R`:

- `σ̂ ← pSign(sk_σ, m, Y)` — pre-sign: a "pre-signature" on `m`, tied to statement `Y`
- `b ← pVerify(pk_σ, m, σ̂, Y)` — deterministic check that `σ̂` is well-formed for `(m, Y)`
- `σ ← Adapt(pk_σ, σ̂, y)` — combine `σ̂` with witness `y` → a full `Σ`-signature `σ` that
  verifies as an ordinary signature (typically under `pk_σ · Y` as the effective key)
- `y ← Extract(σ, σ̂, Y)` — recover the witness `y` from a completed `(σ, σ̂)` pair and `Y`

Security: pre-signature correctness, existential unforgeability (aEUF-CMA), pre-signature
adaptability, **witness extractability** — the last one is what makes this usable as a bonding
mechanism: anyone who sees `σ` appear on-chain can run `Extract` and learn `y`, even though `y`
was never transmitted directly.

**Group constraint (not spelled out explicitly in the paper's syntax box, but true of both the
ECDSA and Schnorr instantiations it references):** `R` must be a discrete-log relation *in the
same group as `Σ`'s keys* — the pre-sign/adapt/extract algorithms manipulate `Y` algebraically
alongside the scheme's own nonce, so `Y` has to be a point on the signature scheme's curve
(secp256k1 for Bitcoin-ECDSA, whichever curve for Schnorr/Taproot). This is the constraint that
matters for ORBIT: `Y` cannot simply be reused as a BN254 `G2` element the way the first draft
of `CLAUDE_replace_HTLC.md` assumed — see that file's Part A for the fix (two independent
commitments to one shared secret, instead of one commitment reused across groups).

## FDE on Bitcoin (Appendix B) — adaptor-signature bonding

**B.1 Preliminaries.** "In the absence of smart contracts, we design a bonding contract on
Bitcoin using adaptor signatures." Relation: `y = sk`, `Y = vk`, language
`L_key = {vk | Verkey(vk, sk) = 1}`. Uses Schnorr-based adaptor signatures (matches Bitcoin's
Taproot/Schnorr signature scheme).

**B.2 Protocol:**

1. Same as the Ethereum §4.2 step 1, except `S` sends both `vk` and the ciphertext `ct` to `C`
   directly (no on-chain `vk` post — Bitcoin has no general contract storage).
2. `C` verifies `ct`/`π`. Creates a Bitcoin bonding transaction: before the timelock, spending
   the locked `tk` requires **two signatures** — one valid under `S`'s ordinary public key
   `pk_S`, and one valid under the adaptor public key `pk_σ · vk`. After timelock expiry, `C`
   alone can reclaim the funds with its own signature.
3. `C` sends a pre-signature on the spending transaction: `σ̂ ← pSign(sk_σ, tx, vk)`, where `tx`
   pays the bonding-contract funds to `S`'s address.
4. If the timelock hasn't expired, funds are correctly locked, and `σ̂` verifies
   (`pVerify(pk_σ, tx, σ̂, vk) = 1`), `S` computes `σ ← Adapt(pk_σ, σ̂, sk)` — using its own
   decryption key `sk` as the adaptor witness — **and separately signs `tx` with its ordinary
   key `sk_S`**, then broadcasts `tx` with **both** signatures attached.
5. `C` extracts `sk ← Extract(σ, σ̂, vk)` from the now-on-chain adapted signature, then decrypts
   `ct` with `sk`.

**Why two signatures, not one (the detail worth keeping):** if the spending transaction only
required the adaptor signature, `C` could see `σ` the moment it lands in the mempool, run
`Extract` immediately, and race `S`'s own broadcast with a *different* transaction that
redirects the funds to `C` before `S`'s original `tx` confirms — `C` would get the data for
free. Requiring `S`'s own ordinary signature on the exact same `tx` closes this: `C` extracting
`sk` early doesn't help, because `C` cannot forge `S`'s ordinary signature to redirect the
payout, and `S`'s broadcast is the only transaction that both pays `S` and carries the adaptor
signature `C` needs to have pre-signed. ORBIT's current single-signature `withdraw()` design in
`zfairexchange.sol` is vulnerable to exactly the naive one-signature version of this race and
needs the same two-signature fix if it moves to an adaptor-signature bonding contract — see
`CLAUDE_replace_HTLC.md` Part A.

## Mapping onto ORBIT (quick reference — full detail in `CLAUDE_replace_HTLC.md`)

| Paper | ORBIT |
|---|---|
| Server `S` | Bank |
| Client `C` | Alice (or Bob, on re-delegation) |
| `data` | `sk3 ∈ G2` (the Waters activation-key component that must stay hidden pre-payment) |
| `vk`, `sk` (VECK) | `Y_bn254 = g2^(H(x))`, and `H(x) mod r` (the ElGamal decryption exponent) |
| `ct`, `π` (VECK) | `(c1, c2) = (g2^b, Y_bn254^b · sk3)`, and the bilinear identity itself
  serves as `π`'s check (`e(sk3,g2) = e(Y_bn254,c1)^{-1}·e(c2,g2)`) |
| Adaptor statement `Y` | `Y_chain = x·G_chain` (secp256k1 or whatever the target chain's
  native signature curve is) |
| Adaptor witness `y` | `x` (a single secret scalar, hashed into `G2` for the VECK side,
  used natively for the chain side) |
| `tk` | locked ETH/BTC/native-asset amount for the denomination |