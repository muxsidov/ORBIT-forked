# Replacing zfairexchange.sol's HTLC with an Adaptor-Signature / Verifiable-Encryption Scheme

Design exploration (prof-suggested direction) for replacing the current HTLC hashlock
mechanism in `zfairexchange.sol` with a discrete-log-based adaptor-signature construction
applied directly to the Waters activation key. Not yet implemented — this is a design doc,
analogous in status to `so-all-of-this-breezy-lampson.md`.

## Motivation

Current `zfairexchange.sol` requires the chain to evaluate a full BN254 pairing check
(`e(...) = e(...)`) on-chain to verify a submitted `(sk1,sk2,sk3)` — see "Waters Activation
Key Structure" in `CLAUDE.md`. This ties ORBIT to chains with a pairing precompile
(effectively just Ethereum/EVM via `alt_bn128`).

Professor's suggestion: replace the on-chain pairing check with an **adaptor-signature-style
verifiable encryption** of `sk3`. The pairing math moves entirely off-chain (checked by the
recipient before they lock funds); the on-chain contract only needs to enforce a generic
"pay out to whoever reveals the discrete log of `Y`" condition — the same primitive behind
Bitcoin/Monero-style atomic swaps ("scriptless scripts").

## Background reading

- Tas et al., *Atomic and Fair Data Exchange via Blockchain* (local copy:
  `Atomic and Fair Data.pdf`) — Fair Data Exchange (FDE) protocol; the Bank/Alice flow below
  is modeled directly on this paper's Fig. 1 (server posts commitment → sends encrypted
  payload + proof off-chain → client locks funds → server reveals decryption key on-chain →
  client decrypts).
- Aumayr et al., *Generalized Channels from Limited Blockchain Scripts and Adaptor
  Signatures* (local copy: `Generalized Channels.pdf`) — formal adaptor signature syntax
  (`pSign`/`pVrfy`/`Adapt`/`Ext`), ECDSA-based construction (Fig. 5), Schnorr-based
  construction (Appendix B, Fig. 8).

## Core idea: ElGamal-encrypt sk3 under an adaptor statement

Waters activation key recap (BN254 Type-3 pairing, see `CLAUDE.md`):
`sk1 = g^α·H(tag)^r ∈ G1`, `sk2 = g^r ∈ G1`, `sk3 = g2^r ∈ G2`.

Only `sk3` needs protection — it's the component the pairing check isolates against `g2`.
`sk1`, `sk2` can be sent in the clear.

**Adaptor statement:** `Y := g^x` for a secret scalar `x` (this replaces the HTLC's SHA-256
`hashlock`; `Y` is a discrete-log-based commitment to `x`, the "preimage").

**ElGamal ciphertext of sk3**, masked multiplicatively (no need for exponential ElGamal since
`sk3` is already a group element, not a scalar):
```
c1 := g2^b                (fresh random b)
c2 := Y^b · sk3
```

**Verification identity** (confirmed algebraically — bilinearity, holds for any b, Y, sk3):
```
e(s3, g2) = e(Y, c1)^{-1} · e(c2, g2)
```
Derivation: `e(Y, g2^{-b}) · e(Y^b·s3, g2) = e(Y,g2)^{-b} · e(Y,g2)^{b} · e(s3,g2) = e(s3,g2)`.

This means: **`e(sk3, g2)` — exactly what the Waters pairing check needs — is computable from
`(Y, c1, c2, g2)` alone, without ever learning `sk3`.** The recipient plugs this into the
existing Waters equations (`e(vk1,vk2)·e(H(m),sk2) = e(sk3,g2)` in the professor's generic
notation, corresponding to the two checks under "Waters Activation Key Structure" in
`CLAUDE.md`) and confirms they hold — while `sk3` stays hidden. This is the pre-signature /
verifiable-encryption stage: checkable, but not yet usable.

## Full protocol (Bank ↔ Alice)

Modeled on the Atomic & Fair Data paper's FDE flow, Bank = server, Alice = client, "data" =
`sk3`:

1. **Bank → Alice (off-chain):** `sk1`, `sk2` in the clear, ElGamal ciphertext
   `(c1,c2) = (g2^b, Y^b·sk3)`, and the statement `Y = g^x`.
2. **Alice verifies** the Waters equations using the identity above — confirms the hidden
   `sk3` is well-formed without decrypting it. dmk is still dormant (matches ORBIT's
   Issuance phase).
3. **Alice locks payment on-chain**, referencing `Y` as the lock condition (replaces
   `newContract`'s `hashlock` parameter).
4. **Bank claims payment by revealing `x`** in its on-chain withdrawal transaction — much
   smaller footprint than today's `withdraw()`, which reveals the full `(sk1,sk2,sk3)`.
5. **Alice extracts `x`** from the on-chain transaction (the `Ext` step, in adaptor-signature
   terms), computes `c1^x = g2^{bx} = Y^b`, then:
   ```
   sk3 = c2 / Y^b = c2 · c1^{-x}
   ```
   Alice now holds a valid `(sk1, sk2, sk3)` — dmk activated.

## Re-delegation for free (Alice → Bob)

Once Alice holds `sk3` in the clear (post-Step 5), she can play the Bank's role for Bob using
the identical primitive:

1. Pick fresh `b'` and a fresh statement `Y_Bob = g^{x_Bob}` (`x_Bob` known only to Bob, to be
   revealed via Bob's own on-chain transaction to Alice).
2. Send Bob `sk1`, `sk2`, and `(c1', c2') = (g2^{b'}, Y_Bob^{b'}·sk3)`.
3. Bob verifies (Step 2 above), locks payment against `Y_Bob`, and once his transaction
   reveals `x_Bob`, decrypts `sk3` the same way Alice did.

This replaces the current GS-circuit-based offline re-delegation (57 AndroidKeyStore ECDH
ops, see "GS Circuit" section in `CLAUDE.md`) with the same atomic-fair-exchange primitive
used for activation. It's cryptographically equivalent to today's "Option A" (Bob reuses
Alice's exact `(sk1,sk2,sk3)`), except the handoff becomes atomic and fair by construction —
Bob can't be cheated out of a decryptable `sk3` without Alice getting paid, and vice versa —
rather than depending on the server to honestly mediate `/api/redelegate`.

## Consequence: chain generalization

Because the pairing check moves entirely off-chain (Alice/Bob verify it themselves before
locking funds), the on-chain contract's job shrinks to a generic "pay out to whoever reveals
`x` such that `Y=g^x`" condition. This is no longer tied to a pairing-supporting chain —
it only needs the target chain's native signature scheme to support an adaptor-signature
construction (ECDSA or Schnorr), which covers most major chains, not just EVM ones with an
`alt_bn128` precompile.

## Open questions / not yet resolved

- Concrete on-chain encoding: how does the contract check "`x` was revealed and `Y=g^x`"
  without a generic EC-exponentiation opcode? (Practical answer: embed the reveal inside an
  ordinary ECDSA/Schnorr transaction signature per the adaptor-signature construction, rather
  than a bare custom check — see Fig. 5 / Fig. 8 in `Generalized Channels.pdf` if revisited.)
- How `Y = g^x` is generated and by whom for each transaction (today's `hashlock` is derived
  deterministically from `denomination`; `x` would need a similar per-transaction generation
  scheme).
- Group compatibility: `sk3 ∈ G2` (BN254) — does `Y`, `c1` also need to live in G2? (Yes, per
  the derivation above — `Y` must be a G2 element for the pairing identity to hold, meaning
  `x` is a discrete log with respect to a G2 generator, not Alice's AndroidKeyStore P-256 key
  directly. AndroidKeyStore key would need to derive/wrap `x` some other way.)
- Not yet compared against the `beta_secret` stripping problem (see `CLAUDE.md`) — does this
  design also remove the need to send `beta_secret` to Alice? (Plausibly yes, since Alice no
  longer needs to *re-derive* `sk3` from master secret material — she decrypts a
  bank-prepared ciphertext instead. Worth revisiting once this design is developed further.)
- No Rust/Solidity implementation sketch yet — this file is conceptual only.