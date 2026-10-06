# ElGamal-in-G2 VECK for sk3

Tracks Part A of `CLAUDE_replace_HTLC.md`: whether the Waters activation key's `sk3`
component (∈ `G2`, BN254) can be hidden behind a verifiable encryption scheme that (a) lets a
recipient check its correctness before locking payment, and (b) still yields a working `sk3`
once a revealed scalar decrypts it.

## 2026-08-12 — Group-type inconsistency found in the original design-doc derivation

**Attempt:** Before writing code, re-derived `CLAUDE_replace_HTLC.md`'s verification identity
`e(s3, g2) = e(Y, c1)^{-1} · e(c2, g2)` carefully against the actual pairing engine used in
this codebase (`Bn254::pairing`, an asymmetric Type-3 pairing `e: G1 × G2 → GT`, confirmed by
every existing call site in `server/rustcode/src/lib.rs`, e.g. `water_derive_ak`).

**Result:** Failure (of the original derivation, not of the underlying idea) — caught before
any code was written.

**Details:** The original identity requires `e(Y, c1)` to be a valid pairing call. But the
ciphertext construction (`c1 := g2^b`, `c2 := Y^b · sk3`) only type-checks if `Y`, `c1`, `c2`,
and `sk3` all live in the *same* group (`G2`), since `Y^b · sk3` is a group operation between
two elements — and `Bn254::pairing` has no `G2 × G2` overload; Type-3 pairings deliberately
have no efficient map between `G1` and `G2` (that asymmetry is the XDH assumption the whole
scheme's hardness could depend on). So `e(Y, c1)` with both arguments in `G2` is not an
operation the pairing engine (or the underlying math) defines.

**Why:** The original derivation was done algebraically/notationally, treating `e(·,·)` as if
it accepted either argument order or either group — true for symmetric (Type-1) pairings, not
for the Type-3 BN254 pairing this codebase actually uses everywhere else (`e(sk2,g2) ==
e(g,sk3)`, always `pairing(G1_element, G2_element)`, never `pairing(G2, G2)`). This is exactly
the kind of error Part A exists to catch before it's load-bearing in Part B/C.

**Implication:** The masking/decryption side (baseline ElGamal-in-G2, both `Y`, `c1`, `c2` in
`G2`) is unaffected and still sound — see the next entry. What breaks is the *verify-before-
decrypting* property: a second, independent public commitment to the same secret in `G1`
(`Y_G1 := g^x`) is needed to make any pairing-based check computable without revealing `x`,
since only pairing calls of the shape `(G1 element, G2 element)` are defined. This still needs
to be built and tested — see Step 2 (not yet attempted as of this entry).

## 2026-08-12 — Step 1: baseline ElGamal-in-G2 round trip on a real sk3

**Attempt:** Implemented the group-type-correct floor only: mask a real Waters `sk3` (derived
via the same formulas as `water_derive_ak` in `server/rustcode/src/lib.rs`) with plain
ElGamal-in-`G2` (`Y := g2^x`, `c1 := g2^b`, `c2 := Y^b · sk3`, all in `G2`), reveal `x`
directly (no pairing trick, no secp256k1 yet), decrypt, and check the recovered `sk3` still
passes both Waters pairing equations. Implemented as a new standalone Rust crate
`server/poc_adaptor_sig/` (deliberately isolated from `rustcode`'s PyO3/extension-module build,
so it's a plain `cargo run`, no Python dependency) — `src/bin/step1_baseline_elgamal.rs`.

**Result:** Success.

**Details:** `cargo run --bin step1_baseline_elgamal` — all three assertions passed: (1)
ground-truth key passes both Waters checks pre-masking, (2) `c2 - c1*x == sk3` exactly
(decryption round-trips), (3) the recovered `(sk1, sk2, sk3)` still passes both Waters pairing
checks post-decryption.

**Why:** Expected — this is standard ElGamal encryption of a group element, using only group
operations (no pairing needed for enc/dec itself, only for the *later* verify-before-decrypt
step this baseline doesn't attempt yet).

**Implication:** Confirms the "floor" is solid: masking `sk3` and recovering it via a later-
revealed scalar is safe and lossless. Does **not** yet confirm the actually load-bearing
property for `CLAUDE_replace_HTLC.md`'s protocol — that Alice can verify correctness *before*
locking funds, without seeing `sk3` or `x`. That's Step 2, using the two-commitment fix noted
in the entry above (`Y_G1 := g^x` alongside the existing `Y := g2^x`).

**Open question carried into Step 2:** Waters check 1 (`e(sk2,g2)==e(g,sk3)`) looks reducible
to a pairing identity computable from `(c1, c2, Y_G1)` alone via bilinearity. Waters check 2
(the one involving `h_tag`) may **not** reduce the same way, since `h_tag` is an independent
`G1` generator unrelated to `g` — the same trick eliminates `x` only for pairings whose `G1`
argument is `g` itself. If check 2 doesn't reduce cleanly, a full verifiable-encryption proof
may need something closer to Groth-Sahai proofs rather than a one-shot pairing trick. Not yet
confirmed either way in code.
