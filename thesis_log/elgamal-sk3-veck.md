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

## 2026-10-06 — Plan review before Step 2: exponent mismatch, check-2 hint, cross-group gap

**Attempt:** Reviewed `CLAUDE_replace_HTLC.md` Part A against the Step 1 code before writing
Step 2. Paper review only, no code yet.

**Findings:**
- `Y_G1 := g^x` (above) doesn't work alongside `Y_bn254 := g2^(H(x))`: then
  `e(Y_G1, c1) = e(g,g2)^(x·b)` but `e(g, Y_bn254^b) = e(g,g2)^(H(x)·b)`. Both commitments must
  use the same exponent `k`, built on the params' own `param.g`/`param.g2`, not the curve
  generators Step 1 used. Alice checks `e(Y_G1, g2) == e(g, Y_bn254)`.
- The encrypted check 1 `e(sk2,g2) == e(g,c2)·e(Y_G1,c1)^{-1}` equals
  `e(g, c2·c1^{-k}) == e(sk2,g2)`. `e(g,·)` is injective, so the ciphertext decrypts to exactly
  `g2^r` for any `c1`.
- Check 2 doesn't need Groth-Sahai: the hint `T = h_tag^k` (checked via
  `e(T,g2) == e(h_tag,Y_bn254)`) gives `e(h_tag, Dec) = e(h_tag,c2)·e(T,c1)^{-1}`. Hypothesis
  for Step 3.
- **New gap:** nothing ties `Y_chain` (secp256k1, `x`) to `Y_bn254` (BN254, `k`). A Bank can
  get paid for an `x` that doesn't decrypt. With `k = H(x)` proving the link needs a SNARK.
  With `k = x` and `x < 2^252` it's a standard cross-group DLEQ proof. `k = x` recommended.
- The re-delegation section had the roles reversed (Bob knowing `x_Bob` could decrypt without
  paying). The seller (Alice) holds the secret.
- Part A's old step 4 still used the ill-typed identity. Its step 6 was redundant after
  asserting `sk3' == sk3`.

**Implication:** Part A was rewritten as Steps 2–5 in `CLAUDE_replace_HTLC.md`: check 1, check 2
with the hint, the cross-group link, then reveal and decrypt. Every step has negative tests.

## 2026-10-07 — Step 2: Waters check 1 verified on the encrypted sk3

**Attempt:** Implemented the encrypted form of Waters check 1 from public values only, using
the corrected commitments `Y_G1 = param.g^k`, `Y_bn254 = param.g2^k` (one exponent `k`, on
the Waters params' own generators). Alice's verifier checks
`e(Y_G1, g2) == e(g, Y_bn254)` (consistency) and `e(sk2, g2) == e(g, c2) · e(Y_G1, c1)^{-1}`
(check 1), with no access to `k`, `b` or `sk3`.

**Result:** Success. All nine assertions hold.

**Details:** `server/poc_adaptor_sig/src/bin/step2_check1_encrypted.rs` (verifier:
`verify_check1`); shared Waters helpers moved to `server/poc_adaptor_sig/src/lib.rs` (Step 1
left unchanged). Command: `cargo run --release --bin step2_check1_encrypted`, exit 0.
- Accepted: the honest offer (decrypts to `sk3` once `k` is revealed, and the result passes
  both Waters checks); an offer with an arbitrary random `c1` and `c2 = c1^k · sk3` (also
  decrypts to `sk3`).
- Rejected: `c2` with a random G2 element added; `c2` encrypting a different key's `sk3`;
  `Y_G1` with a different exponent than `Y_bn254`; `c2` masked under a different `k` than the
  commitments advertise; all commitments built on `G1::generator()`/`G2::generator()` instead
  of `param.g`/`param.g2` (the Step 1 shortcut).
- PoC randomness is `ark_std::test_rng()`.

**Why:** `e(g, c2) · e(Y_G1, c1)^{-1} = e(g, c2 · c1^{-k}) = e(g, Dec)`, and `e(g, ·)` is
injective on G2, so the check fixes `Dec = g2^r` where `sk2 = g^r`. Nothing about `c1` is
assumed, which the arbitrary-`c1` case confirms. The consistency check is what makes the
rewrite valid: without it a Bank could advertise a `Y_G1` whose exponent differs from the
one actually masking `c2`.

**Implication:** Q1 of `multichain-feasibility.md` is half answered: check 1 works
encrypted. Check 1 alone does **not** make the key valid: a Bank can pick any `r'`, send
`sk2' = g^{r'}` and encrypt `g2^{r'}`, and it passes. Only check 2 ties `r` to `sk1` and the
tag, so Step 3 (hint `T = h_tag^k`) is required, not optional. Its negative tests must include
exactly this case: consistent `(sk2', sk3')` paired with a wrong or mismatched `sk1`.

## 2026-10-07 — Step 3: Waters check 2 verified on the encrypted sk3 via the hint T = h_tag^k

**Attempt:** Extended the Step 2 verifier with Waters check 2. The Bank adds a per-tag hint
`T = h_tag^k`. Alice computes `h_tag` herself from her own tag and checks, in addition to the
consistency check and the encrypted check 1:
`e(T, g2) == e(h_tag, Y_bn254)` (hint) and
`e(sk1, g2) == e(g_alpha, g2_beta) · e(h_tag, c2) · e(T, c1)^{-1}` (check 2).

**Result:** Success. All eleven assertions hold. The open risk recorded on 2026-08-12 (check 2
might need Groth-Sahai proofs) does not materialise: plain pairings plus one extra G1 point
suffice.

**Details:** `server/poc_adaptor_sig/src/bin/step3_check2_encrypted.rs` (verifier: `verify`,
Bank side: `make_offer`). Command: `cargo run --release --bin step3_check2_encrypted`, exit 0.
- Accepted: the honest offer, which decrypts to `sk3` once `k` is revealed and passes both
  Waters checks.
- Rejected, hint: random `T`; `T` computed for a different tag (`001_043` instead of
  `001_042`); `T` under a different exponent than `Y_bn254`.
- Rejected, key: the Step 2 gap (a self-consistent `(g^{r'}, g2^{r'})` with the original `sk1`;
  the test first confirms this case *passes* check 1 alone, then that the full verifier rejects
  it); tampered `sk1`; a fully valid key honestly encrypted for a different tag; tampered `c2`.
- Verifier cost: 11 pairings, one of them (`e(g_alpha, g2_beta)`) constant and cacheable;
  about 12–13 ms per verification (release build, WSL, three single runs). Bank-side extra
  cost over Step 2: one G1 scalar multiplication for `T`.

**Why:** The hint check `e(T, g2) == e(h_tag, Y_bn254) = e(h_tag^k, g2)` forces `T = h_tag^k`
exactly, since `e(·, g2)` is injective on G1. Then
`e(h_tag, c2) · e(T, c1)^{-1} = e(h_tag, c2 · c1^{-k}) = e(h_tag, Dec)`, so the encrypted
check 2 is literally Waters check 2 on the decrypted value. The hint is needed only because
`h_vec`/`h_0` exist in G1 alone. It works because the tag is known when the Bank prepares the
offer, which holds both at issuance and in the Alice → Bob resale (where `T'` uses the
key's own tag).

**Implication:** Q1 of `multichain-feasibility.md` is answered yes: a recipient can fully
validate an encrypted Waters key before paying, without the chain and without heavyweight
proofs. One caveat for the security chapter: publishing `Y_G1 = g^k` makes DDH in G2 easy for
this ciphertext (`e(Y_G1, c1) == e(g, Y_bn254^b)` is testable), so the hiding of `sk3` rests on
a computational assumption (computing `g2^{kb}` from `g^k, g2^k, g2^b`, a co-CDH-style
problem), not on DDH/IND-CPA. Since `e(g, sk3) = e(sk2, g2)` is already public, only one-wayness
is meaningful here anyway; this still needs to be stated and argued properly. Next: Step 4, the
cross-group link between `Y_chain` and `Y_bn254` (Q2).

## 2026-10-07 — Step 4: cross-group DLEQ links the on-chain secret to the encrypted key (k = x)

**Attempt:** Fixed `k = x` with `x < 2^252` and implemented a non-interactive cross-group
discrete-log equality proof that `Y_chain = x·G` (secp256k1) and `Y_G1 = g^x` (BN254 G1) share
the same `x`. Alice's verifier is the Step 3 verifier plus the proof check. Step 3's consistency
check already ties `Y_G1` to `Y_bn254`, so a passing offer means the `x` revealed on-chain
decrypts `sk3`.

**Result:** Success. All 11 cases pass (`test-results.md`, run 2026-10-07 (2)), and Steps 1–3
still pass after the library change.

**Details:** `server/poc_adaptor_sig/src/dleq.rs` (generic over two short-Weierstrass curves),
`src/veck.rs` (Step 3 offer/verifier moved into the library for reuse),
`src/bin/step4_cross_group_link.rs`. New dependencies: `ark-secp256k1 0.5`, `ark-serialize 0.5`,
`sha2 0.10`. Construction:
- Bit decomposition: for each of 252 bits, Pedersen commitments `C_a = b·G + r_a·H` (secp256k1,
  standard generator) and `C_b = b·g + r_b·H'` (BN254 G1, Waters `param.g`). `H`, `H'` are
  derived by try-and-increment SHA-256 hashing to the curve, so their discrete logs are unknown.
- Blinders sum to zero with weights `2^i`, so `Σ 2^i·C_a = Y_chain` and `Σ 2^i·C_b = Y_G1`.
- Per bit, a CDS OR-proof that both commitments open to 0 or both open to 1, with one shared
  128-bit challenge for the two groups (smaller than both group orders) and an XOR split
  between the branches. One Fiat-Shamir SHA-256 challenge covers the statement and all
  commitments and announcements.
- Proof: 55.4 KB. Prove and verify each take about 230 ms (release, single runs).
- The gap case (4.1) was run first: an offer encrypted under `x'` passes the Step 3 verifier,
  and revealing the chain's `x` does not decrypt it. It is rejected once the proof is required.

**Why:** The sums pin `x` only modulo each group's order, and those orders differ. The bit
proofs pin every digit to {0, 1}, so both groups hold the same integer `x < 2^252`, which is
below both orders. Case 4.8 checks exactly this: digits 2 and −1 keep both sums correct and
are rejected only by the bit proofs. `k = H(x)` would instead have required proving a SHA
preimage inside a SNARK.

**Implication:** Q2 of `multichain-feasibility.md` is answered yes, with known techniques and
no trusted setup. `k = x` is now the design choice. Part A Step 5 (reveal and decrypt) is
covered by case 4.2. What remains is a real reveal of `x` through an adaptor signature
(Part B). Two costs carry into Part C:
- The 55 KB proof does not fit the single-QR, offline device-to-device handoff that
  re-delegation uses today.
- About 230 ms on a laptop is likely several times that on a phone.

The proof is PoC code: not audited, and the hash-to-curve is not constant-time (harmless here,
since its inputs are public).
