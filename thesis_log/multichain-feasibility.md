# Multi-Chain Feasibility

Tracks whether ORBIT's payment layer can be moved off Ethereum-only HTLCs onto any chain with
ordinary ECDSA/Schnorr signatures — the research question that Parts A and B of
`CLAUDE_replace_HTLC.md` are designed to answer.

## 2026-10-07 — Framing: which groups live where, and what Parts A/B must establish

**Attempt:** Re-stated the purpose of the HTLC-replacement track and mapped each cryptographic
object to the group it lives in, to identify exactly which properties must hold for ORBIT to
support cryptocurrencies other than ETH.

**Result:** Partial — a framing result, not an experiment. The feasibility question decomposes
into three sub-questions with a concrete test for each. None is answered in code yet.

**Details:**

*Why the current design is Ethereum-only.* `zfairexchange.sol` verifies a submitted Waters key
`(sk1, sk2, sk3)` with BN254 pairing equations evaluated on-chain. Only EVM chains expose a
BN254 pairing precompile (`alt_bn128`). Bitcoin, Monero and most other chains cannot evaluate
these equations, so the payment step cannot be ported as written.

*Groups involved.*

| Object | Group | Role |
|---|---|---|
| `sk1`, `sk2`, `h_tag`, `param.g`, `Y_G1 = g^k`, `T = h_tag^k` | BN254 G1 | Waters key components and verification helpers |
| `sk3`, `param.g2`, `Y_bn254 = g2^k`, `c1`, `c2` | BN254 G2 | the protected key component and its ElGamal ciphertext |
| pairing results | BN254 GT | `e: G1 × G2 → GT`, Type-3, no map between G1 and G2 |
| `x`, `Y_chain = x·G_chain` | target chain's curve: secp256k1 (Bitcoin, EVM-ECDSA), ed25519 (Monero) | adaptor-signature witness and statement |

The secret `x` is what the chain sees and what the Bank reveals to get paid. The exponent `k`
is what decrypts `sk3`. The design hinges on these being the same secret (`k = x`, or
`k = H(x)`) — and on Alice being able to *check* that before paying.

*The three sub-questions.*

| # | Question | Answered by |
|---|---|---|
| Q1 | Can Alice verify the encrypted Waters key off-chain, without decrypting it? | Part A, Steps 2–3 (check 1 via `Y_G1`, check 2 via hint `T`) |
| Q2 | Can a secret on a non-BN254 curve provably unlock it? | Part A, Step 4 (cross-group discrete-log equality between `Y_chain` and `Y_bn254`) |
| Q3 | Can a chain without pairings enforce "pay whoever reveals `x`"? | Part B (ECDSA adaptor signature on secp256k1) |

**Why:** Q1 removes the need for the chain to understand Waters or BN254 at all. Q3 replaces
the on-chain pairing check with an adaptor signature, which only needs the chain's own native
signature scheme. Q2 is the bridge between them, and it exists *only* because of the
multi-chain goal: on Ethereum today the chain checks BN254 directly, so no cross-curve link is
ever needed. Off Ethereum, without Q2 a dishonest Bank can publish `Y_chain` for one secret and
`Y_bn254` for another, collect payment and leave Alice with an undecryptable ciphertext. The
same cross-curve problem is solved in deployed Monero↔Bitcoin atomic swaps (ed25519 ↔
secp256k1), which is evidence that Q2 is tractable, provided `k = x` (a hash `k = H(x)` would
require a SNARK over the hash instead).

**Implication:** If Q1–Q3 all hold, multi-chain support is feasible; Part C (server endpoints,
Android wiring) is engineering, not feasibility. The Part A step order in
`CLAUDE_replace_HTLC.md` (Steps 2→5) follows this decomposition. The choice `k = x` vs.
`k = H(x)` is the first design decision this framing forces; `k = x` is recommended because it
keeps Q2 within known techniques. Per-step results go in `elgamal-sk3-veck.md` (Part A) and a
future Part B file; this file records the feasibility verdict as each question resolves.

## 2026-10-07 — Q1 answered: the encrypted Waters key is verifiable off-chain

**Attempt:** Part A Steps 2 and 3 (`elgamal-sk3-veck.md`) implemented both Waters checks on
the ElGamal-encrypted `sk3`, using `Y_G1 = g^k` for check 1 and a per-tag hint `T = h_tag^k`
for check 2.

**Result:** Success for Q1. Q2 and Q3 are untested.

**Details:** The recipient's check costs 11 BN254 pairings (one constant), about 12–13 ms on
a laptop release build, and runs entirely off-chain. Every tested cheating variant (wrong key,
wrong tag, wrong hint, wrong mask, tampered ciphertext) is rejected before payment.

**Why:** Bilinearity moves both Waters equations onto the ciphertext; injectivity of the
pairing in each argument makes the encrypted checks equivalent to the plain ones.

**Implication:** The chain never needs to evaluate a pairing, which removes the dependence on
EVM's BN254 precompile from the *verification* side. Feasibility now hinges on Q2 (proving
`Y_chain` and `Y_bn254` share one secret across curves) and Q3 (enforcing payment with an
adaptor signature).

## 2026-10-07 — Q2 answered: a secp256k1 secret provably unlocks the BN254-encrypted key

**Attempt:** Part A Step 4 (`elgamal-sk3-veck.md`) set `k = x` and implemented a cross-group
discrete-log equality proof between `Y_chain = x·G` on secp256k1 and `Y_G1 = g^x` on BN254 G1.

**Result:** Success for Q2. Q1 and Q2 are now answered yes; Q3 (on-chain enforcement) is
untested.

**Details:** 55.4 KB proof, about 230 ms to prove and to verify (laptop, release, single runs).
Every tested cheat (swapped `Y_chain`, mismatched encryption secret, replayed or tampered
proof, oversized `x`) is rejected before payment. Test table: `test-results.md`, run
2026-10-07 (2).

**Why:** Bit-decomposition with Pedersen commitments in both groups forces the same integer
`x < 2^252` on both curves. This is the same technique that links ed25519 and secp256k1 in
Monero↔Bitcoin swaps. The code is generic over short-Weierstrass curves, so another chain
curve of that form only needs a new set of bases. ed25519 (Monero) would need a twisted-Edwards
variant.

**Implication:** On the cryptographic side, multi-chain support is feasible. A Bank cannot get
paid on a non-pairing chain without handing Alice the secret that decrypts her verified key.
Feasibility now rests on Q3: Part B, an ECDSA adaptor signature on secp256k1 that reveals `x`
on-chain. Practical costs (proof size for offline QR handoff, phone-side timing) are Part C
concerns, not feasibility blockers.
