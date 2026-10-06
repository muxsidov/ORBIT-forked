# ORBIT — Crypto Implementation Notes

How the Waters key, the activation circuit (GWat), and the re-delegation circuit (GS) are
actually implemented, where that differs from the paper, and the known crypto flaws. Read this
before touching `server/rustcode/src/lib.rs`, `paymentbox_otp/app/rust/src/paymentbox/pbcrypto.rs`,
`computeGsAk2()`, or anything tag-related. Paper background: `ORBIT_PAPER.md` (protocol) and
`CLAUDE_Waters.md` (Waters IBE/signature math). Open items: `thesis_log/open-questions.md`.

## Waters activation key

`ak = dk_tag = KeyDerWat(sk, tag)` — a Waters IBE decryption key, adapted to BN254's Type-3
pairing (`e: G1 × G2 → GT`) as three components:

| Paper | Code | Group | Value |
|---|---|---|---|
| `dk1` | `sk1` | G1 | `msk · (u′·∏_{i∈tag} u_i)^r` |
| `dk2` | `sk2` | G1 | `g^r` |
| `dk3` | `sk3` | G2 | `g2^r` |

Verification (in `zfairexchange.sol` and the Rust code):
- `e(g, sk3) == e(sk2, g2)` — `sk2` and `sk3` use the same `r`
- `e(g^α, g2^β) · e(H(tag), sk3) == e(sk1, g2)` — the main Waters equation

**Notation vs. the paper.** The paper (§7.1) has one secret `α` and secret key `g2^α`. The code
(`generate_params_waters()`) uses two scalars, `alpha_secret` and `beta_secret`, with
`msk = g_alpha · beta_secret = g^(alpha_secret·beta_secret)`; its own comment maps code `g` ↔
paper `g2` and code `beta_secret` ↔ paper `α`. So `α_paper = alpha_secret · beta_secret`.
Currently `beta_secret = alpha_secret` (independent sampling is commented out). Params come from
`ark_std::test_rng()` (fixed seed) and are identical on every server start; `h_vec` has 256
generators.

## `beta_secret` stays on the server

`beta_secret` is the master secret: anyone holding it can mint keys for any tag. The server
strips it from `params` before returning them (`params_public.pop('beta_secret', None)`) and uses
it internally in `garble_waters`, `generate_gs_core`, and `water_unlock_solidity`. The Android
`ParamWaters` struct keeps the field with `#[serde(default)]` (deserializes as zero) so the dead
`water_decrypt` / `garble_redelegate` paths still compile; `evaluate_paymentbox` never reads it.

To make this possible, the Waters-IBE layer was removed from the activation circuit (no `rtag`,
no `water_decrypt`): `aon_key = XOR(ECDH shares)` only. Consequence: activation no longer
requires an activation key from the bank — the device's own ECDH is enough.

## GWat — the activation circuit

`garble_waters(param, shared_keys, garble_message_size=5, MAX_ITEM=256, tag)`: 5 positions ×
256 items. Each item's share is encrypted under its own ECDH key, plus an all-or-nothing key
built from per-position XOR shares. The device picks one random item per position (5 ECDH ops).
The `tag` argument is stored in `PaymentBox.tag` as **metadata only** — `garble_waters` never
calls `h_of_id`.

## GS — the re-delegation circuit

### What the code does

Minting calls `garble_waters_with_gs(param, gwat_keys, 5, 256, tag, gs_keys, tag_bits = 88)`
(server, `lib.rs`), which builds GWat and then GS, linked. Per-coin randomness comes from
`rand::thread_rng()` (not `test_rng()`, which would give every coin the same `r` and masks).

`generate_gs_core` follows the paper's two layers:
- **Masking.** Random G1 shares `s_1..s_ℓ`, `s_0 = −Σ s_i`. Slot `(i,0)` holds `s_i`, slot
  `(i,1)` holds `u_i·r + s_i`, the base holds `base_dk1 = msk + u′·r + s_0` with `dk2 = g·r`,
  `dk3 = g2·r`. (The paper's multiplicative shares `t′_0·∏t′_i = 1`, in additive notation.)
- **All-or-nothing.** `a = H(link) ⊕ a_0 ⊕ a_1 ⊕ … ⊕ a_ℓ`. The branch slot carries `a_0` under
  `shared_keys[0]` (`base_key_mat`); slot `(i,β)` carries `a_i ‖ b_iβ` under its own ECDH key
  (`key_mat{β}[i]`), and its share is encrypted under `H(a ‖ b_iβ)` (`slots_c{β}[i]`); the base
  (16-byte zero check value ‖ base_dk1 ‖ dk2 ‖ dk3) is encrypted under `a` (`base_enc`).
- **Link to GWat.** `link = SHA256("ORBIT-GS-LINK" ‖ sk2 ‖ sk3)` of the coin's own GWat key
  (`gs_link()`). Only a device that evaluated GWat knows it, so GS can't be opened without
  spending GWat's 5 uses. This plays the role of the paper's `rtag` from `Activate`.

`evaluate_gs(gs_circuit, bob_tag, shared_keys, gwat_sk2, gwat_sk3)` (Android JNI, identical copy
in the server's `pbcrypto.rs` for tests) opens the branch and one slot per bit of `bob_tag`
(LSB-first within each byte), rebuilds `a`, checks the zero check value, and sums the shares into
`dk1`. It returns an error (JNI: `RuntimeException`) instead of a garbage key if anything is off.
`computeGsAk2()` (Kotlin) does the `1 + numBits` AndroidKeyStore ECDH ops and passes the card's
`hiding_sign_vec2` as the GWat key.

### Why one recipient per coin

Every share is needed: missing any slot means missing some `a_i`, so nothing decrypts, and a
single slot is a uniformly masked G1 element. Opening both slots of bit `k` costs one extra ECDH
use, and the budget has none to spare (below). Opening GS without GWat fails (no `link`).
`test_gs_full()` checks the honest flow (94 uses, key verifies for exactly one tag), rejection of
another coin's GWat key, failure with any bit slot unopened, and fresh randomness per coin.

What it does **not** fix: the evaluator still chooses every tag bit, including `DDD`
(denomination forgery, below). The old "keys from one circuit are linkable" issue is moot now
that a circuit yields only one key.

### Budget (`nusecount`)

GWat 5 + GS branch 1 + 88 bits = **94 = `_GS_NUSECOUNT`, exactly** (the old 96 had 2 spare uses,
enough to open both slots of 2 bits → 4 recipients). One AndroidKeyStore key per coin, including
in `/api/replenish` (one attestation per coin): a shared key with a pooled `94 × n` budget would
let a client leave one coin unused and spend its uses on another coin's GS. `verify_attestation`
accepts 94 but no longer any multiple of it. GS size: 177 epks (33 B) + 1 + 176 key-material
ciphertexts (32/64 B) + 177 payload ciphertexts ≈ 23 KB, stored on the card.

All of this rests on the hardware enforcing `nusecount` (see the software-attestation-root flaw).
Coins minted before this change (no `base_key_mat`) can't be evaluated: discard and re-mint.

## The re-delegation tag `bobTag = "UUU_DDD_CCC"`

Built on the sender's device: recipient uid, card denomination, recipient's counter for that
denomination, each `%03d`, joined by `_` → 11 ASCII bytes = 88 bits. Fixed widths keep the field
bit-ranges disjoint and the encoding injective (requires uid, counter < 1000). Splitting the
identity into fields is a regrouping of the same product `u′·∏_{i∈M}u_i`
(see `CLAUDE_Waters.md`). The counter is checked only offline, never on-chain.

Limitations: two senders scanning the same "My ID" QR before the counter advances get the same
tag; the ~7M-value tag space is brute-forceable from a submitted key (linkability); GS circuits
minted before the 56→88-bit change or the masking change are incompatible (re-mint);
`CCC ≥ 1000` breaks the format.

## Known flaw — denomination forgery (OPEN, raised by supervisor)

1. **Circuit level.** `generate_gs_core` gives a free 1-of-2 choice on every tag bit, including the
   fixed denomination bits `DDD` (bytes 4–6) and the separators. Latent today only because of the
   tag-encoding mismatch below.
2. **Server level (live).** `/api/pay` and `/api/redelegate` read `denomination` from the request
   body. `/api/redelegate` with an empty `contract_id` (or a failing old withdrawal) still mints a
   fresh HTLC for that denomination: `{contract_id: "", denomination: 100}` creates an unbacked
   100C coin.

**Planned fix (proposed, not implemented):**
- *Circuit:* fold the fixed bits into the base at mint time,
  `base_dk1 = msk + (u′ + Σ_{fixed bits = 1} u_j)·r`, and emit slots only for `UUU` and `CCC`;
  `evaluate_gs`/`computeGsAk2` must skip fixed positions. Forging a denomination then needs
  `u_j^r` from `u_j` and `g^r` — CDH. 48 free bits → `nusecount = 5 + 1 + 48 = 54` (exact). Paper's alternative: one Waters key per
  denomination.
- *Server:* read the denomination from the on-chain contract; reject an empty `contract_id` and
  abort on a failed withdrawal in `/api/redelegate` (or remove that endpoint).
- Verifying the circuit fix on-chain requires the tag-encoding fix below.

## Tag-encoding mismatch (OPEN)

Three tag → group-element computations that must agree for a client key to pass on-chain:
1. `h_of_id()` (server Rust): tag as an ASCII **string**, bit by bit, into `h_vec`.
2. `water_unlock_solidity()` (server Rust): tag as an **integer**, bits into `h_vec[0..40]`.
3. `hashlockMatches` (`zfairexchange.sol`): integer bits of `hashlock` — matches (2).

Client keys from GWat/GS never pass the on-chain check, so `/api/pay` substitutes a server-derived
key from `water_unlock_solidity(denomination)`. **Fix (not implemented):** make the circuits and
`computeGsAk2` use the same integer encoding as the contract; then `/api/pay` can verify submitted
keys (and `decompress_waters_key()`, already in `lib.rs`, becomes useful). Neither `garble_waters`
nor `generate_gs_core` calls `h_of_id`, so the GS tag width is orthogonal to this bug.

## Tests

- `python3 -c "from server import test_gs_full; test_gs_full()"` — the real mint → activate (GWat)
  → re-delegate (GS) pipeline with a simulated device key and ECDH-use counting; also the
  negative cases listed under "Why one recipient per coin".
- `python3 -c "from server import test_redelegate_full; test_redelegate_full()"` — the unused
  Option-B `garble_redelegate` path only.
