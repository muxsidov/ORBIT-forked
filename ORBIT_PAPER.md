# ORBIT_PAPER.md

Reference summary of `ORBIT.pdf` ("ORBIT: One-Shot Re-Delegatable Signatures for Scalable Off-Chain Payments", anonymous submission to ACM CCS 2025). Read this instead of re-reading the PDF for questions about the paper's design, formal definitions, or algorithms.

For how these concepts map onto the actual code in this repo (Rust functions, endpoints, Android flow, and where the implementation *deviates* from the paper), see `CLAUDE.md` — this file stays paper-only so the two don't drift out of sync.

## Core idea

ORBIT is a new primitive: **one-shot re-delegatable signatures**. A signer (the bank) delegates signing authority for free in an **offline phase**, but the delegated token (`dmk`, "dormant key") is inert until the bank cooperates in an **online phase** to activate it. Once activated, the token can be used *exactly once*, either to:

1. **Re-delegate** — pass signing capability to another user (who must then also activate), or
2. **Delegated sign** — produce one final signature and stop the chain.

This gives a chain of transfers (bank → Alice → Bob → …) where each hop consumes a one-shot token and hands the next party a fresh dormant token, until someone redeems the final signature. Applied to payments: locking value once (bank/Alice, on-chain) and passing a claim to it through any number of off-chain, peer-to-peer re-delegations, with only two on-chain transactions total (initial lock, final redeem).

**Design goals:** no pre-registration, legacy blockchain compatibility, fungibility (payments unlinkable/history-free), rollback protection without on-chain dispute resolution.

**Key hardware assumption ("limited-count keys"):** a hardware-backed key can be configured to allow only *n* uses (enforced by a monotonic counter), e.g. Android Keystore `nusecount`. This is weaker/lighter than requiring a full TEE — no secure code execution needed, just a counter check before key access. This is the *only* thing preventing a malicious delegatee from over-using a token or extracting the delegator's key.

## Formal syntax (Definition 4.1)

ORBIT is defined relative to an underlying signature scheme `DS = (KeyGen, Sign, Verify)` (in the construction: ECDSA):

| Algorithm | Signature | Role |
|---|---|---|
| `OKeyGen(λ, skDS, vkDS)` | → `(sk, pk)` | bank's one-shot keypair, wraps `skDS/vkDS` |
| `DKeyGen(λ)` | → `(pkD, skD)` | delegatee generates an nUKE (hardware-backed, count-limited) keypair |
| `Delegate(sk, pk, pkD)` | → `(dmk, tag)` | bank issues a dormant key bound to a fresh random `tag`, for delegatee `pkD` |
| `Unlock(sk, tag)` | → `ak` | bank computes the **active key** for `tag` — this is a Waters signature on `tag`, only the bank can compute it |
| `Activate(dmk, ak, pk, tag)` | → `osk` or `⊥` | delegatee combines `dmk` + `ak` → one-shot signing key `osk` |
| `RDelegate(osk, skD, tag2)` | → `ak2` | delegatee re-evaluates their **own** activated `osk` at a new tag (bound for the next recipient) → produces the *next* person's active key |
| `DSign(osk, skD, m)` | → `σ` | delegatee spends the one-shot key to sign message `m` under `DS` |
| `VerifyD(dmk, tag, pk, pkD)` | → `0/1` | (verifiability extension) checks a dormant key is well-formed before activation |

**Critical point for "can RDelegate happen without Activate":** `RDelegate` takes `osk` (the *output* of `Activate`) as a formal input — there is no algorithm that goes directly from `dmk` to a re-delegation. So per the paper, no — activation is a hard prerequisite for re-delegation. (See CLAUDE.md's "GS Circuit" section for how this repo's actual implementation approximates this differently.)

### Correctness chain (Definition 4.2)

For a chain of `n` delegatees:
```
ak_tag,1        ← Unlock(sk, tag1)                        # bank issues first active key
dmk_tag,i, tag_i ← Delegate(sk, pk, pkD,i)                 # for each hop i
osk_i           ← Activate(dmk_tag,i, ak_tag,i, pk, tag_i)
ak_tag,i+1      ← RDelegate(osk_i, skD,i, tag_i+1)         # hands off to hop i+1
```
and the final `osk_n` must produce a valid `DS.Verify`-passing signature via `DSign`.

## Security properties

- **One-timeness** (Def. 4.3): stronger than standard unforgeability — an adversary who has received *l* activation keys (via the `Unlock` oracle) can produce at most *l* extra valid message/signature pairs beyond what the signer directly signed. Modeled as a "one-more unforgeability" game (cf. blind signatures).
- **History-freeness** (Def. 4.4): a signature produced via a delegation chain (`DSign`) is indistinguishable from a signature the bank produced directly (`DS.Sign`) — third parties can't tell how many hops a coin went through. The bank itself *can* always trace a final signature back to the original dormant key it issued.
- **Verifiability** (Def. 4.5, optional — `ORBITZK` extension): protects delegatees against a malicious bank issuing bad `dmk`s. Adds `VerifyD`/`VerifyDZK` and a `DelegateZK` that attaches a NIZK proof that `dmk` was computed correctly (i.e., will activate into a valid `osk`). Estimated cost: ~5M non-linear constraints, ~15-20s prover time (paid once, offline, doesn't affect payment latency). Cheaper alternative sketched: cut-and-choose over `2λ` dmk instances + `(λ+1)-of-2λ` VSS of the signing key, revealing `λ` shares for spot-checking.

## Off-chain payment protocol (Figures 1 & 2)

**Offline phase (Fig. 1):** Bank runs `Delegate(sk, pk, pkD)` → gives Alice `dmk` bound to `tag1`. Free — no payment, no on-chain action. Can be done any time, independent of when/whether Alice ever spends it.

**Online phase (Fig. 2)**, numbered steps as in the paper:

1. Alice wants to activate her `dmk` (tag1).
2. Bank runs `Unlock(sk, tag1)` → `ak1`.
3. **Atomic fair exchange**: Alice pays `$v` to the bank ⟺ bank releases `ak1`. This is the step that must be protected by a smart-contract-based fair-exchange protocol (see below) — otherwise a malicious bank can take payment and withhold `ak1`.
4. Alice runs `Activate(dmk, ak1, pk, tag1)` → `osk1`. Alice's dmk is now live.
5–6. To pay Bob: Alice runs `RDelegate(osk1, skD1, tag2)` using Bob's fresh tag → `ak2`. This **consumes** Alice's `osk1` (one-shot: she can only re-delegate once) and hands Bob the active key for his own (separately, offline-issued) `dmk`.
7–8. Bob (holding his own dormant key from a prior offline `Delegate`) runs `Activate(dmk2, ak2, pk, tag2)` → `osk2`. He can repeat the chain (steps 5-8 again) or redeem.
9. Final holder runs `DSign(osk_n, skD,n, m)` → `σ`, a standard `DS` (ECDSA) signature on a bank-designated redemption message `m`.
10. **Atomic fair exchange**: final holder submits `(m, σ)` to the smart contract ⟺ receives `$v`. Same fair-exchange concern as step 3, mirrored.

**Only two on-chain interactions total** (step 3 and step 10), regardless of chain length — every re-delegation in between is off-chain, peer-to-peer, and (in the construction) requires no server contact, only the delegatee's local hardware key.

### Fair exchange, distributed bank, and denominations (Section 2.4)

- **Fair exchange** (steps 3 & 10) can be instantiated generically via smart contracts (cites [38]) or by adapting BLS-signature/cryptocurrency exchange techniques [22]. Necessary because the bank is only assumed **honest-but-curious** by default (malicious if verifiability/`ORBITZK` is required) — without atomicity it could take Alice's payment and never release `ak1`, or accept a valid final signature without paying out.
- **Distributed bank**: to stop the bank from independently forging redemptions with its own `skECDSA` and draining the payout contract, the paper proposes splitting the bank across `n` parties and requiring `n` independent ECDSA signatures (one per bank) at step 10 — safe as long as at least one bank instance is honest.
- **Multiple denominations**: explicitly noted as **not solved** by the base construction — the paper's scheme supports only a single fixed value `$v` per key. It sketches using *multiple bank public keys* (`pk1` = $1 coin, `pk5` = $5 coin, …) as a direction, and **explicitly leaves an efficient multi-denomination mechanism to future work**. (This repo's `_DENOM_ETH` / `tag`-as-denomination system in `server.py` is exactly this kind of extension, going beyond what the paper formally specifies.)
- **Cross-chain payments**: since blockchain interaction is limited to steps 3 and 10, those two steps could in principle happen on *different* chains, as long as the payout chain has sufficient locked balance — noted as unexplored future work.

## Construction (Section 5) — how the crypto actually works

Starting point: Yeoh, Hanzlik, Valta's single-use delegatable-ECDSA scheme (no re-delegation, no dormant/active key split). ORBIT extends it two ways: (1) adds the offline/online dormant-key split, (2) adds a **Waters-signature branch** so a token can be evaluated either as a final ECDSA signature (`DSign`) or as a Waters signature used to re-delegate (`RDelegate`) — both branches coexist in the same `dmk`, gated by which nUKE key-exchange slots the delegatee chooses to burn.

### ECDSA branch — garbling trick

ECDSA: `s = k⁻¹·(r·skECDSA + H(m))`. Writing `H(m)` in bits `h1...hℓm`, this becomes `s = p0 + Σ pi,hi` where `p0 = k⁻¹·r·skECDSA`, `pi,0 = 0`, `pi,1 = 2^(i-1)·k⁻¹`. Revealing `p0` and any `pi,1` leaks `skECDSA`, so each `pi,b` is additively masked with a `0`-sum secret sharing `t0..tℓm` (`Σti = 0`): `p0 += t0`, `pi,0 = ti`, `pi,1 = 2^(i-1)k⁻¹ + ti`.

### Waters branch — enables re-delegation

Waters signature `(σ1,σ2,σ3) = (g^αβ·(u0·Πuᵢ^mᵢ)^r, g1^r, g2^r)` — only `σ1` depends on message bits. Same trick applies multiplicatively: `σ1 = p'0 · Π p'i,mi` with a **multiplicative** secret sharing of `1_G1` (`t'0 · Π t'i = 1`) instead of additive.

**Why Waters, specifically:** a Waters signature on identity `ID` *is* a valid Waters IBE decryption key for `ID` (`KeyDerWat(sk, ID) = SignWat(sk, ID)`). So possessing a re-delegated Waters signature under `tag` = holding the decryption key needed to unlock the *next* dormant key's secret. This is the mechanism that ties "received a valid re-delegation" to "can activate the next dmk" without the bank being involved.

### nUKE (n-Use Key Exchange) — non-interactive OT replacement

Each delegatee's hardware key is attested to allow exactly `n = ℓm + 1` `Shared()` (ECDH) derivations. The bank encrypts two payloads per bit position (`pi,0`, `pi,1`) each under a different ephemeral key such that only the ECDH matching the delegatee's chosen bit is decryptable — a non-interactive 1-of-2 OT, enforced by hardware rather than a live OT protocol. An **all-or-nothing** layer additionally ensures a delegatee who tries to decrypt *both* options at some position `i` (double-spend attempt) fails to reconstruct *any* of the payloads: the true decryption secret `a` is itself split into per-bit shares `ai` that only reconstruct correctly if exactly one branch per bit was decrypted.

The **`tag` itself is IBE-gated**: the dormant key encrypts a secret `rtag` under Waters-IBE with identity = `tag`; only someone holding a valid Waters signature under `tag` (i.e., `ak = aktag`) can decrypt `rtag`, which is required to derive the final decryption key `a` for the garbled payloads. This is what makes "no `ak` ⇒ can't activate" hold cryptographically, not just by protocol convention.

### Concrete algorithms (Figures 3 & 4)

```
OKeyGen(λ, skECDSA, pkECDSA):
  (skWat, pkWat) ← SetupWat(λ)
  return sk := (skECDSA, skWat), pk := (pkECDSA, pkWat)

DKeyGen(λ):
  (skNUKE, pkNUKE, σatt) ← nUKE.KeyGenAtt(gkAtt, ℓm + 1)   # ℓm = tag/message bit length
  return skD := skNUKE, pkD := (pkNUKE, σatt)

Unlock(sk, tag):
  dktag := KeyDerWat(skWat, tag)      # = SignWat(skWat, tag), a Waters signature
  return aktag := dktag

Activate(dmk, ak, pk, tag):
  parse dmk := (GECDSA, GWat, GS), (cak, ω) := GS
  rtag := DecryptWat(aktag, cak)      # only possible if ak is a valid Waters sig under tag
  set ĜS := (rtag, ω)
  return ⊥ if a decrypt-consistency check fails, else osk := (GECDSA, GWat, ĜS)

RDelegate(osk, skD, tag2):
  parse (·, GWat, ĜS) := osk
  # ĜS contains rtag (decrypted in Activate) + per-bit nUKE ciphertexts (pkS,1,cS,1), (pki,0,ci,0,pki,1,ci,1)
  do 1 ECDH for the branch slot (pkS,1) + ℓm ECDH ops, one per bit of tag2, using skD
  reconstruct secret a = H2(rtag) XOR (XOR of per-bit shares ai)
  dk1 := p'0 · Π p'i    dk2 := H2(a||1) XOR cγ,1    dk3 := H2(a||2) XOR cγ,2
  return ak2 := (dk1, dk2, dk3)     # a fresh Waters signature/decryption key under tag2

DSign(osk, skD, m):
  # same shape as RDelegate but reconstructs ECDSA (r,s) instead, using H(m)'s bits
  # requires the branch slot for the ECDSA sub-circuit (a separate nUKE key from the Waters branch)
  return σ := (r, s)
```

`Delegate(sk, pk, pkD)` (bank side, Fig. 4) is the expensive one: samples a fresh random `tag`, secret-shares both the ECDSA payloads (additive, `Σti=0`) and the Waters payloads (multiplicative, `Πt'i=1`), encrypts every share under a per-bit nUKE-derived key targeting the delegatee's attested `pkD`, and IBE-encrypts `rtag` under identity `tag`. Output: `dmk := (GECDSA, GWat, GS)`.

**`GS` structure** (what actually gets decrypted during `Activate`/`RDelegate`):
```
GS = ( cak,                                    # Waters-IBE ciphertext of rtag under identity=tag
       (pkS,i, cS,i) for i ∈ {0,1},             # branch-secret slots: i=0 for DSign, i=1 for RDelegate
       (pki,0, ci,0, pki,1, ci,1) for i ∈ [ℓm] ) # per-tag-bit slots
```

### Efficiency knob: word size `w`

Bit-wise decomposition (`w=1`) can be generalized to word-size decomposition (`w>1`, e.g. bytes), trading more delegator-side computation (Delegate) for `ℓm/w` fewer client-side operations. The paper benchmarks both `w=1` and `w=8`. (This repo's `garble_waters`/`garble_redelegate` use `MAX_ITEM=256` i.e. `w=8` byte-wise decomposition — see CLAUDE.md.)

### Optimization: split tag length from message length

`ℓm` (bit length) is split into two independent parameters: `ℓtag = 40` bits for re-delegation tags, `ℓecdsa = 256` bits for the ECDSA message hash — since the tag space only needs to be large enough to avoid collisions over the system's lifetime (40 bits ⇒ 2^40 tags), not as large as a full hash.

## Hardware assumptions (Section 2.5, Section 3)

Three tiers of hardware trust, from weakest to strongest:

| Assumption | Guarantee |
|---|---|
| 1 — TEE-Secured Keys | keys + attestation both protected by TEE against system-level adversaries (not side-channel/fault-injection) |
| 2 — Post-Compromise TEE-secured Keys | keys in tamper-resistant hardware keystore, but attestation mechanism managed by TEE (what the paper's Pixel 6 test device actually provides) |
| 3 — Tamper-resistance Hardware Keys | keys **and** attestation both in tamper-resistant hardware (strongest, e.g. StrongBox) |

**Multi-device policy**: to avoid trusting a single hardware manufacturer, `Delegate` can be modified so each per-bit ciphertext requires ECDH shared secrets from `k` different attested devices simultaneously (`ci,b := H2(Ki,b,1,...,Ki,b,k) ⊕ (ai||bi,b)`) — decryption requires *all* `k` devices to cooperate.

## Implementation & benchmarks (Section 6, Pixel 6 Pro + M3 Pro Macbook)

- Key exchange / ECDSA curve: **secp256r1**. Waters pairing curve: **BN254**.
- `|pkD|` (attested delegatee pubkey sent to bank): ~3.7 KB.
- Partial `dmk` (RDelegate-only functionality): 8 KB (`w=8`) to 122 KB (`w=1`).
- Punctured `dmk` (DSign-only functionality): 776 KB (`w=8`) to 50 KB (`w=1`) — note DSign's `dmk` is *larger* for `w=8`, opposite of RDelegate, because `ℓecdsa=256 ≫ ℓtag=40`.

**Table 1 — timings (ms), averaged over 100 runs:**

| Operation | Config | w=1 | w=8 |
|---|---|---|---|
| Delegate (tag, ℓtag=40) | — | 15.90 | 300.98 |
| Delegate (ECDSA, ℓecdsa=256) | — | 46.96 | 692.17 |
| DKeyGen | TEE | 14.46 | — |
| DKeyGen | StrongBox | 140.78 | — |
| RDelegate | TEE | 386.36 | 116.35 |
| RDelegate | StrongBox | 2038.68 | 333.9 |
| DSign | TEE | 2215.36 | 337.31 |
| DSign | StrongBox | 12606.65 | 1671.79 |

`Activate` costs the server ~2.07 ms total (negligible). `Unlock`'s cost is folded into the RDelegate/DSign benchmarks above. Byte-wise (`w=8`) is faster client-side for RDelegate/DSign despite costing the delegator more at Delegate time — favorable trade since Delegate happens offline/pre-paid, RDelegate/DSign happen online where latency matters.

## Related work contrast (Section 1.2, for context)

- **Teechain**: relies on full TEE (stronger assumption), needs per-party on-chain channel setup, requires both parties continuously online.
- **Ekiden**: TEE-based, general-purpose contract execution, not offline-payment-focused.
- **FastKitten**: TEE-based, still needs synchrony between parties.
- ORBIT's pitch vs. all three: weaker hardware assumption (monotonic counter, not full TEE), no per-party setup, recipient can be **offline** during the payment.
- **Straw-man alternatives rejected** (Section 2.1): (a) quantum one-shot signatures — incompatible with classical blockchains, leaks full transaction graph to the bank; (b) naive one-time delegatable signatures (Yeoh et al. base scheme) — not re-delegatable, would force the bank to delegate its full signing authority upfront (misuse risk) if applied directly.
