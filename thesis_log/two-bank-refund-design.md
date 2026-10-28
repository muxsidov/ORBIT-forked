# Two-Bank Refund Design

Design of the payback/refund path for the Bitcoin FDE purchase under the supervisor's two-bank
proposal (assumption: at least one of two banks is honest).

## 2026-10-27 — Problem statement: a two-bank payback path for a Bitcoin-only purchase

**Attempt:** The supervisor's proposal was recorded and checked against the current Part C lock
(`server/poc_adaptor_sig/src/btc.rs`). The proposal: Alice buys a coin from **two banks**,
paying each half, with an exchange as a fourth party that coordinates. At the end, the two banks
and Alice contribute, and the party that delivers is paid. No design or code was produced; this
entry fixes the requirements and the design space for a later session.

**Result:** Partial. The goals and the trust assumption are stated, and three candidate readings
are assessed. The payback (refund) path is **not yet designed**, so it can be designed from
scratch.

**Details:**
- *Goal, as stated by the user.* Alice transacts **purely on Bitcoin**: no Sepolia, no EVM
  contract, no pairing check on-chain.
- *Trust assumption.* **At least one of the two banks is honest.** Neither bank is trusted
  individually.
- *Payout rule.* "Whoever provides the … should be paid." The sentence is incomplete in the
  source. The most likely reading is "whoever provides the witness (`x`, i.e. the key) is paid";
  to be confirmed with the supervisor.
- *Current lock (Part B/C, single bank).* A P2WSH script:
  `IF <Alice> CHECKSIGVERIFY <Bank> CHECKSIG ELSE <T> CHECKLOCKTIMEVERIFY DROP <Alice> CHECKSIG ENDIF`.
  - The claim pays the Bank and reveals `x` through the adaptor signature.
  - The refund is a pure timelock (CLTV). It is **not** an HTLC: there is no hash lock, and the
    `zfairexchange.sol` contract is not involved.
  - Known weakness (B3.10, B3.11b): if the claim has not *confirmed* before `T`, Alice can read
    `x` from the mempool and replace the claim with her refund under full-RBF.
- *Constraint established in this session.* Bitcoin script cannot detect misbehaviour. The only
  two ways for Alice to recover funds that another party must co-sign are:
  1. **time** (CLTV/CSV), or
  2. **another party's signature** (multisig).

  Removing the timelock therefore means a refund authorised by other parties. Under the
  1-of-2-honest assumption, an honest bank could be the party that authorises it.
- *Candidate readings, assessed in this session (before the trust assumption was known):*

  | Reading | Effect | Timelock removed? | Fairness risk |
  |---|---|---|---|
  | A. Refund branch = multisig with the exchange/other bank instead of CLTV | Refund needs a quorum, not time | Yes | A signer who co-signs a refund after `x` is in the mempool recreates the B3.10 race |
  | B. `x = x1 + x2`, one share per bank, half the amount to each | No single bank can deliver or withhold the key alone | No (each half needs a refund path) | One bank claims, the other does not: Alice has paid half and has no key |
  | C. One joint claim transaction, completable only by both banks together | Both banks are paid all-or-nothing | No | Needs two-party ECDSA adaptor signing (MPC), or a switch to Schnorr/MuSig2 adaptor |

  Rough effort: A 1–2 days, B 3–5 days, C 1–2 weeks with Schnorr (longer with ECDSA MPC).
- *Cheap mitigations of the race that keep the single-bank design:*
  - a large timelock and margin (144 / 12 blocks already in `server.py`);
  - Alice pre-signs the claim at a high fee, or at several fee levels (each reveals the same
    `x`);
  - a CPFP anchor output.

**Why:** The refund path exists for liveness: if the seller never claims, the buyer's money must
not be locked forever. A timelock provides this without trust; any other mechanism moves the
decision to signers. The 1-of-2-honest assumption is what makes a signer-based refund plausible.
It also introduces a new threat: a dishonest bank colluding with Alice could authorise a refund
after the honest bank has revealed its part of the key.

**Implication:**
- The two-bank design is feasible on Bitcoin with standard script (multisig, CLTV) if the
  refund is authorised by the honest bank instead of (or in addition to) time.
- What remains is to design it so that, with any single bank dishonest, three things hold:
  1. Alice gets either the key or her money back, never neither;
  2. an honest bank that revealed its share is paid;
  3. Alice cannot obtain both the key and the refund.
- Open points: the role of the exchange (the fourth party), and the incomplete payout rule.
  Tracked in `open-questions.md`.

### Prompt for a fresh session

> Context: ORBIT thesis prototype, repo `/home/mirzokhid/Masters/orbit-7C66`. Read
> `thesis_log/two-bank-refund-design.md` (this entry), then `CLAUDE_replace_HTLC.md`
> ("Full protocol", Part B/C status), `CLAUDE_AandFD.md` (§B.2 Bitcoin bonding transaction),
> `thesis_log/ecdsa-adaptor-secp256k1.md` (B3 and Part C entries) and
> `server/poc_adaptor_sig/src/btc.rs` (current lock script).
>
> Task: design the payback/refund path for a **two-bank** Bitcoin-only coin purchase,
> proposed by my supervisor.
> - Alice pays each of two banks half the amount, and an exchange (fourth party) coordinates.
> - The party that delivers the key/witness is paid.
> - Assumption: **at least one bank is honest**; neither bank is trusted alone.
> - Everything settles on Bitcoin (script: multisig, CLTV/CSV, ECDSA adaptor signatures as in
>   B3). No EVM and no pairing on-chain.
> - The refund is not yet designed; a timelock-free refund authorised by the honest bank is
>   allowed if it is sound.
>
> Deliver:
> 1. Concrete lock and spending scripts for every branch (claims, refund), saying who signs
>    what and in which order.
> 2. How `x` (and the VECK/ElGamal key and cross-group proof) is split or shared between the
>    banks.
> 3. A case analysis for every single-bank-dishonest scenario, including:
>    - collusion of a dishonest bank with Alice;
>    - one bank claiming and the other staying silent;
>    - the B3.10 mempool race.
>
>    Show: Alice ends with the key or her money; an honest bank that revealed its share is
>    paid; Alice never gets both.
> 4. The role of the exchange, and whether it needs to be trusted.
> 5. A work estimate and a test plan in the style of B3 (`b3_bitcoin_regtest.rs`, regtest).
>
> Ask me first if the payout rule ("whoever provides the … is paid") or the exchange's role
> is ambiguous. Log the result with /labnote two-bank-refund-design.
## 2026-10-27 — Gap: no coin holder is ever paid; redemption path added to the design scope

**Attempt:** Traced where the money goes when a coin holder (Alice, or Bob after
re-delegation) redeems a coin, on both settlement paths.

**Result:** Failure (design gap). On neither path does the holder receive funds at an address
of their own.

**Details:**
- *Sepolia HTLC path (used by the Android app).* Payouts return to the Bank.
  - Every contract is created with `newContract(_eth_acct.address, …)`, so the receiver is the
    Bank's own wallet (`server/server.py:287` mint, `:463` redelegate, `:548` `/api/lock`).
  - `/api/pay` sends `withdraw()` from the Bank's account (`server.py:576`), and the contract
    pays `c.receiver` (`server/zfairexchange.sol:356`).
  - Net effect of "Withdraw": the denomination moves Bank → contract → Bank. The phone receives
    only a `tx_hash` as evidence that the coin was consumed.
  - Re-delegation follows the same pattern: Bob redeems through `/api/pay`, so the funds return
    to the Bank, and Alice receives nothing for the coin she transferred.
- *Bitcoin FDE path (Part C).* Only the purchase direction exists:
  - Alice's BTC goes into the lock and then to the Bank's payout address, and Alice receives
    the key;
  - the only flow back to Alice is her refund, when the Bank does not claim;
  - there is no redemption step that turns a valid Waters key into BTC at the holder's address.
- *Re-delegation payment (Bob pays Alice).* This is designed in `CLAUDE_replace_HTLC.md`
  ("Re-delegation for free": Alice plays the Bank's role towards Bob with the same purchase
  protocol), but it is not implemented.

**Why:** The demo was built to show that a coin is consumed exactly once, not to move value to
the holder. The HTLC receiver was fixed to the Bank's address, and Part C implemented only the
purchase half of the FDE protocol.

**Implication:** The payout rule ("whoever provides the … is paid") must also cover
**redemption**, not only the purchase. The two-bank design must specify three flows:
1. **Purchase:** Alice pays the banks and receives the key.
2. **Redemption:** the holder proves a valid key and receives the denomination at their own
   Bitcoin address. Requirements:
   - it is one-shot: a redeemed key never pays twice;
   - the holder's address is bound to the claim, so an observer cannot redirect the payout
     (compare the B3.2 front-running case);
   - it works for a coin received by re-delegation.
3. **Re-delegation payment:** Bob pays Alice for the coin (seller = Alice).

Each flow also needs its own refund/liveness path under the at-least-one-honest-bank
assumption. The prompt below supersedes the one in the previous entry.

### Prompt for a fresh session (supersedes the previous one)

> Context: ORBIT thesis prototype, repo `/home/mirzokhid/Masters/orbit-7C66`. Read both entries
> of `thesis_log/two-bank-refund-design.md`, then:
> - `CLAUDE_replace_HTLC.md` ("Full protocol", "Re-delegation for free", Part B/C status);
> - `CLAUDE_AandFD.md` (§B.2 Bitcoin bonding transaction);
> - `thesis_log/ecdsa-adaptor-secp256k1.md` (B3 and Part C entries);
> - `server/poc_adaptor_sig/src/btc.rs` (the current lock script);
> - `/api/fde/*` in `server/server.py`.
>
> Task: design the settlement for a **two-bank**, Bitcoin-only version of ORBIT, as proposed by
> my supervisor:
> - two banks, with Alice paying each half;
> - an exchange (a fourth party) that coordinates;
> - **at least one bank is honest**, and neither bank is trusted alone;
> - everything settles on Bitcoin (multisig, CLTV/CSV, and ECDSA adaptor signatures as in B3),
>   with no EVM and no pairing on-chain.
>
> Cover three flows:
> 1. **Purchase:** Alice pays the banks and receives the key.
> 2. **Redemption:** the holder (Alice, or Bob after re-delegation) proves a valid Waters key
>    and is paid the denomination at **their own** address. Today nobody is: the Sepolia path
>    pays the Bank back, and Part C has no redemption step.
> 3. **Re-delegation payment:** Bob pays Alice.
>
> The refund/payback path is not yet designed. A timelock-free refund authorised by the honest
> bank is acceptable if it is sound.
>
> Deliver, for each flow:
> - (a) the lock and spending scripts for every branch, saying who signs what and in which
>   order;
> - (b) how `x` (and the VECK ciphertext and cross-group proof) is split or shared between the
>   banks;
> - (c) a case analysis of every single-bank-dishonest scenario, including:
>   - a dishonest bank colluding with Alice or Bob;
>   - one bank acting while the other stays silent;
>   - the B3.10 mempool race;
>   - front-running a redemption payout;
>   - double redemption of one key.
>
>   Show that nobody ends with neither the key nor the money, that nobody gets both, and that
>   an honest bank that acted is paid.
>
> Also deliver:
> - the exchange's role, and whether it must be trusted;
> - a work estimate and a regtest test plan in the style of `b3_bitcoin_regtest.rs`.
>
> Ask me first if the payout rule ("whoever provides the … is paid") or the exchange's role is
> ambiguous. Log the result with /labnote two-bank-refund-design.
