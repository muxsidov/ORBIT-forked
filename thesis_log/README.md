# Thesis Log

Running, append-only record of research/design work on this project: HTLC-replacement Parts
A/B/C (`CLAUDE_replace_HTLC.md`), feature reviews against `ORBIT_PAPER.md`, and Waters IBE /
tag-design work. One file per major topic; entries are never edited or reordered after the fact
— corrections get a new entry, not a rewrite of the old one.

See also: [`GLOSSARY.md`](GLOSSARY.md) — term definitions used across these entries, so you
don't have to re-derive them from code each time — and [`open-questions.md`](open-questions.md)
— a live tracker of unresolved threads; check it first when picking a topic back up.

## Topic files

### [ElGamal-in-G2 VECK for sk3](elgamal-sk3-veck.md)
Hiding the Waters `sk3` component behind a verifiable encryption scheme, and whether it can be
checked before decryption (Part A, Steps 1-2+, of `CLAUDE_replace_HTLC.md`).
- **Scope test:** the VECK/adaptor-signature cryptographic design for replacing
  `zfairexchange.sol` — pairing-group derivations, ElGamal/Groth-Sahai proof attempts, Parts
  A/B/C milestones.
- **Thesis use:** System Design (HTLC-replacement chapter) and Security Analysis. The first
  entry documents a caught derivation error before any code was written — good source material
  for a design-iteration/methodology subsection, not just the final result.

### [Multi-Chain Feasibility](multichain-feasibility.md)
Whether ORBIT's payment layer can work on chains without a BN254 pairing precompile (Bitcoin,
Monero, …): the three sub-questions Parts A/B answer, and the groups each object lives in.
- **Scope test:** the overall feasibility verdict and framing — what must hold for multi-chain
  support. Individual cryptographic experiments go in `elgamal-sk3-veck.md` (Part A) or a Part B
  file; record here only how their results change the verdict.
- **Thesis use:** Introduction/Motivation (why leave Ethereum-only) and the opening of the
  HTLC-replacement design chapter; the groups table is a ready-made figure.

### [Test Results](test-results.md)
Raw pass/fail tables of the research test programs (Part A Steps 1–3 so far): one row per case,
with what it simulates, expected vs. observed, and the exact command/commit of each run.
- **Scope test:** test outcomes only. The reasoning behind a result goes in the topic file
  (`elgamal-sk3-veck.md`, `multichain-feasibility.md`); this file is the evidence table.
- **Thesis use:** Evaluation chapter. The negative cases are the evidence for "a cheating Bank
  is caught before Alice pays".

### [Denomination and Identity-QR Feature Review](denomination-and-identity-qr-review.md)
Mapping the denomination system and scan/identity-QR re-delegation flow onto the paper's
algorithms; surfaces that recipient identity in the current re-delegation path has no
attestation binding to a real hardware key.
- **Scope test:** reviews/audits of how an *already-implemented* feature maps onto the paper's
  formal algorithms — field-by-field or endpoint-by-endpoint walkthroughs, gap analysis against
  Definitions 4.1-4.5. Not for new design work on the Waters tag itself (see the file below).
- **Thesis use:** Implementation chapter (code-to-paper mapping) and Discussion/Future Work —
  the "Option A vs. Option B" recipient-attestation gap is directly citable as a scoped
  limitation of the prototype.

### [Waters IBE / Signature Scheme](waters-ibe-signature-scheme.md)
Review of the underlying Waters IBE paper and design/implementation of extensions to the Waters
identity tag (uid/denomination fields, and a per-recipient coin counter for RDelegate),
including the privacy/linkability tradeoffs that extension introduced.
- **Scope test:** the Waters IBE/signature math itself, the identity/tag structure, or features
  built directly on top of it (GS circuit, coin counter, their security properties). If it's
  about reviewing an *existing, unrelated* feature's paper-correctness, prefer the
  Denomination/QR file above instead.
- **Thesis use:** Background (Waters IBE primitives, §4), System Design (the tag extension), and
  Security Analysis — the brute-force-linkability finding (2026-10-01) is directly usable in a
  limitations/threat-model discussion.

## Conventions

- **Picking a topic file for a new entry:** match against the scope tests above. If genuinely
  ambiguous (touches two tracks), ask rather than guess, or split into two entries, one per file.
- **Found something still unresolved?** Add a line to `open-questions.md` the same session you
  write the entry that raises it.
- **Unfamiliar term in an entry?** Check `GLOSSARY.md` before re-deriving it from code.
