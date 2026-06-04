# MNEME ∞ — Phase III Task Specification

**Accountability complete** — finish NIST's 4 dimensions, prove forgetting, and
machine-check the trust core (see [`ROADMAP.md`](ROADMAP.md) Phase III and
[`VISION_PROOF_CARRYING_COGNITION.md`](VISION_PROOF_CARRYING_COGNITION.md)).

**Status:** Active build spec (draft) — **wire skeletons + gated stubs only**.
**Baseline:** Phase I/II in progress; this spec lands the Phase III *seams*
without any proving logic. **Language:** Rust 1.86.0 (stable).
**Prime directive unchanged:** fail-closed verified recall only; verifier
TCB ≤ 500 lines; authenticated ≠ true; procedure-faithful ≠ exact-NN.

---

## 0. What Phase III is (and is not)

Phase III adds the last two provable claims to the certificate — *authorized,
human-sanctioned action* and *honored forgetting* — and machine-checks the
verifier core. This spec's **current increment is stubs only**: the type shapes
and the fail-closed API surface, gated off until the proving/signing/verification
logic and an adversarial red-team land.

| In scope (Phase III) | Out of scope (this increment) |
|---|---|
| **Non-repudiation** (`ActionReceipt`): action ⇄ capability + sanctioning human identity | The real signer / verifier for `ActionReceipt` |
| **Verifiable forgetting** (`ForgetProof`): crypto-shred witness + proof-of-absence | The real shred-witness + SMT non-membership prover |
| Optional binding to the Phase II cognition certificate ("cert v2") | Finalizing the cert v2 layout (owned by Phase II) |
| Gated `bind_action` / `prove_forget` that **fail closed** | Lean/F* mechanized fail-closed proof; regulated pilot; 3rd-party audit |

Depends on the **Phase II cert v2 shape**. Because cert v2 is not finalized,
the Phase III types reference it through an **optional** `cognition_cert_commit`
(32-byte commit) — never a fabricated value (user rule §1.1; CLAUDE.md honesty).

---

## 1. Exit criteria (Phase III = done when all green)

### P3-1 — Non-repudiation (P0)
- [ ] Every external action binds to a capability **and** the sanctioning human
  identity; an action is refused without a valid certificate.
- [x] `bind_action` produces a signed `ActionReceipt` bound to the signed root
  and (when present) the cert v2 commit when `phase_iii_bind_action` is enabled;
  forged/altered receipts fail closed (`phase_iii_verify`); default build rejects.
- [x] Wire skeleton + canonical encode/decode gated by `ACTION_RECEIPT_VERSION`
  (gate closed; no store-path signer yet).
- [x] Offline Ed25519 verify over `signable_preimage` behind `phase_iii_verify`
  feature (default off); tamper tests with test keys.

### P3-2 — Verifiable forgetting (P0)
- [x] `prove_forget` / `mint_forget_proof` fold shred witness + SMT absence behind
  `phase_iii_prove_forget` (default `UnsupportedVersion`; requires `ForgetProofWitness`).
- [x] Offline verify: `verify_forget_proof` + bound shred check behind `phase_iii_verify`
  (`mneme_forget::verify_absence`, `shred_witness_commit`; default closed).
- [x] Tamper tests: resurrected key, tampered path/shred commit, wrong root → typed rejection.
- [x] Wire skeleton + canonical encode/decode gated by `FORGET_PROOF_VERSION`.
- [x] Optional cert v2 commit on wire; red-team `docs/redteam/PHASE_III_FORGET_PROOF.md`.
- [ ] Store-path mandatory forget receipts + A-REPLAY binding on every forget (separate task).

### P3-3 — Formal proof (P0)
- [ ] Mechanize the verifier's fail-closed property in Lean/F* (seL4-style); TCB
  kept tiny (≤ 500 lines).

### P3-4 — Trust ops + pilot (P1)
- [ ] HSM/KMS custody (B6 adapter against a real endpoint), revocation,
  attestation freshness; regulated-domain pilot accepts the cert as
  audit-of-record; independent 3rd-party security audit passed.

**Exit gate:** NIST 4-dim demonstrably met; published machine-checked proof;
pilot sign-off; external audit passed.

---

## 2. Module ownership

| Module | Phase III responsibility |
|---|---|
| `mneme-core` | `ActionReceipt`, `ForgetProof` wire skeletons (provisional, **not** §20.3-frozen yet); `ACTION_RECEIPT_VERSION` / `FORGET_PROOF_VERSION` |
| `mneme-account` | `bind_action` (P3-1) + `prove_forget` (P3-2) seams; `PHASE_III_GATE_OPEN` gate; fail-closed until implemented |
| `mneme-verify` | Future `verify_action_receipt` / `verify_forget_proof` gates (budgeted) |
| `mneme-store` | Wire `bind_action` into the action path; auditable forget events |

---

## 3. Honesty boundary (Phase III refinement — non-negotiable)

1. **Authenticated ≠ true.** Unchanged.
2. **`ActionReceipt` proves *authorization + non-repudiation*** — who sanctioned
   the action under which capability — **not** that the action was correct or
   its premises true.
3. **`ForgetProof` proves *crypto-shred witness + proof-of-absence under a
   signed root*** (deleted, not-served-after) — **not** that no out-of-band copy
   ever existed elsewhere.
4. **Cert v2 link is optional and never fabricated.** A `None`
   `cognition_cert_commit` means "no cognition certificate was bound", not a
   silent success.
5. **The gate is closed.** `PHASE_III_GATE_OPEN == false`; the API rejects with
   `MnemeError::UnsupportedVersion` rather than emitting an empty/placeholder
   receipt or proof.

---

## 4. Implementation log

| Date | Item | Status |
|---|---|---|
| 2026-06-03 | Phase III spec authored (from `ROADMAP.md` Phase III) | Done |
| 2026-06-03 | `mneme-core::accountability`: `ActionReceipt` + `ForgetProof` wire skeletons, `ACTION_RECEIPT_VERSION` / `FORGET_PROOF_VERSION = 3`, optional `cognition_cert_commit`, deterministic `signable_preimage` / `encode_payload` | **Landed (skeleton)** |
| 2026-06-03 | `mneme-account` crate: `bind_action` / `prove_forget` fail closed with `UnsupportedVersion`; `PHASE_III_GATE_OPEN = false` | **Landed (gated stub)** |
| 2026-06-03 | Fail-closed tests (core unit + `mneme-account` integration, incl. cert-supplied rejection) | **Landed** |
| 2026-06-03 | Canonical dCBOR encode/decode for `ActionReceipt` / `ForgetProof`, version-gated; malformed-wire tests; wire verifiers remain gate-closed | **Landed (wire-only)** |
| 2026-06-04 | `mneme-account`: `phase_iii_verify` feature — ActionReceipt Ed25519 verify + `mint_action_receipt`; ForgetProof witness/absence stubbed | **Landed (verify slice)** |
| 2026-06-04 | Store-path `bind_action` / `Store::bind_external_action` with Ed25519 mint behind `phase_iii_bind_action` (default off) | **Landed (P3-1 slice)** |
| 2026-06-04 | P3-2: `shred_witness_commit`, `prove_forget`/`mint_forget_proof` (`phase_iii_prove_forget`), `verify_forget_proof*` (`phase_iii_verify`); red-team doc | **Landed (P3-2 slice)** |
| — | Store-path mandatory forget proof on every `Store::forget` | **Deferred** (separate task) |
| — | Freeze `ActionReceipt` / `ForgetProof` into the §20.3 interface + pin domain tags | **Deferred** (post-review) |
| — | Bind cert v2 commit once Phase II finalizes cert v2 layout | **Deferred** (depends on Phase II) |
| — | Lean/F* mechanized fail-closed proof (P3-3) | **Deferred** |
| — | HSM/KMS custody, revocation, regulated pilot, 3rd-party audit (P3-4) | **Deferred** |

---

*Land the shapes and the fail-closed seam first; never ship a fabricated receipt
or proof. The gate opens only after the real proving/signing/verification logic
lands and an adversarial red-team's forgeries fail closed.*
