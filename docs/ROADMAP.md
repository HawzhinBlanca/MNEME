# MNEME ∞ — Program Roadmap (all phases, one page)

**North star:** extend MNEME's fail-closed, signed-root, receipt discipline from verifiable
**memory** → verifiable **cognition**. Every AI action ships one offline-verifiable
**Cognition Certificate**. Full thesis: [`VISION_PROOF_CARRYING_COGNITION.md`](VISION_PROOF_CARRYING_COGNITION.md).

**Standing rule (every phase):** fail-closed default · verifier TCB ≤ 500 lines · determinism
byte-identical · **authenticated ≠ true** · ship nothing until an adversarial red-team's forgeries
fail closed.

---

## Phases at a glance

| Phase | Goal | Unlocks (the new proof) | Exit gate | ~Effort | Spec |
|---|---|---|---|---|---|
| **0 ✅** | Verifiable memory | integrity · provenance · authorization of stored memory | `master` green; cross-OS determinism proven | shipped | `READINESS.md`, `MNEME_2.0_TASK_SPEC.md` |
| **I ✅** | Verifiable **retrieval** + Certificate v1 | the recall is *receipt-bound*, *time-anchored*, *un-poisoned* | `validation-lane full` + forgery red-team closed @ `d433999` (`9462a04`); offline `verify-cert`; git tag **`phase-i`** @ `42079de` (software pin: **`phase-i-software`** @ `be2b536` — predates TCB fail-open @ `a494fe0`; do not move without release policy) | shipped | [`PHASE_I_TASK_SPEC.md`](PHASE_I_TASK_SPEC.md) |
| **II** | The **Context Gate** (the kernel) | the model consumed *exactly* the certified context | strict CCA/output binding on `master` @ `01abbbc`; cert v2 draft + `context_gate` tests; TEE/RA pending — **`phase-ii-software` tag not cut** (software slice only; gate closed) | ~3–5 mo | [`PHASE_II_TASK_SPEC.md`](PHASE_II_TASK_SPEC.md) |
| **III** | **Accountability** complete | who sanctioned the action · what was forgotten · machine-checked TCB | NIST 4-dim met; Lean/F* proof; regulated pilot + 3rd-party audit — wire slice on `master`; gate closed | ~4 mo | [`PHASE_III_TASK_SPEC.md`](PHASE_III_TASK_SPEC.md) |
| **IV** | **Scale & standard** | global exact-NN; federated certificates; open spec | certificate is an interop standard; cost ≈ "default tier" — PIOP research only | ongoing | [`PHASE_IV_TASK_SPEC.md`](PHASE_IV_TASK_SPEC.md) |

The certificate grows one provable claim per phase: **0** memory → **I** + correct/temporal/clean
retrieval → **II** + attested model & sealed context → **III** + authorized action & honored
forgetting & proven core → **IV** + global-NN & cross-org federation.

```
Phase 0 ✅ ──▶ Phase I ✅ ──▶ Phase II ──▶ Phase III ──▶ Phase IV
 memory       retrieval     cognition     accountability   standard
 receipt      certificate   certificate   certificate      everywhere
```

---

## Phase I — Verifiable retrieval + Certificate v1  *(buildable today)*

**Goal:** prove a recall is receipt-bound, time-anchored, and un-poisoned; fuse into one offline cert.

**Clear steps**
1. **zkANN-1** — authenticated dominance evidence: full-set membership/completeness with top-k over prover-asserted distances (flat index) + *audit-on-demand* (HNSW). Forged/reordered/truncated top-k → typed rejection.
2. **Bi-temporal recall** — add valid-time to `Draft`; `recall_verified_at(RootSeq|ValidTime)` bound to the *historical* signed root (A-REPLAY safe).
3. **Poison-evidence** — provenance-scoped recall whose receipt proves the `written_by/since/min_tier` filter held (anti-MINJA); auditable promotion events.
4. **Certificate v1** — dCBOR schema binding root + receipt + zkANN-1 proof + time anchor + provenance attestation; `mneme certify` / `mneme verify-cert` (offline); `crossref` independent verifier.

**Exit gate:** all P1-1…P1-5 in the spec green; `validation-lane full`; forgery red-team fails closed.
**Honest level reached:** retrieval is authenticated and procedure-faithful over the committed/visited set; flat-path distances are not yet verifier-recomputed, so this is not true query-to-embedding top-k and not global exact-NN.

## Phase II — The Context Gate  *(the "almost impossible" kernel)*

**Goal:** bind an opaque model's *actually-consumed* context to the verifiable substrate — the bridge nobody has built.

**Clear steps**
1. **Enclave verify** — port the recall + zkANN-1 verification *inside* a GPU TEE (NVIDIA CC + Remote Attestation); fail-closed before any context is assembled.
2. **Deterministic assembly** — build the prompt byte-deterministically from only verified entries inside the enclave; emit `H(context)`.
3. **Context-Consumption Attestation** — enclave signs `H(assembled_context) == H(certified_memory_set)` bound to enclave report + model identity.
4. **Output binding** — fold the model's output hash into the attestation; extend Certificate → **v2 (cognition)**.

**Exit gate:** offline verify of "attested model M consumed exactly context C → output O at time t" on a real model; latency + attestation-freshness benchmarked; red-team cannot inject out-of-band context.
**Honest level reached:** **Proof-Carrying Cognition** end-to-end (chain-of-custody of the thought) — still not *truth*.

## Phase III — Accountability complete

**Goal:** finish NIST's 4 dimensions, prove forgetting, and machine-check the trust core.

**Clear steps**
1. **Non-repudiation** — bind every external action to a capability *and* the sanctioning human identity (NIST); action refused without a valid cert.
2. **Verifiable forgetting** — fold crypto-shred + proof-of-absence into the certificate (prove deleted **and** not-used-after).
3. **Formal proof** — mechanize the verifier's fail-closed property in Lean/F* (seL4-style), TCB kept tiny.
4. **Trust ops + pilot** — HSM/KMS custody (B6 adapter against a real endpoint), revocation, attestation freshness; a regulated-domain pilot accepts the cert as audit-of-record; independent 3rd-party security audit.

**Exit gate:** NIST 4-dim demonstrably met; published machine-checked proof; pilot sign-off; external audit passed.
**Honest level reached:** an audit-grade *accountability* substrate (explicitly not an oracle of truth).

## Phase IV — Scale & standard

**Goal:** turn the working system into the trust rail others build on.

**Clear steps**
1. **Global exact-NN** — land the [zkRAG-style PIOP](https://eprint.iacr.org/2026/709) over HNSW → succinct global exact-NN, retiring the last retrieval caveat.
2. **Federated certificates** — cross-org / multi-agent cognition certificates over the existing verified CRDT merge.
3. **Open spec + interop** — publish the Cognition Certificate as an open standard; align to EU AI Act Art. 50 + NIST; ship verifier SDKs in multiple languages.
4. **Cost to default** — drive prove/verify cost down until "verified cognition" is the default tier, not the premium one.

**Exit gate:** ≥1 external implementation of the verifier; a standards-track submission; production cost parity.
**Honest level reached:** verifiable cognition as infrastructure — the "trust me → here's the receipt" shift, at scale.

---

## Cross-cutting (carried through every phase)

- **Fail-closed** at every step; typed `MnemeError` rejection surface.
- **Tiny verifier TCB** is the only thing anyone must trust; everything else is checked.
- **Determinism** byte-identical across OS/arch (already proven) — extended into the enclave in II.
- **Adversarial gate** — each new proof faces a red-team that tries to forge it; ship only when forgeries fail closed.
- **Honesty ledger** — each phase states the exact level proven and what remains unproven. Never claim truth.

## Definition of done (whole program)

A third party, offline, with no trust in the operator, can take any AI action and verify:
*which attested model reasoned over which authenticated, correctly-retrieved, un-poisoned,
time-anchored memories, under which authorized human-sanctioned capability, with nothing else in
context and authorized forgetting honored* — and the verifier proving it is itself machine-checked.
That is the landscape change: **AI you can verify instead of AI you must trust.**
