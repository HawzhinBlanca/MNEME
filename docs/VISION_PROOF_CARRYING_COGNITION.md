# MNEME ∞ — Proof-Carrying Cognition

**A founder-to-team blueprint for the first verifiable cognition substrate.**
Status: vision / north-star architecture. Dated 2026-06-03. Grounded in the state of the
art as of this date (citations inline). This is deliberately ambitious — "almost impossible,
achievable with a real team in 3–12 months." It does **not** weaken MNEME's honesty boundary.

---

## 0. The one-sentence invention

> Every AI action ships with a single, **offline-verifiable certificate** proving the complete
> chain of custody of the *thought* behind it: **which attested model**, reasoning over
> **exactly which authenticated memories** (each with provenance and **proven-correct
> retrieval**), under **which authorized capability**, at **which verifiable point in time**,
> with proof that **nothing else entered the context** and that **authorized forgetting was
> honored** — checkable by anyone, without trusting the operator.

Today's frontier proves pieces in isolation. **Nobody has the bridge that turns the whole
cognitive act into one receipt.** That bridge is the invention. Call the property
**Proof-Carrying Cognition (PCC)**: as proof-carrying code shipped a proof *with* the binary,
PCC ships a proof *with* the thought.

MNEME v0/2.0 already proves **memory**. PCC extends the same fail-closed, signed-root,
receipt discipline across **retrieval → model execution → context → action → forgetting**, and
collapses it into one portable artifact.

---

## 1. Why this changes AI long-term (the thesis)

AI is moving from chatbots to **autonomous agents that act** — in finance, medicine, law,
defense, supply chains. The blocker is not capability; it is **accountability**. You cannot
deploy an autonomous agent into a regulated, high-stakes domain if you cannot *prove* what it
knew, where that came from, that it reasoned over only authorized knowledge, and who sanctioned
the action. Three independent forces converged in 2026 and all point at the same missing layer:

1. **Verifiable inference went production.** [Lagrange DeepProve-1 generated cryptographic proofs over a full LLM (GPT-2) inference](https://blog.icme.io/the-definitive-guide-to-zkml-2025/); zkPyTorch proves VGG-16 in 2.2 s. The 2026 forecast: *"proving becomes standard… unverified inference becomes the budget tier."* ([ICME](https://blog.icme.io/the-definitive-guide-to-zkml-2025/), [ZKP-VML survey](https://arxiv.org/abs/2502.18535))
2. **Attested execution went mainstream.** [NVIDIA H100/H200/Blackwell GPU TEEs](https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/) run confidential, **remotely attestable** LLM inference at **2–8 % overhead**, live today on [Phala/OpenRouter](https://phala.com/posts/GPU-TEEs-is-Alive-on-OpenRouter).
3. **Regulators now require the receipt.** [EU AI Act Article 50](https://www.softwareseni.com/eu-ai-act-and-content-provenance-regulations-making-c2pa-urgent-in-2026/) (effective **Aug 2, 2026**, penalties to €15 M / 3 % turnover) demands *full traceability, model lineage, and reconstructable decisions*. [NIST's AI Agent Standards Initiative](https://workos.com/blog/nist-ai-agent-standards-initiative-explained) (launched **Feb 17, 2026**) names four required dimensions: **identification, authorization, auditing, non-repudiation** — *"link agent actions to the human authority that sanctioned them."*

**MNEME already implements 3 of NIST's 4 dimensions for memory** (identity via signed
provenance, authorization via capabilities, auditing via receipts; non-repudiation via signed
roots). PCC finishes the set and extends it from *memory* to *cognition*. The long-term shift:
**AI stops being "trust me" and becomes "here is the receipt."** Whoever builds the trust rail
that the EU AI Act and NIST are implicitly specifying owns the substrate the next decade of
regulated, autonomous AI runs on. That is the landscape change — not a smarter model, but the
**accountability layer that makes powerful models deployable where they currently can't go.**

---

## 2. The "almost impossible" kernel (the part that is genuinely first-time)

Each pillar exists in isolation. The hard, unbuilt thing is the **binding**:

> **Prove that an opaque neural model consumed *exactly* the certified memory set — no more,
> no less — and that its output is bound to that exact context.**

ZK-proving an entire LLM's forward pass is still impractical at frontier scale and would not,
by itself, prove *what context went in*. The breakthrough is to **not** prove the model, but to
**seal the boundary** around it:

**The Context Gate (TEE-resident, the novel kernel).** Inside the GPU TEE enclave, a tiny,
formally-verified component is the **only** path by which memory may enter the model's context
window. It:

1. receives the MNEME recall receipts + the **zkANN retrieval-correctness proof** (§3.2),
2. verifies them *inside the enclave* against the signed root (fail-closed),
3. assembles the prompt **deterministically** from only the verified entries,
4. emits a signed **Context-Consumption Attestation**: `H(assembled_context) == H(certified_memory_set)` bound to the enclave's attestation report and the model identity,
5. forwards the context to the model, and binds the model's output hash back into the attestation.

Now a verifier, offline, can check: *the attested model M, running in a genuine enclave, was
fed precisely the certified context C (and nothing injected out-of-band), and produced output
O bound to (M, C, t).* This **bridges the verifiable-memory world and the attested-inference
world** — the gap nobody has closed. It is achievable because every primitive (TEE attestation,
in-enclave verification, deterministic assembly, Merkle/signature checks) exists *today*; the
invention is composing them into one fail-closed boundary with a **tiny, formally-proven TCB**
and a single portable certificate. That composition, at production reliability, is the 3–12
month moonshot.

---

## 3. The integrated system — 9 processes fused into one substrate

```
            ┌───────────────────────────  COGNITION CERTIFICATE  ──────────────────────────┐
            │  one portable, offline-verifiable artifact (NIST 4-dim + EU AI Act lineage)    │
            └────────────────────────────────────┬──────────────────────────────────────────┘
                                                  │ assembled from ↓
  (1) Verifiable        (2) Proven-correct    (3) Attested        (4) Context-Consumption
      Memory      ─────▶    Retrieval     ───▶    Execution   ◀──▶    Proof  (THE KERNEL)
   (MNEME today)          (zkANN)             (GPU TEE)            (in-enclave context gate)
       │                      │                   │                      │
       ▼                      ▼                   ▼                      ▼
  (5) Capability-Bound Action   (6) Bi-Temporal Ledger   (7) Poison-Evidence   (8) Verifiable
      + NIST non-repudiation        (time-travel audit)      (anti-MINJA)          Forgetting
                                                  │
                                          (9) Formal Proof of the fail-closed TCB (Lean/F*)
```

| # | Process | What it proves | Seed in MNEME today |
|---|---|---|---|
| 1 | **Verifiable memory** | integrity / provenance / authorization of each stored memory | ✅ shipped (signed root, receipts, fail-closed) |
| 2 | **Proven-correct retrieval (zkANN)** | the returned k *are* the true top-k of the committed index — upgrades *procedure-faithful → retrieval-correct* | seam exists (`plonky2_prover`); needs [zkRAG/V3DB-style HNSW PIOP](https://eprint.iacr.org/2026/709) |
| 3 | **Attested execution** | the genuine model weights ran unmodified in a sealed enclave | new: NVIDIA CC + Remote Attestation |
| 4 | **Context-consumption proof** | the model ingested *exactly* the certified memory set, nothing injected | **new — the kernel (§2)** |
| 5 | **Capability-bound action + non-repudiation** | every external action was authorized and links to the sanctioning human | caps shipped; bind to action + identity ([NIST](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)) |
| 6 | **Bi-temporal ledger** | what was known *when*; reconstruct any past decision (EU AI Act traceability) | DAG + HLC + checkpoints shipped; add valid-time + `recall_verified_at` |
| 7 | **Poison-evidence** | the recall was *not* attacker-injected (defeats [MINJA, 95 % success](https://arxiv.org/html/2604.16548v1)) | trust tiers + quarantine + promote shipped; compose into a provenance-scoped recall proof |
| 8 | **Verifiable forgetting** | a memory was truly crypto-shredded and *not used after deletion* | crypto-shred + prove-absent shipped; bind absence into the certificate |
| 9 | **Formal proof of the TCB** | the fail-closed property holds for *all* inputs (not just tests) | TCB ≤500 lines today; mechanize in Lean/F* (seL4-style) |

The unification: **all nine emit evidence into one signed structure, the Cognition
Certificate**, verifiable offline by a regulator, a counterparty agent, or an auditor — with a
**single tiny verifier TCB** they can read in an afternoon.

---

## 4. End-to-end pipeline (every step, fail-closed)

```
INGEST → CERTIFY → STORE → QUERY → PROVE-RETRIEVAL → ENCLAVE-VERIFY → ASSEMBLE-CONTEXT
       → ATTEST-INFER → BIND-OUTPUT → AUTHORIZE-ACTION → EMIT-CERTIFICATE → VERIFY-OFFLINE
```

1. **Ingest** — content enters at `Quarantine` tier with a write-provenance receipt (who/when/cap).
2. **Certify & store** — atomic, `.incomplete`-guarded write; signed root (MNEME today).
3. **Query** — agent issues a query + declared procedure + capability.
4. **Prove-retrieval (zkANN)** — recall returns entries **plus a proof the top-k is correct** for the committed root.
5. **Enclave-verify** — the Context Gate, *inside the TEE*, re-checks every receipt + the zkANN proof against the signed root. Any failure → **fail closed**, no context assembled.
6. **Assemble-context** — deterministic prompt build from only verified entries; emit `H(context)`.
7. **Attest-infer** — the GPU TEE produces a fresh attestation report binding (enclave, model id, `H(context)`); model runs.
8. **Bind-output** — output hash folded into the Context-Consumption Attestation.
9. **Authorize-action** — any external effect is gated by a capability token bound to the sanctioning identity (NIST non-repudiation).
10. **Emit-certificate** — assemble processes 1–9 + the bi-temporal anchor + forgetting-absence proofs into the **Cognition Certificate**.
11. **Verify-offline** — the open-source verifier SDK checks the whole chain with no trust in the operator. **No valid certificate → the action is not accepted.**

Reliability discipline (carried from MNEME, extended): fail-closed at every arrow; deterministic
replay (cross-OS/arch byte-identity already proven); adversarial multi-agent review of each
gate; generative tamper + fuzz on every wire format; attestation **freshness + revocation**;
and the §9 formal proof on the verifier core.

---

## 5. Architecture & module ownership (hand this to the company)

| Layer | Component | New vs. extend | Owning team |
|---|---|---|---|
| L0 Substrate | MNEME store kernel, signed roots, caps, forget | extend | **Core Kernel** |
| L1 Retrieval-proof | zkANN prover/verifier over HNSW | new (research) | **Cryptography / ZK** |
| L2 Enclave | Context Gate (TEE-resident verify + deterministic assemble + attest) | **new — kernel** | **Confidential Computing** |
| L3 Inference | attested model runtime, attestation capture, output binding | new (integration) | **ML Systems** |
| L4 Action | capability→action binding, identity / non-repudiation | extend | **Identity & Authz** |
| L5 Time | bi-temporal ledger, `recall_verified_at`, audit replay | extend | **Core Kernel** |
| L6 Certificate | certificate schema, assembler, **offline verifier SDK + formal proof** | new | **Verifier TCB (small, elite)** |
| L7 Trust ops | revocation, attestation freshness, key custody (HSM/KMS), policy | extend (B6 seam) | **Security / SRE** |

**Invariant for the whole program:** the *verifier* TCB stays tiny and is the only thing anyone
must trust. Everything else can be untrusted and is checked. (This is MNEME's existing
discipline — `TCB_LINE_BUDGET`, fail-closed — scaled to cognition.)

---

## 6. Program plan — 3 phases, ~12 months

**Phase I (months 0–3): Verifiable Retrieval + Certificate v1**
- Cryptography: ship **zkANN** correctness proof over the existing HNSW (procedure-faithful → retrieval-correct). *Exit:* forged top-k rejected with a typed error; <X ms prove at 10k.
- Kernel: bi-temporal ledger + `recall_verified_at`; poison-evidence provenance-scoped recall.
- Verifier: **Cognition Certificate v1** schema (memory + retrieval + time), offline verifier SDK.
- *Milestone:* "prove what was recalled, that it was the true match, that it wasn't poisoned, and when" — already beyond anything shipping in 2026.

**Phase II (months 3–8): The Context Gate (the kernel)**
- Confidential Computing: TEE-resident Context Gate — in-enclave receipt + zkANN verification, deterministic assembly, Context-Consumption Attestation. Integrate NVIDIA Remote Attestation.
- ML Systems: attested inference runtime; bind model id + output hash.
- *Milestone:* end-to-end **PCC** on one model in a TEE — offline-verify "this model consumed exactly this certified context and produced this output." **This is the first-of-its-kind result.**

**Phase III (months 8–12): Non-repudiation, Forgetting, Formal Proof, Scale**
- Identity & Authz: capability→action binding + human-sanction linkage (NIST 4-dim complete).
- Kernel: verifiable forgetting folded into the certificate (prove deleted + not-used-after).
- Verifier TCB: **machine-checked proof** of the fail-closed property (Lean/F*), seL4-style.
- Security/SRE: HSM/KMS custody, revocation, attestation freshness, throughput hardening.
- *Milestone:* a regulated-domain pilot (finance or health) accepts MNEME ∞ certificates as the audit-of-record; independent third-party security audit; the formal proof published.

Run each phase as a **fan-out → adversarially-verify → synthesize** program (the same
multi-agent discipline used to harden v0/2.0): independent teams build, an independent red team
tries to forge each proof, nothing ships until forgeries fail closed.

---

## 7. What would make it Nobel-tier / first-time — and the honest risks

**Genuinely first-time:** the **Context-Consumption Proof** (process 4) and its fusion of
verifiable memory + proven retrieval + attested execution into **one portable cognition
certificate with a formally-verified verifier**. No system in 2026 binds *what an opaque model
actually consumed* to a verifiable memory substrate. If it works at production reliability with
a machine-checked TCB, it is a foundational accountability primitive for AI — the kind of result
standards bodies build on.

**Hard risks (named, not hidden):**
- **zkANN latency** at frontier index sizes — may need audit-on-demand (V3DB-style) rather than every-call proofs.
- **TEE trust model** — you trust the hardware vendor's root of trust; side-channels exist. Mitigation: attestation freshness, defense-in-depth, and *honesty about the assumption*.
- **Determinism inside the enclave** — prompt assembly must be byte-deterministic (MNEME's proven cross-OS determinism is the foundation; extend it into the gate).
- **Formal proof scope** — prove the *verifier* fail-closed property, not the model; keep the TCB tiny enough to mechanize.

**Honesty boundary (unchanged, non-negotiable):** PCC proves **chain of custody and faithful
execution** — *which* model reasoned over *which* authenticated memory, retrieved correctly,
authorized, in time. It does **not** prove the memory is **true**, nor that the model's
reasoning is **wise**. Authenticated ≠ true. Verifiable ≠ correct-in-the-world. A Nobel-tier
*accountability* substrate, explicitly **not** an oracle of truth. That honesty is what makes
the rest believable.

---

*MNEME today proves the memory. MNEME ∞ proves the thought. The first is shipped and verified.
The second is the moonshot — and every primitive it needs now exists.*
