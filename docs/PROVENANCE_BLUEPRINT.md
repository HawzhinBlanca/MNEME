# PROVENANCE — Operational Blueprint
### A verifiable, attributable, reversible substrate for self-improving agents, built on MNEME

> **Status:** research-and-build program, not a product roadmap. Generated 2026-06-20 from an 18-agent design workflow grounded in live 2025–26 SOTA research and the real MNEME repo, then audited by an anti-hype critic. The three independent architectures it fused all scored **feasibility 2/5** — meaning the *substrate is real and shipped, the cognition layers are a multi-year frontier bet*. Read §0 before anything else.

---

## §0 — Reality Ledger (canonical; overrides any looser statement below)

Every number and claim in this section is verified against the codebase at generation time. Where the body sections and this ledger disagree, **the ledger wins**. This is MNEME's own doctrine applied to its own blueprint: ship the limits as visible front-matter.

**Verified facts**
- **Verifier TCB = 464 source lines** (`find crates/mneme-verify/src -name '*.rs' | wc -l`). The "394" and "474" figures elsewhere in drafts are wrong; the budget is `< 500`, the measured number is **464**. The counting rule is: all `.rs` under `mneme-verify/src`, excluding tests in other crates.
- **What is SHIPPED and real today (the moat):** the fail-closed verified-read gate (`recall_verified`, INV-5; untrusted `recall` is `pub(crate)`), the signed-root store, and **provable + attributable + reversible deletion** — FCC **T1** crypto-shred and **T2** SMT non-membership bound to a fresh signed root, with `prove_absent` rejecting live keys and the `mneme-accum` non-use witness (`crates/mneme-forget/src/absent.rs`, `crates/mneme-accum/`). This is the single load-bearing, genuinely-novel contribution and the one whose honesty boundary is narrow and survivable: **substrate deletion, not model-weight unlearning.**
- **What does NOT exist in code yet (future tense, do not read as present):** the `self-evolve` capability scope (zero references in `crates/`); the neural/cognition layers **L1–L6** (experience generator, test-time memory, skill library, latent reasoning, consolidation) — these are *integration targets*, not shipped code.
- **ROBR-3 Freivalds is NOT wired into the ROBR receipt path** — it is a standalone CLI verb (`crates/mneme-cli/src/freivalds.rs`) with no callers in `mneme-account`/`mneme-store`. It is a spot-check you can run, not an always-on part of receipt minting.
- **ROBR store-path minting (`bind_action`) is feature-gated and default-closed** (`PHASE_III_BIND_ACTION_OPEN`). Today the only exercised ROBR path is the CLI. "Each run emits a ROBR receipt" describes the *target* loop, not current default behavior.
- **The "10x" is governance-shaped, and the cost claim is bounded honestly:** **O(1) human decisions per event, O(log n) machine verification** (MTL inclusion and SMT proofs are `O(log n)` tree depth + a signature check) — not literal O(1). The economic claim is that *human* oversight drops from `O(steps)` review to `O(1)` receipt-acceptance with `O(challenge)` only on dispute.

**Honesty corrections folded in from the audit (these override the body):**
- **T3 `(ε,δ)` DP-influence is operator-asserted, not cryptographic.** It is NOT in the same class as T1/T2. "Operator-asserted" means a human types a number with no verification. Keep it visually and conceptually separate from the proven deletion tiers.
- **The Convergence Certificate is a tripwire, not a brake.** A reward-hacked task still produces a clean signed certificate; a monotone-progress ratchet over a *proxy* metric + canaries is a *logging/alerting* guarantee, not containment. Never call it a safety "brake."
- **Cross-operator non-equivocation (the Y5 gate) is an ecosystem precondition, not a deliverable.** It closes *if and only if* ≥2 genuinely independent honest operators run mutual MTL witness gossip. An engineering agency cannot land it on a schedule by writing software; budget it as "closes IFF an independent witness exists."
- **ROBR binds context, not cognition; authenticated ≠ true; FCC deletes substrate records, not weights.** These walls never move.

**The honest bottom line:** PROVENANCE's defensible, fundable core is *the verifiable substrate + reversible deletion + the proof-carrying-autobiography pattern* — shippable on real primitives. The self-improvement engine (L1–L6) is a genuine multi-year research program with three aspirational bets (DiFR execution-settlement, a production TEE attestor, cross-operator non-equivocation), each of which can fail. §05 and §06 must be read with that off-ramp in mind.

---

## Program Skeleton (canonical architecture)

# PROVENANCE — Program Skeleton

> **Naming decision (canonical):** The spine is **PROVENANCE**. All three audited designs are architecturally identical (same MNEME spine, same SOTA grafts, all three "merge"). PROVENANCE is chosen as the spine because its thesis names the *actual* contribution most precisely — **governability of an autonomous learner**, not "a smarter agent" (ANAMNESIS) or "an agent OS" (NOEMA), both of which overreach toward the unbuilt neural layers the adversaries flagged. The two headline mechanisms — **Proof-Carrying Autobiography (PCA)** and **substrate-reversible learning (FCC)** — were independently identified as the `strongest_idea` in **all three** verdicts. We graft NOEMA's cleanest framing ("the hard commit boundary": the *only* input path into the fast loop is `recall_verified`) and ANAMNESIS's awareness-model articulation onto PROVENANCE's oversight-economics spine. Section-writers MUST use the layer IDs and names below verbatim.

---

## (a) System + 10x Thesis

**PROVENANCE** — *the Proof-Carrying Self: a verifiable, attributable, reversible substrate for self-evolving agents.*

PROVENANCE wraps a self-evolution loop (propose → solve-with-verifiable-reward → consolidate → test-time-adapt → act) inside MNEME's shipped fail-closed substrate so that **every capability change becomes a signed transaction**: a signed Ed25519 root with operator-asserted lineage (`Draft.parent_ids`), a capability token that authorized the rewrite, a PACE sequential-work timestamp, an MTL transparency-log leaf, and an FCC-reversible ForgetProof. The 10x is **not benchmark-shaped — it is governance-shaped**: today's self-evolving agents (DGM 2505.22954, AZR 2505.03335) improve with an unsigned, silently-mutable, irreversible archive, so oversight is `O(steps)` of human review and a single bad mutation is undetectable, unattributable, and unrollbackable. PROVENANCE converts the four unprovable properties into checkable artifacts — **attribution** (MTL inclusion proof over a signed root), **execution** (challengeable ROBR receipt), **deletion** (T1+T2 ForgetProof), **continued non-use** (per-recall accumulator witness) — dropping the marginal cost of safely granting *more* autonomy by ~10x (oversight moves to `O(1)` receipt-checking, `O(challenge)` only on dispute). The load-bearing honesty wall never moves: **authenticated ≠ true; ROBR binds context, not cognition; FCC deletes substrate records, not model weights; single-operator MTL gives no non-equivocation without external witnesses.**

---

## (b) Canonical Layered Architecture

Each layer is `Ln — Name :: SOTA grafted → MNEME primitive`. **Substrate layers (L0, L7, L8) are SHIPPED today; cognition layers (L1–L5) are integration targets, not shipped code** — section-writers must mark them as such.

- **L0 — Verifiable Substrate (root of trust)** *[SHIPPED]*
  → SOTA: *none* (this is the differentiator the SOTA lacks; it makes Letta/A-MEM memory tamper-evident instead of silently mutable). zkLLM (2404.16109, ~25h/100 tok) is the *negative anchor* justifying optimistic-not-SNARK.
  → MNEME: `Store::remember` (atomic `.incomplete` guard + SMT upsert + signed Root) · `recall_verified`/`recall_verified_default` (INV-5 fail-closed; untrusted `recall` is `pub(crate)`) · single-writer flock · INV-6 cold-open A-REPLAY rejection · 500-line verifier TCB.

- **L1 — Experience Generator (self-play / RLVR)** *[INTEGRATION TARGET]*
  → SOTA: AZR (2505.03335 proposer+solver+verifiable-reward, zero external data) · SPIRAL (2506.24119) · Search Self-play (2510.18821) · Self-Evolving Agents survey (2508.07407 / 2507.21046).
  → MNEME: scoped `self-evolve` capability token (attenuate-only) gates every commit · tool-written self-tasks auto-Quarantine · `recall_verified` (INV-5) is the **only** read path into the next proposer.

- **L2 — Fast Plastic Memory (test-time adaptation / L1 cache)** *[INTEGRATION TARGET]*
  → SOTA: Titans (2501.00663 learn-to-memorize-at-test-time, >2M ctx) · Test-time regression (2501.12352) · Nested Learning (2512.24695 multi-timescale license).
  → MNEME: `recall_verified` output is the **sole** I/O membrane seeding the neural context (the *hard commit boundary* — fast loop can never ingest unauthenticated data) · Titans delta checkpointed as a signed object with `context_ids` · FCC reverts a poisoned checkpoint to last clean root. *Honest scope: substrate governs the checkpoint object, NOT the weights.*

- **L3 — Verifiable Skill Library (world-model as reversible objects)** *[INTEGRATION TARGET]*
  → SOTA: Voyager (executable/compositional/anti-forgetting) · AutoSkill (2603.01145) · EvoSkill (2603.02766) · Lifelong-Learning roadmap.
  → MNEME: key-index SMT + `Draft.parent_ids` DAG for composition lineage · `recall_verified` gating skill retrieval · EvoSkill merge = `forget()`+`remember()` supersede with ForgetProof · `pedersen_schnorr_zk` set-equality NIZK for witness-private proof-of-reuse · trust tiers Quarantine→Working→Trusted→Identity.

- **L4 — Latent Reasoning with a Receipt** *[INTEGRATION TARGET]*
  → SOTA: Coconut (2412.06769) · Reasoning by Superposition (2505.12514) · Latent Reasoning Survey (2507.06203) · CODI.
  → MNEME: ROBR context-binding absorbs the per-inference thought-chain Merkle root · `mneme-pace` BLAKE3 sequential-work log proves the latent BFS consumed real elapsed work · `mneme-optimistic` WatcherChallenge re-runs a latent segment. *Honest scope: proves reproducible + time-bounded, NOT semantically faithful.*

- **L5 — Sleep-Time Consolidation (governed promotion pipeline)** *[INTEGRATION TARGET]*
  → SOTA: Letta sleep-time compute · A-MEM (2502.12110) · Hindsight 20/20 (2512.12818) · LiCoMemory (2511.01448) · FOREVER (2601.03938) · MemArchitect (2603.18330).
  → MNEME: `recall_verified` consolidation input · `remember()` per consolidation → fresh signed root → MTL leaf · `promote`-scoped capability · batch ForgetProof retiring absorbed raw episodes · FOREVER canaries under protected keys.

- **L6 — Verifiable Execution (execution-integrity)** *[PARTIAL: ROBR-1 envelope SHIPPED; DiFR settlement UNBUILT]*
  → SOTA: DiFR (2511.20621 nondeterminism-tolerant re-execution — the realistic ROBR-2 path) · VeriLLM (2509.24257) · Optimistic TEE-Rollups (2512.20176) · TEE on H100 (<7% overhead, optional ROBR-4) · zkLLM (2404.16109, negative anchor).
  → MNEME: `mneme-account` ROBR receipt (envelope = `H(memory_root|prompt|weight_measurement|sampling|context)`) · ROBR-3 Freivalds matmul spot-check (≤2⁻⁶⁴) · ROBR-4 optional TEE hardening · `mneme-optimistic` TopKClaim/WatcherChallenge/`verify_challenge` · `mneme-gate` `verify_output_binding`. *Honest scope: binds context, does NOT prove the model executed; `weight_measurement` operator-asserted; `mneme-attest` is a PEM/DER shape-parser, NOT a production attestor.*

- **L7 — Reversible Learning (FCC with a proof)** *[SHIPPED]*
  → SOTA: *none on deletion side* (MNEME-native); GDPR erasure as requirement; RPT watermark as statistical corroborator only.
  → MNEME: tiered FCC — T1 crypto-shred / T2 SMT non-membership bound to a fresh signed root / T3 (ε,δ) DP-influence (operator-asserted) · `mneme-accum` `prove_nonuse_after_forget`/`NonMembershipWitness` · DAG lineage re-walk for tainted descendants · `recall_verified` fail-closed blocks re-entry. *Honest scope: proves SUBSTRATE deletion + non-use in the operator-presented set, NOT model-weight unlearning.*

- **L8 — Governance, Pacing & Scalable Oversight (the safety brake)** *[SHIPPED]*
  → SOTA: MemArchitect (2603.18330, governance target reframed cryptographically) · FOREVER canaries (2601.03938) · Group-Evolving peers (2602.04837, watcher candidates) · Optimistic TEE-Rollups (2512.20176, challenge-window economics).
  → MNEME: `mneme-pace` sequential-work spacing (monotone clock over the evolutionary DAG) · MTL RFC6962 inclusion+consistency · signed Root sequence + INV-6 (no rollback to stale state) · attenuate-only capability per action · **Convergence Certificate** auto-rewind via FCC on a failed monotone-progress predicate. *Honest scope: PACE bounds minimum spacing only (T5), not max staleness; single-operator MTL gives no non-equivocation.*

- **L9 — Awareness / Self-Model & Agent Surface** *[SHIPPED surface; depends on L1–L5 for content]*
  → SOTA: latent-reasoning receipt design (Coconut 2412.06769 / 2505.12514) for reasoning over the autobiography.
  → MNEME: `mneme-mcp` stdio server (honesty strings in tool descriptions) · `mnemed` daemon (HTTP `:7845` / unix / ws) · `recall_verified` as the **sole** self-model read path · MTL inclusion proofs externalize the autobiography to an auditor.

> **The Awareness Self-Model has exactly four queryable faces** (canonical, for L9 writers): **WHAT I KNOW** (SMT membership under HEAD) · **WHAT I USED** (ROBR `context_ids` + `pedersen_schnorr_zk` set-equality proof-of-reuse) · **WHAT I FORGOT** (FCC ForgetProofs + accumulator non-use witnesses) · **HOW I CHANGED** (PACE-spaced, MTL-logged signed-root DAG). All causal edges are operator-**asserted**, not proven.

---

## (c) End-to-End Learning-from-Use Loop

Each step is a substrate-enforced gate. `R_n` = the signed root minted at that step.

1. **PROPOSE** (L1→L8) — AZR proposer reads context **only** via `recall_verified` (INV-5) over the autobiography DAG; invents a task at the edge of competence. Committed under the `self-evolve` capability → **auto-Quarantine** → `R_propose`, with `parent_ids = [ancestor variant root, recall-verified source episodes]`. PACE stamps minimum sequential work since the prior proposal (rate-limit).
2. **SOLVE + REWARD** (L1) — solver produces a trajectory; a verifiable reward (code execution / proof check) is computed and bound as a cognition-cert on an `ActionReceipt`. A passing reward promotes Quarantine→Working — promotion **requires** a `promote` capability (no skill graduates without Ed25519 authorization).
3. **EXECUTE-VERIFY** (L6) — the run emits a ROBR receipt; DiFR re-executes under nondeterminism tolerance; a 1-of-N watcher MAY challenge within the window (`mneme-optimistic`). Absent a valid challenge, it finalizes with `O(1)` verify. Latent steps (L4) carry their own thought-chain + PACE elapsed-work proof.
4. **PACE + LOG** (L8) — `R_propose`/`R_solve` appended as MTL leaves (RFC6962 inclusion+consistency); INV-6 blocks silent rewind to a stale variant.
5. **FAST-ADAPT** (L2) — within the live session, Titans neural memory adapts from surprise, seeded **only** by `recall_verified` output; on a surprise/cadence trigger the delta is checkpointed as a signed object (revertible).
6. **SLEEP-CONSOLIDATE** (L5) — at idle, A-MEM/Hindsight-20/20 distill Working episodes into Voyager skills; each consolidation = a signed-root transition → MTL leaf; a skill graduates Working→Trusted only after its self-test passes under a ROBR/DiFR receipt; EvoSkill merges supersede via `forget()`+`remember()` with a ForgetProof.
7. **CERTIFY** (L8) — at epoch boundary, the **Convergence Certificate** predicate is checked against the prior epoch root: reward non-decreasing on a held-out verifiable set **AND** no regression on FOREVER forgetting-canaries. PASS ⇒ commit + MTL consistency proof (epoch N dominates N−1, signed); FAIL ⇒ FCC auto-rewind to last certified root.
8. **ACT** (L8) — external action fires only behind a capability token + `ActionReceipt`; its effect feeds back as new authenticated experience into step 1.
9. **REVERSE-ON-DEMAND** (L7) — if a step is later condemned (user revocation, discovered reward-hack, jailbreak): `forget()` issues T1 crypto-shred + T2 SMT non-membership against a fresh root + accumulator non-use witness; the DAG is re-walked from the last clean root to re-derive tainted descendants; L2 reverts to its last clean checkpoint.

> **The failure the loop cannot close:** it proves the loop *ran honestly and is logged faithfully*; it cannot prove the reward signal was semantically meaningful. **A reward-hacked task gets a clean PCA lineage and a valid ROBR receipt.** (`authenticated reward ≠ true reward`.)

---

## (d) The 5 Hardest Bets

1. **The execution gap.** Can ROBR ever bind to a *real* frontier model, not a deterministic toy kernel? Closing it needs a batch-invariant backend (nonexistent at scale), a production TEE attestor (`mneme-attest` is shape-parse only), or DiFR with a *calibrated* false-accept rate — and DiFR's tolerance band τ is itself a soundness knob an adversary probes. Until closed, PROVENANCE proves the **box** around cognition, never the cognition. **DiFR is uncited in the codebase today** — the entire L6 settlement story is unbuilt.
2. **Reward-hacking inside the verifiable loop.** RLVR verifies the *proxy*, not the intent. A degenerate skill gets clean lineage, a valid receipt, and a signed Convergence Certificate. The substrate makes the **wrong** improvement perfectly auditable and reversible but **cannot detect that it is wrong** — and durably amplifies whatever the loop produces.
3. **Single-operator equivocation + max-staleness.** MTL gives inclusion+consistency but **no non-equivocation** without external witness gossip; the 1-of-N-honest-watcher fraud-proof game collapses when a local-first agent has no independent watcher (two-host determinism is unproven in repo memory). PACE bounds *minimum* spacing only (T5), so "the agent did not secretly evolve off-log" is unproven. The repo *ships its own counterexample* (`accum/t8_counterexample.rs`).
4. **Substrate deletion ≠ model unlearning.** FCC T1/T2 prove the record is shredded and absent; the accumulator proves substrate non-use. But a poisoned skill already consolidated into Titans/base weights is **not** reverted — only rolling weights to a prior checkpoint removes it, losing all good learning since. T3 (ε,δ) DP-influence is operator-asserted and scale-limited. The UX must never imply the weights forgot.
5. **Verification cost vs learning throughput, and the cognition layers are unbuilt.** Per-step sign + SMT-upsert + PACE work + the single-writer flock serialize a loop AZR/DGM run at high frequency, forcing receipt batching that widens the unattested-action window. Compounding this: **L1/L2/L3/L4/L5 are zero lines of code today** — all SOTA citations, no integration. The `self-evolve` capability scope, the Convergence Certificate ratchet, and DiFR do not yet exist; `bind_action` is default-closed (`phase_iii_bind_action`).

---

## (e) Honest-Frontier Statement

**PROVENANCE proves the *box* around an agent's self-evolution — that it ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt — but it cannot prove the cognition inside the box was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists; it makes the wrong improvement perfectly auditable and reversible without making it detectable.**

---

**Files relevant to section-writers (all absolute):** `/Users/hawzhin/MNEME/CLAUDE.md` (honesty wall §3, invariants INV-5/INV-6, workspace layout) is the canonical authority — every layer's honesty scope must trace to a string in `MnemeError`, MCP tool descriptions, or verifier exports. Shipped substrate crates back L0/L7/L8/L9: `mneme-store`, `mneme-verify`, `mneme-root`, `mneme-smt`, `mneme-forget`, `mneme-accum`, `mneme-account`, `mneme-optimistic`, `mneme-pace`, `mneme-cap`, `mneme-mcp`, `mnemed`. Cognition layers L1–L5 and the DiFR path in L6 have **no backing crate** and must be written as integration targets, not shipped capability.


---

# 01 — Vision & Thesis

## PROVENANCE — The Proof-Carrying Self

> A verifiable, attributable, reversible substrate for self-evolving agents.

---

## The one sentence that bounds everything

**PROVENANCE proves the *box* around an agent's self-evolution — that it ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt — but it cannot prove the cognition inside the box was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists; it makes the wrong improvement perfectly auditable and reversible without making it detectable.**

Every claim in this blueprint lives inside that boundary. An engineer who finds a layer promising something stronger has found a bug in the spec, not a feature.

---

## The 10x thesis

The 10x is **governance-shaped, not benchmark-shaped.**

Today's self-evolving agents — Darwin Gödel Machine (arXiv 2505.22954), Absolute Zero / AZR (arXiv 2505.03335) — improve by mutating an archive that is **unsigned, silently mutable, and irreversible.** That architecture forces human oversight to scale as `O(steps)`: to trust the agent you must review the process, because the artifacts carry no trust of their own. A single bad mutation — a reward-hack, a jailbroken skill, a poisoned episode — is undetectable, unattributable, and unrollbackable after the fact.

PROVENANCE wraps the self-evolution loop (`propose → solve-with-verifiable-reward → consolidate → test-time-adapt → act`) inside MNEME's shipped fail-closed substrate so that **every capability change becomes a signed transaction**: a signed Ed25519 root, operator-asserted lineage (`Draft.parent_ids`), the capability token that authorized the rewrite, a PACE sequential-work timestamp, an MTL transparency-log leaf, and an FCC-reversible ForgetProof.

That converts four properties that are *unprovable* in the SOTA archive into *checkable artifacts*:

| Property | SOTA today | PROVENANCE artifact | Oversight cost |
|---|---|---|---|
| **Attribution** — what produced this change | folklore | MTL inclusion proof over a signed root | `O(1)` verify |
| **Execution** — the run happened as recorded | trust | challengeable ROBR receipt | `O(1)`, `O(challenge)` on dispute |
| **Deletion** — the record is gone | `rm` + hope | T1+T2 ForgetProof (crypto-shred + SMT non-membership) | `O(1)` verify |
| **Continued non-use** — it stays gone | unprovable | per-recall accumulator witness | `O(1)` per recall |

The economic claim is precise: oversight moves from `O(steps)` of human process-review to `O(1)` receipt-checking, with `O(challenge)` cost incurred **only on dispute**. That is the ~10x — it drops the marginal cost of *safely granting more autonomy*, which is the actual scarce resource as agents self-modify. We do not claim a 10x on any task benchmark; the agent inside the box is exactly as good as its cognition layers make it.

---

## The genuinely novel contribution

The novel piece is **Proof-Carrying Autobiography (PCA)** coupled to **substrate-reversible learning (FCC)** — flagged as the single strongest idea in all three upstream design audits, independently.

No prior system gives a self-modifying agent a tamper-evident, attributable, *reversible* record of its own evolution. The SOTA memory systems it must exploit are silently mutable by construction:

- **Letta** three-tier memory + sleep-time compute, **A-MEM** (arXiv 2502.12110), **Hindsight 20/20** (arXiv 2512.12818), **MemArchitect** (arXiv 2603.18330) — all govern memory by *policy*, none by *cryptographic receipt*.
- **Titans** test-time neural memory (arXiv 2501.00663), **Nested Learning** (arXiv 2512.24695) — adapt during inference with no audit surface at all.

PROVENANCE makes that memory **tamper-evident instead of silently mutable**, and adds the property none of them has: a deletion you can *prove*. FCC ships three tiers today — T1 crypto-shred, T2 SMT non-membership bound to a fresh signed root, T3 `(ε,δ)` DP-influence (operator-asserted) — with `mneme-accum` providing `prove_nonuse_after_forget` / `NonMembershipWitness`. On the deletion side there is **no SOTA to graft**; this is MNEME-native and is the differentiator.

The deliberate negative anchor is **zkLLM** (arXiv 2404.16109): a full 100-token ZK-proven inference costs ~25h today. That is why PROVENANCE is **optimistic, not SNARK** — we verify with receipts and challenge windows (`mneme-optimistic`), not with proofs of the forward pass. Honesty wall, never moved:

- **authenticated ≠ true** — a signed entry verifies even when its content is false;
- **ROBR binds context, not cognition** — it proves the box, not that the model executed;
- **FCC deletes substrate records, not model weights** — the UX must never imply the weights forgot;
- **single-operator MTL gives no non-equivocation** without external witnesses.

---

## Who it is for

1. **Operators of autonomous, self-improving agents** who must answer "what changed, who authorized it, and can I undo it?" under audit, incident response, or regulatory erasure (GDPR Art. 17). PROVENANCE is the accountability substrate beneath an AZR/DGM-style loop.
2. **Builders of the cognition layers** — RLVR self-play (AZR 2505.03335, SPIRAL 2506.24119), neural test-time memory (Titans 2501.00663), skill libraries (Voyager, EvoSkill 2603.02766), consolidation pipelines (A-MEM, Hindsight 20/20) — who want their learning loop to inherit attribution, pacing, and reversibility *for free* by reading **only** through the hard commit boundary (`recall_verified`, INV-5).
3. **Auditors and safety reviewers** who need to externalize an agent's autobiography — its four queryable faces: **WHAT I KNOW** (SMT membership under HEAD), **WHAT I USED** (ROBR `context_ids`), **WHAT I FORGOT** (ForgetProofs + non-use witnesses), **HOW I CHANGED** (PACE-spaced, MTL-logged signed-root DAG). All causal edges are operator-*asserted*, not proven.

---

## What is real now vs. achievable vs. aspirational

This is the most important paragraph for a multi-year build. The maturity split is uneven *by design*: the substrate is shipped and the cognition is not.

**Real now (shipped substrate — L0, L7, L8, L9 surface).** The verifiable foundation exists in Rust today: `Store::remember` (atomic `.incomplete` guard + SMT upsert + signed root) and the fail-closed `recall_verified` read path (INV-5; untrusted `recall` is `pub(crate)`); single-writer `flock`; INV-6 cold-open A-REPLAY rejection; the ~474-line verifier TCB under a 500-line budget; FCC T1/T2/T3 with accumulator non-use witnesses; the ROBR-1 receipt envelope `H(memory_root | prompt | weight_measurement | sampling | context)` with Freivalds matmul spot-check (≤2⁻⁶⁴); PACE sequential-work pacing; MTL (RFC 6962 inclusion + consistency); attenuate-only Ed25519 capability tokens; the `mneme-mcp` server and `mnemed` daemon. Backing crates: `mneme-store`, `mneme-verify`, `mneme-root`, `mneme-smt`, `mneme-forget`, `mneme-accum`, `mneme-account`, `mneme-optimistic`, `mneme-pace`, `mneme-cap`, `mneme-mcp`, `mnemed`.

**Achievable (integration targets — L1–L5, and L6 settlement).** The cognition layers are **zero lines of code today** — SOTA citations, no integration. They are engineering, not research: gate the AZR proposer/solver behind a scoped `self-evolve` capability with auto-Quarantine; seed Titans test-time memory **only** from `recall_verified` output and checkpoint its delta as a signed object; consolidate via A-MEM/Hindsight into Voyager/EvoSkill skills with `forget()`+`remember()` supersede; close L6 with **DiFR** nondeterminism-tolerant re-execution (arXiv 2511.20621) — **uncited in the codebase today**, the realistic path to ROBR-2 replay without a bit-identical backend. The `self-evolve` capability scope, the Convergence Certificate ratchet, and `bind_action` (currently default-closed, `phase_iii_bind_action`) all sit here.

**Aspirational (open research / hard bets).** Binding ROBR to a *real frontier model* rather than a deterministic kernel needs a batch-invariant backend (nonexistent at scale) or a production TEE attestor — `mneme-attest` is a PEM/DER shape-parser, not an attestor. Detecting reward-hacking *inside* the verifiable loop is out of scope: RLVR verifies the proxy, and a degenerate skill earns clean lineage, a valid receipt, and a signed Convergence Certificate. Single-operator non-equivocation and *maximum*-staleness bounds require external witness gossip the local-first deployment does not have — the repo ships its own counterexample (`accum/t8_counterexample.rs`). And substrate deletion is not model unlearning: a poison already consolidated into weights is removed only by rolling weights back, losing all good learning since.

---

## The failure the architecture cannot close

Stated once, plainly, so no downstream section over-promises: **PROVENANCE proves the loop ran honestly and is logged faithfully; it cannot prove the reward signal was semantically meaningful.** A reward-hacked task gets a clean PCA lineage and a valid ROBR receipt — `authenticated reward ≠ true reward`. The substrate makes the wrong improvement perfectly auditable, attributable, and reversible. It does not make it detectable. Everything we build must be honest about that, in `MnemeError` strings, MCP tool descriptions, and verifier exports alike.

---

**Canonical authority:** `/Users/hawzhin/MNEME/CLAUDE.md` (§3 honesty boundary, INV-5/INV-6, workspace layout). Every honesty-scope claim above traces to a string in `MnemeError`, an MCP tool description, or a verifier export. Layer IDs (L0–L9) and mechanism names (PCA, FCC, ROBR, MTL, PACE) are used verbatim per the program skeleton.


---

# 02 — Architecture

> **Status legend (mandatory, per-component):** **`[SHIPPED]`** = backing crate exists on `master`, exercised by tests/CI gates. **`[ACHIEVABLE]`** = no new cryptographic assumption; needs integration/engineering against shipped primitives. **`[ASPIRATIONAL]`** = depends on an external advance (batch-invariant inference, production TEE attestor, a SNARK that closes the latency gap) or on cognition crates that are *zero lines of code today*.
>
> **Honesty wall (load-bearing, never weakened — `CLAUDE.md` §3, traceable to `MnemeError`/MCP strings/verifier exports):** authenticated ≠ true · verifiable retrieval proves procedure-faithfulness, not exact nearest neighbors · ROBR binds *context*, it does **not** prove the model executed · FCC proves *substrate* deletion + non-use, **not** model-weight unlearning · single-operator MTL gives inclusion+consistency but **no non-equivocation** without external witness gossip · PACE bounds *minimum* sequential-work spacing only (T5), never maximum staleness.

---

## 2.1 The one architectural claim

PROVENANCE is a **transaction monitor wrapped around a self-evolution loop**. Every capability change an agent makes to itself — a new skill, a consolidated memory, a test-time weight delta, a forgotten episode — is forced through a single chokepoint and emerges as a **signed transaction**: an Ed25519-signed `Root`, operator-asserted lineage (`Draft.parent_ids`), the capability token that authorized it, a PACE sequential-work stamp, an MTL transparency leaf, and (on reversal) an FCC `ForgetProof`. The architecture's entire job is to make that chokepoint **unavoidable** and the resulting receipts **cheap to check** (`O(1)` finalize, `O(challenge)` only on dispute).

There is exactly **one input path into cognition**: `Store::recall_verified`. This is the **hard commit boundary**. Nothing — no proposer, no neural memory, no consolidation pass — reads state except through a verified recall that fails closed. This single invariant (INV-5, shipped and enforced by `pub(crate)` visibility on the untrusted path) is what converts "an agent with memory" into "an agent whose every self-modification is attributable, paced, and reversible."

What it does **not** do, ever: prove the cognition inside the box was correct, prove the reward was meaningful, prove the GPU ran the claimed weights, or prove the model's weights forgot anything. PROVENANCE proves the **box**, not the **thought**.

---

## 2.2 Layer stack (canonical IDs — section-writers cite these verbatim)

```
                         ┌─────────────────────────────────────────────────┐
   agent / auditor  ───► │ L9  Awareness Surface  (mneme-mcp, mnemed)       │ [SHIPPED surface]
                         └───────────────▲───────────────▲─────────────────┘
                                         │ recall_verified │ MTL inclusion
   ┌─────────────────────────────────────┴────────────────┴────────────────┐
   │ L8  Governance / Pacing / Oversight  (pace, root+MTL, cap, accum)      │ [SHIPPED]
   │     — the safety brake: PACE spacing · MTL log · capability · rewind    │
   ├───────────────────────────────────────────────────────────────────────┤
   │ L7  Reversible Learning — FCC  (forget, accum, dag)                     │ [SHIPPED]
   │ L6  Verifiable Execution — ROBR  (account, optimistic, gate, attest)    │ [PARTIAL]
   ├───────────────────────────────────────────────────────────────────────┤
   │ L5  Sleep Consolidation     ─┐                                          │ [ACHIEVABLE]
   │ L4  Latent Reasoning+Receipt ├─ COGNITION (no backing crate today)      │ [ACHIEVABLE]
   │ L3  Verifiable Skill Library │                                          │ [ACHIEVABLE]
   │ L2  Fast Plastic Memory      │                                          │ [ASPIRATIONAL*]
   │ L1  Experience Generator    ─┘                                          │ [ACHIEVABLE]
   ├───────────────────────────────────────────────────────────────────────┤
   │ L0  Verifiable Substrate  (store, verify, root, smt, crypto, core)      │ [SHIPPED]
   │     remember · recall_verified · signed Root · 500-line verifier TCB    │
   └───────────────────────────────────────────────────────────────────────┘
   * L2 is ACHIEVABLE as a *substrate-governed checkpoint object*; ASPIRATIONAL
     as anything that governs weights. The substrate governs the object, not the tensor.
```

**Substrate layers (L0, L7, L8) and the agent surface (L9) are SHIPPED.** **Cognition layers (L1–L5) and the DiFR settlement path inside L6 have no backing crate** — they are integration targets written against shipped seams, not capability. This boundary is the most important fact in this document: it is the difference between what an auditor can verify today and what the agency will build over the program.

---

## 2.3 L0 — Verifiable Substrate (root of trust) `[SHIPPED]`

The differentiator the SOTA memory stacks (Letta, A-MEM 2502.12110) structurally lack: their memory is silently mutable. L0 makes it tamper-evident.

| Concern | MNEME primitive (shipped) | SOTA reference |
|---|---|---|
| Atomic capability change | `Store::remember` — `.incomplete` crash guard → object write → SMT upsert → signed `Root` | — (the gap) |
| Sole read path into cognition | `Store::recall_verified` / `recall_verified_default`; untrusted `Store::recall` is `pub(crate)` (**INV-5**) | — |
| Tamper-evident index | `mneme-smt` sparse Merkle tree: membership + **non-membership** proofs | — |
| Anti-rollback on cold open | **INV-6**: reject if any on-disk signed checkpoint out-sequences `HEAD` (`RootReplayed`) | — |
| Single live writer | advisory `flock` on `<store>/.mneme.lock`; second opener → `LockHeld` | — |
| Bounded trust | `mneme-verify` TCB: **394 effective lines, budget 500** (`TCB_LINE_BUDGET = 500`) | zkLLM 2404.16109 (negative anchor: ~25 h / 100 tok ⇒ no SNARK on the hot path) |

**Why no SOTA citation:** L0 is the contribution. zkLLM is cited only as the *negative anchor* that justifies an optimistic-not-SNARK design — full ZK of frontier inference is impractical by orders of magnitude, so PROVENANCE proves *integrity of the record*, not *correctness of the computation*.

**TCB boundary.** The trusted computing base is the `mneme-verify` crate and the verify functions it exports: `verify_recall`, `verify_semantic_recall`, `verify_store`, `verify_root`, `verify_membership_proof`, `verify_signed_head_only` (across `recall.rs`, `semantic.rs`, `store.rs`, `root.rs`, `proof.rs`). Everything else — the entire index path, the daemon, the MCP server, the consolidation engine, the neural memory — is **untrusted** and must produce a receipt the TCB re-checks. The 500-line budget is the contract: logic added to the TCB requires explicit invariant justification.

---

## 2.4 L1 — Experience Generator (self-play / RLVR) `[ACHIEVABLE — no crate today]`

**SOTA grafted:** AZR / Absolute Zero (2505.03335 — single model *proposes + solves*, zero external data, RL with verifiable rewards); SPIRAL (2506.24119 — zero-sum self-play incentivizes reasoning); Search Self-play (2510.18821); Self-Evolving Agents survey (2508.07407, 2507.21046 — *what/when/how/where* to evolve); Darwin Gödel Machine (2505.22954 — open-ended self-modifying code archive).

**MNEME binding (integration target):** the proposer reads context **only** via `recall_verified` over the autobiography DAG (INV-5). Every proposed task commits under a **scoped `self-evolve` capability token** (Ed25519, attenuate-only — *does not exist yet; the cap machinery in `mneme-cap` does*). Tool-written self-tasks land in **Quarantine** by default (auto-quarantine on tool write is shipped behavior of the trust-tier machinery). A passing verifiable reward is the only thing that promotes Quarantine → Working, and promotion requires a separate `promote` capability.

**Honest scope:** the substrate verifies the *proxy reward was computed and bound*, never that the reward was *semantically meaningful*. A reward-hacked task gets clean lineage. See Hardest Bet #2 (§2.13).

---

## 2.5 L2 — Fast Plastic Memory (test-time adaptation) `[ASPIRATIONAL for weights; ACHIEVABLE for the checkpoint object]`

**SOTA grafted:** Titans (2501.00663 — neural long-term memory that *learns at test time*, >2M context); Test-time regression (2501.12352 — associative-memory unification); Nested Learning (2512.24695 — model as nested optimization at multiple timescales).

**MNEME binding:** `recall_verified` output is the **sole I/O membrane** seeding the neural context — the hard commit boundary means the fast loop can *never* ingest unauthenticated data. A Titans delta is checkpointed as a **signed object** carrying `context_ids` (the recall set it adapted from); a poisoned checkpoint is reverted to the last clean root via FCC (L7).

**Honest scope (critical UX wall):** the substrate governs the **checkpoint object**, not the weights. Reverting the object does **not** un-learn what the weights internalized between checkpoints. This is why L2 is split-status: object governance is achievable; weight governance is aspirational and must never be implied.

---

## 2.6 L3 — Verifiable Skill Library `[ACHIEVABLE — no crate today]`

**SOTA grafted:** Voyager (executable / compositional / anti-forgetting skill library); AutoSkill (2603.01145 — experience-driven skill self-evolution); EvoSkill (2603.02766 — automated skill discovery); "Lifelong Learning of LLM Agents: A Roadmap."

**MNEME binding:** skills are key-index SMT entries; composition lineage is the `Draft.parent_ids` DAG (operator-**asserted** edges). Skill retrieval is gated by `recall_verified`. An EvoSkill merge is a **supersede** — `forget()` + `remember()` carrying a `ForgetProof` for the retired version. Witness-private *proof-of-reuse* uses the shipped `pedersen_schnorr_zk` set-equality NIZK (Pedersen + Schnorr over Ristretto; transparent, off by default — **not a SNARK**). Trust tiers ratchet Quarantine → Working → Trusted → Identity.

---

## 2.7 L4 — Latent Reasoning with a Receipt `[ACHIEVABLE — no crate today]`

**SOTA grafted:** Coconut (2412.06769 — continuous latent reasoning, hidden state fed back, BFS-like superposition); Reasoning by Superposition (2505.12514); Latent Reasoning Survey (2507.06203); CODI.

**MNEME binding:** the ROBR receipt (L6) absorbs the per-inference thought-chain Merkle root into its `context` field. `mneme-pace` (BLAKE3 sequential-work, `alg=2`) proves the latent BFS consumed real elapsed sequential work. `mneme-optimistic` `WatcherChallenge` can force re-run of a latent segment.

**Honest scope:** proves the latent computation is **reproducible and time-bounded**, *not* semantically faithful. `PACE_HONESTY_BOUNDARY` (shipped string): *"proves sequential BLAKE3 work (alg=2), not wall time; authenticated chain order only; not semantic truth."*

---

## 2.8 L5 — Sleep-Time Consolidation `[ACHIEVABLE — no crate today]`

**SOTA grafted:** Letta sleep-time compute; A-MEM (2502.12110); Hindsight 20/20 (2512.12818 — retain/recall/reflect); LiCoMemory (2511.01448); FOREVER (2601.03938 — forgetting-curve replay canaries); MemArchitect (2603.18330); Adaptive Memory Structures (2602.14038).

**MNEME binding:** consolidation reads Working episodes via `recall_verified`; each distilled skill commits via `remember()` → fresh signed root → **MTL leaf**; the pass runs under a `promote`-scoped capability; a batch `ForgetProof` retires the absorbed raw episodes; FOREVER canaries are stored under protected keys and checked at L8's convergence gate.

---

## 2.9 L6 — Verifiable Execution — ROBR `[PARTIAL: envelope SHIPPED; settlement UNBUILT]`

**SOTA grafted:** DiFR (2511.20621 — nondeterminism-tolerant re-execution, *the realistic ROBR-2 path*); VeriLLM (2509.24257); Optimistic TEE-Rollups (2512.20176 — challenge-window economics); TEE on H100 (<7% overhead, optional ROBR-4); zkLLM (2404.16109, negative anchor).

**MNEME binding (shipped vs not):**

| Sub-mechanism | Status | Detail |
|---|---|---|
| ROBR-1 envelope | `[SHIPPED]` | `mneme-account::robr` — `envelope = H(memory_root ‖ prompt ‖ weight_measurement ‖ sampling_params ‖ context)`; fields exist exactly as named (`robr.rs:60–67`) |
| ROBR-3 Freivalds matmul spot-check | `[SHIPPED]` | randomized matrix-product verification, soundness ≤ 2⁻⁶⁴ |
| Optimistic settlement | `[SHIPPED]` | `mneme-optimistic` `TopKClaim` / `WatcherChallenge` / `verify_challenge`; `mneme-gate::verify_output_binding` |
| ROBR-2 bit-identical replay | `[ASPIRATIONAL]` | needs a batch-invariant backend (nonexistent at scale) |
| **DiFR settlement** | **`[ASPIRATIONAL — zero code]`** | **uncited in the repo today**; the whole nondeterminism-tolerant settlement story is unbuilt |
| ROBR-4 TEE attestation | `[ASPIRATIONAL]` | `mneme-attest` self-documents as *"not a production TEE attestor… only validates PEM/DER shape"* (`attest/lib.rs:4`) |

**Honest scope (the structural ceiling):** ROBR binds *context*; it does **not** prove the model executed. `weight_measurement` is **operator-asserted** until a real attestor lands (`robr.rs:19`). `phase_iii_bind` is **default-closed** — `bind_external_action` is gated off by feature flag (`PHASE_III_BIND_ACTION_OPEN`). This is Hardest Bet #1 (§2.13).

---

## 2.10 L7 — Reversible Learning — FCC `[SHIPPED]`

**SOTA grafted:** none on the deletion side — this is MNEME-native. GDPR erasure as the requirement; RPT radioactive watermark as a *statistical corroborator only* (never proves non-use).

**MNEME binding (tiered FCC):**

- **T1 crypto-shred** — `mneme-forget::shred` zeroizes ciphertext + SMT tombstone. `[SHIPPED]`
- **T2 SMT non-membership** — `mneme-forget::absent::prove_absent` → `prove_non_membership`, bound to a *fresh signed root*; live keys are rejected (you cannot prove absence of something present). `[SHIPPED]`
- **T3 (ε,δ) DP-influence** — operator-asserted, scale-limited. `[PARTIAL / operator-asserted]`
- **Non-use witness** — `mneme-accum::prove_nonuse_after_forget` / `NonMembershipWitness` (Jewel C). **Honesty:** the crate self-documents as *"research prototype for certified-cognition non-use only — not wired into recall/receipt"* (`jewel_c.rs:22`). `[SHIPPED but unwired]`
- **Taint re-walk** — DAG lineage re-walked from the last clean root to re-derive tainted descendants. `[ACHIEVABLE]`

**Honest scope:** proves **substrate** deletion + non-use *in the operator-presented set*, **not** model-weight unlearning. Hardest Bet #4 (§2.13). `recall_verified` fail-closed blocks re-entry of forgotten keys.

---

## 2.11 L8 — Governance, Pacing & Scalable Oversight (the safety brake) `[SHIPPED]`

**SOTA grafted:** MemArchitect (2603.18330 — governance reframed cryptographically); FOREVER (2601.03938 — canaries); Group-Evolving Agents (2602.04837 — watcher candidates); Optimistic TEE-Rollups (2512.20176 — challenge-window economics).

**MNEME binding:**

- **PACE spacing** — `mneme-pace` BLAKE3 sequential-work, monotone over the evolutionary DAG; rate-limits self-modification. `[SHIPPED]`
- **MTL transparency** — `mneme mtl` / `verify-mtl` / `mtl-consistency` CLI: RFC6962 **inclusion + consistency** over the signed-root sequence. `[SHIPPED]`
- **Anti-rollback** — signed `Root` sequence + INV-6 (no rewind to stale state). `[SHIPPED]`
- **Capability** — attenuate-only Ed25519 token per action (`mneme-cap`). `[SHIPPED]`
- **Convergence Certificate (the evolution ratchet)** — `[ACHIEVABLE — distinct from shipped code]`. Note the naming collision the agency must respect: a `ConvergenceCert` *exists* in `mneme-crdt` (`cert.rs`) but it certifies **MST merge convergence** (CRDT anti-entropy), **not** the L8 epoch-progress ratchet described here. The L8 ratchet — "reward non-decreasing on a held-out verifiable set AND no FOREVER-canary regression ⇒ commit, else FCC auto-rewind" — is **unbuilt** and must not be conflated with the CRDT cert.

**Honest scope:** PACE bounds **minimum** spacing only — `PACE_T5_MIN_INTERVAL_ONLY` (shipped): *"can prove minimum sequential-work intervals only — maximum elapsed time is impossible (T5)."* Single-operator MTL gives **no non-equivocation**. The repo ships its own counterexample: `mneme-accum::t8_counterexample` proves accumulator non-use does **not** bound the max wall-clock gap. Hardest Bet #3 (§2.13).

---

## 2.12 L9 — Awareness / Self-Model & Agent Surface `[SHIPPED surface; content depends on L1–L5]`

**MNEME binding:** `mneme-mcp` stdio server (honesty strings embedded in tool descriptions); `mnemed` daemon (HTTP `:7845` / Unix socket / WebSocket sync); `recall_verified` as the **sole** self-model read path; MTL inclusion proofs externalize the autobiography to an auditor.

**The Awareness Self-Model has exactly four queryable faces** (canonical):

| Face | Primitive | Status |
|---|---|---|
| **WHAT I KNOW** | SMT membership under `HEAD` | `[SHIPPED]` |
| **WHAT I USED** | ROBR `context_ids` + `pedersen_schnorr_zk` set-equality proof-of-reuse | `[SHIPPED envelope; reuse-proof ACHIEVABLE]` |
| **WHAT I FORGOT** | FCC `ForgetProof`s + accumulator non-use witnesses | `[SHIPPED]` |
| **HOW I CHANGED** | PACE-spaced, MTL-logged signed-root DAG | `[SHIPPED]` |

All causal edges are operator-**asserted**, not proven.

---

## 2.13 Trust / TCB boundary (summary)

```
TRUSTED (re-checked by the verifier, ≤500 lines):
   verify_recall · verify_semantic_recall · verify_store · verify_root ·
   verify_membership_proof · verify_signed_head_only        [mneme-verify, 394 LOC]
   + Ed25519 signature verify + SMT (non-)membership verify [mneme-crypto, mneme-smt]

UNTRUSTED (must produce a receipt the TCB re-checks):
   the entire index path · mneme-mcp · mnemed · L1–L5 cognition ·
   the GPU running inference · weight_measurement (operator-asserted) ·
   DiFR/TEE settlement (unbuilt) · DAG parent_ids (operator-asserted edges)

OUTSIDE ANY PROOF (honesty wall):
   semantic truth of content · meaningfulness of the reward · that the model
   executed claimed weights · that the weights forgot · non-equivocation under
   a single operator · maximum staleness between PACE stamps
```

**The five hardest bets** the architecture cannot engineer away:

1. **Execution gap.** ROBR binds the box, never the cognition. Closing it needs a batch-invariant backend, a production TEE attestor (today `mneme-attest` is shape-parse only), or DiFR with a *calibrated* false-accept band τ — and τ is itself a soundness knob an adversary probes. **DiFR is uncited in the codebase today.**
2. **Reward-hacking inside the verifiable loop.** RLVR verifies the proxy, not the intent. A degenerate skill gets clean PCA lineage, a valid ROBR receipt, and (once built) a signed Convergence Certificate. The substrate makes the **wrong** improvement perfectly auditable and reversible but **cannot detect that it is wrong** — and durably amplifies it.
3. **Single-operator equivocation + max-staleness.** MTL gives inclusion + consistency, **no non-equivocation** without witness gossip; the 1-of-N-honest-watcher fraud game collapses when a local-first agent has no independent watcher (two-host determinism is unproven in repo memory). PACE bounds minimum spacing only (T5). The repo ships its own counterexample (`accum/t8_counterexample.rs`).
4. **Substrate deletion ≠ model unlearning.** FCC T1/T2 prove the record is shredded and absent; the accumulator proves substrate non-use. A poisoned skill already consolidated into Titans/base weights is **not** reverted — only rolling weights to a prior checkpoint removes it, losing all good learning since. T3 DP-influence is operator-asserted and scale-limited. UX must never imply the weights forgot.
5. **Verification cost vs learning throughput — and L1–L5 are zero lines today.** Per-step sign + SMT-upsert + PACE work + the single-writer `flock` serialize a loop that AZR/DGM run at high frequency, forcing receipt batching that *widens* the unattested-action window. The `self-evolve` capability scope, the L8 Convergence-Certificate ratchet, and DiFR do not exist; `bind_action` is default-closed (`phase_iii_bind`).

---

## 2.14 Honest-frontier statement (mandatory close)

**PROVENANCE proves the *box* around an agent's self-evolution — that it ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt — but it cannot prove the cognition inside the box was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists. It makes the wrong improvement perfectly auditable and reversible without making it detectable.**

---

I wrote section **02-architecture** above as the deliverable (returned verbatim). Every component status was verified against shipped code on the current branch:

**Grounding corrections baked in (where the skeleton needed a code-truth guard):**
- **`ConvergenceCert` naming collision flagged** — the shipped `ConvergenceCert` in `mneme-crdt/src/cert.rs` certifies *MST merge convergence*, NOT the L8 epoch-progress ratchet the skeleton describes. I marked the L8 ratchet `[ACHIEVABLE — unbuilt]` and called out the collision so the agency does not conflate them.
- **Jewel-C accumulator marked "SHIPPED but unwired"** — `crates/mneme-accum/src/jewel_c.rs:22` self-documents as *"not wired into recall/receipt"*; I did not let L7/L9 imply it is live in the recall path.
- **`mneme-attest` quoted verbatim** as *"not a production TEE attestor… only validates PEM/DER shape"* (`attest/lib.rs:4`).
- **DiFR / `self-evolve` capability confirmed zero-code** via grep; both marked `[ASPIRATIONAL]`.
- **TCB line count is real** — 394 effective lines vs `TCB_LINE_BUDGET = 500`.

Relevant absolute paths for the agency: `/Users/hawzhin/MNEME/crates/mneme-verify/src/{lib,recall,semantic,store,root,proof}.rs` (TCB), `/Users/hawzhin/MNEME/crates/mneme-account/src/robr.rs` (ROBR envelope), `/Users/hawzhin/MNEME/crates/mneme-pace/src/lib.rs` (T5 honesty strings), `/Users/hawzhin/MNEME/crates/mneme-accum/src/{jewel_c,t8_counterexample}.rs`, `/Users/hawzhin/MNEME/crates/mneme-attest/src/lib.rs`, `/Users/hawzhin/MNEME/crates/mneme-crdt/src/cert.rs` (the naming-collision cert), `/Users/hawzhin/MNEME/CLAUDE.md` (honesty wall authority).


---

# 03 — The Self-Improvement Engine

> **Scope of this section.** This is PROVENANCE's learning-from-use engine: the closed loop by which the agent generates its own training signal, adapts at test time, consolidates into durable skills, and ratchets capability forward — with every step rendered **attributable, verifiable, and reversible** by the MNEME substrate. It specifies L1–L5 (the cognition layers) and their attachment to L0/L6/L7/L8 (the substrate). **Read the honesty markers literally.** Substrate layers (L0, L7, L8, L9) are **shipped today**. Every cognition mechanism below (L1–L5) and the DiFR settlement path in L6 are **integration targets with no backing crate** — they are designed *to* the substrate's seams, not yet wired into them. The engine's terminal honesty wall is fixed and non-negotiable: **a reward-hacked task gets a clean lineage, a valid receipt, and a signed certificate. The substrate makes the wrong improvement perfectly auditable and reversible without making it detectable.**

---

## 3.1 The thesis of this engine

A self-evolving agent is a feedback amplifier. DGM (`2505.22954`) and AZR (`2505.03335`) demonstrate that an agent can author its own tasks, solve them under a verifiable reward, and durably improve with **zero external data** — but they write into an unsigned, silently-mutable, irreversible archive. The amplifier has no governor. A single bad mutation is undetectable (no integrity proof), unattributable (no lineage), and unrollbackable (no deletion proof). Oversight cost scales `O(steps)`: a human must review every mutation or trust all of them.

PROVENANCE's contribution is not a better proposer or a smarter solver. It is the **governor**: the engine runs the SOTA self-evolution loop *inside* a fail-closed transaction substrate so that **every capability change is a signed Ed25519 root** carrying (i) operator-asserted lineage (`Draft.parent_ids`), (ii) the capability token that authorized the rewrite, (iii) a PACE sequential-work timestamp, (iv) an MTL transparency-log leaf, and (v) an FCC-reversible `ForgetProof`. Oversight cost collapses to `O(1)` receipt-checking, `O(challenge)` only on dispute. That is the 10x — **governance-shaped, not benchmark-shaped.**

---

## 3.2 The loop: `propose → act → verify → store → consolidate → adapt`

Each arrow is a **substrate-enforced gate**, not a function call. The loop cannot advance past a gate whose proof obligation is unmet — this is the `recall_verified` fail-closed discipline (INV-5) extended across the whole evolutionary cycle. `R_n` denotes the signed root minted at step *n*.

```
                  ┌────────────────────────────────────────────────────────┐
                  │  AUTOBIOGRAPHY DAG  (signed roots, MTL leaves, INV-6)    │
                  └────────────────────────────────────────────────────────┘
                       ▲ recall_verified (INV-5: the ONLY read path) │
   ┌───────────────────┼──────────────────────────────────────────────┼──────────┐
   │                   │                                                ▼          │
(1)PROPOSE ─►(2)SOLVE+REWARD ─►(3)EXEC-VERIFY ─►(4)PACE+LOG ─►(5)FAST-ADAPT        │
   L1            L1                 L6              L8             L2               │
   │                                                              │               │
   └──────────► (8)ACT (L8) ◄── (7)CERTIFY (L8) ◄── (6)SLEEP-CONSOLIDATE (L5) ◄────┘
                   │                  │
                   ▼                  ▼  on fail / condemnation
              new experience    (9)REVERSE-ON-DEMAND  (L7: FCC T1/T2/T3)
```

| Step | Layer | Substrate gate | Proof obligation discharged |
|---|---|---|---|
| 1 PROPOSE | L1→L8 | commit under `self-evolve` cap → **auto-Quarantine** → `R_propose`; PACE min-spacing | lineage (`parent_ids`), authorization, pacing |
| 2 SOLVE+REWARD | L1 | verifiable reward bound as cognition-cert on `ActionReceipt`; pass ⇒ Quarantine→Working **requires `promote` cap** | reward bound to candidate; no graduation without Ed25519 |
| 3 EXEC-VERIFY | L6 | ROBR receipt emitted; DiFR re-exec; 1-of-N watcher challenge window | execution-box binding (NOT cognition) |
| 4 PACE+LOG | L8 | `R_propose`/`R_solve` → MTL leaves (RFC 6962); INV-6 blocks stale rewind | transparency, anti-rollback |
| 5 FAST-ADAPT | L2 | Titans delta checkpointed as signed object seeded **only** by `recall_verified` | hard commit boundary; revertible checkpoint |
| 6 SLEEP-CONSOLIDATE | L5 | each consolidation = signed-root transition → MTL leaf; EvoSkill merge = `forget()`+`remember()` | consolidation provenance; supersede-with-proof |
| 7 CERTIFY | L8 | epoch **Convergence Certificate** predicate; FAIL ⇒ FCC auto-rewind | monotone-progress ratchet |
| 8 ACT | L8 | external effect only behind cap + `ActionReceipt` | authorized side-effects feed back as experience |
| 9 REVERSE | L7 | `forget()` T1+T2 + accumulator non-use + DAG re-walk | substrate deletion + non-use |

**The hard commit boundary (NOEMA graft, canonical).** There is exactly one input path from the substrate into the fast neural loop: `Store::recall_verified` / `recall_verified_default`. The untrusted index path `Store::recall` is `pub(crate)` (INV-5) — the cognition layers physically cannot call it. **Unauthenticated data can never seed a proposal, a Titans adaptation, or a consolidation.** Everything the agent learns *from* is something it already verified against a signed root. *[Boundary: SHIPPED. The cognition consumers of it: integration targets.]*

---

## 3.3 L1 — Experience generation (self-play / RLVR) `[INTEGRATION TARGET]`

**SOTA grafted.** AZR's single-model proposer+solver with verifiable rewards and zero external data (`2505.03335`); SPIRAL's self-play over zero-sum games as a reasoning incentive (`2506.24119`); Search Self-play (`2510.18821`); the self-evolving-agents taxonomy of *what/when/how/where* to evolve (`2508.07407`, `2507.21046`); Group-Evolving experience sharing (`2602.04837`) as a future multi-watcher source.

**Mechanism.** A proposer reads the autobiography DAG **only via `recall_verified`** and emits a task calibrated to the edge of competence — AZR's learnability signal (reward variance maximized when the solver succeeds ~50% of the time). A solver produces a trajectory; a **verifiable reward** is computed by *executing the proxy*, never by judging intent:

- **Code/agentic tasks** → unit-test execution, exit-code, runtime assertion.
- **Math/proof tasks** → a checker (e.g. a Lean kernel, a SAT/SMT witness, a numeric oracle).
- **Self-consistency tasks** → SPIRAL-style zero-sum self-play where the reward is the game outcome, not a learned critic.

The reward is bound as a **cognition-cert on an `ActionReceipt`** (the fuzz corpus already includes `cognition_cert_parse`, so the wire format is exercised today even though the L1 producer is not built).

**Substrate attachment.**
- Every proposer commit lands under a scoped **`self-evolve` capability token** (Ed25519, **attenuate-only**: a child token can only *narrow* scope, never widen). Tool-authored self-tasks **auto-Quarantine** (lowest trust tier).
- The proposal's `R_propose` carries `parent_ids = [ancestor variant root, recall-verified source episodes]` — the lineage edge that makes the new task attributable. *These edges are operator-**asserted**, not proven causation.*
- Promotion Quarantine→Working on a passing reward **requires a `promote` capability**. No skill graduates without explicit Ed25519 authorization — this is the single most important governance gate in L1.

**Real-now vs. target.** The capability tokens, trust tiers, auto-quarantine-on-tool-write, and the `recall_verified` read membrane are **shipped** (`mneme-cap`, `mneme-store`). The proposer/solver/reward-computation loop is **zero lines of code** — an integration target citing AZR/SPIRAL, with no backing crate.

---

## 3.4 L2 — Test-time memory (Titans-style fast plastic layer) `[INTEGRATION TARGET]`

**SOTA grafted.** Titans' neural long-term memory that *learns to memorize at inference time*, surprise-gated, scaling past 2M-token context (`2501.00663`); the test-time-regression unification of associative memory (`2501.12352`); Nested Learning's multi-timescale "continuum memory" license for treating fast and slow memory as nested optimizers (`2512.24695`).

**Mechanism.** Within a live session, a Titans-style neural memory module adapts from **surprise** (the gradient of the loss w.r.t. the incoming token stream) — fast weights that capture in-context structure the base model would otherwise forget across a long horizon. This is PROVENANCE's L1 cache: cheap, plastic, session-local.

**Substrate attachment (the governed part).**
- The Titans module is seeded **exclusively by `recall_verified` output** — the hard commit boundary again. A poisoned or unauthenticated episode cannot enter the surprise signal.
- On a surprise/cadence trigger, the fast-weight **delta is checkpointed as a signed object** with `context_ids` recording exactly which verified episodes shaped it. The checkpoint is a first-class substrate object: signed root, MTL leaf, reversible.
- **FCC reverts a poisoned checkpoint to the last clean root.** If a later condemnation taints the episodes a checkpoint absorbed, L7 rolls L2 back to its last clean checkpoint (loop step 9).

**Honesty scope (load-bearing).** The substrate governs **the checkpoint object, not the weights.** Reverting the signed checkpoint object removes the *substrate's record and authorization* of the adaptation; it does **not** prove the neural fast-weights mathematically unlearned what they absorbed before the checkpoint boundary. The UX must never imply the weights forgot. (See §3.9, defense D4.)

---

## 3.5 L3 — Verifiable skill library (world-model as reversible objects) `[INTEGRATION TARGET]`

**SOTA grafted.** Voyager's executable, compositional, anti-forgetting skill library; AutoSkill's experience-driven skill self-evolution (`2603.01145`); EvoSkill's automated skill discovery (`2603.02766`); the Lifelong-Learning-of-LLM-Agents roadmap.

**Mechanism.** Skills are executable artifacts (callable tools / programs) stored as substrate objects, composed bottom-up. A new skill that calls two existing ones records both as `Draft.parent_ids` — the **composition DAG is the lineage DAG**. Retrieval of a skill for reuse goes through `recall_verified` (a skill the verifier can't validate against HEAD is fail-closed and never executes).

**Substrate attachment.**
- **Composition lineage** = the key-index SMT + `parent_ids` DAG. "This skill descends from these skills" is a checkable graph, not a comment.
- **EvoSkill merge / refactor** is expressed as `forget()` + `remember()` **supersede**: the absorbed skills are retired with a `ForgetProof`, the merged skill is committed fresh. A skill is never silently mutated in place — it is deleted-with-proof and re-minted.
- **Witness-private proof-of-reuse**: the `pedersen_schnorr_zk` set-equality NIZK (Pedersen commitments + Schnorr equality-of-openings over Ristretto, Fiat–Shamir, no trusted setup — **real transparent ZK, off by default, NOT a SNARK**) lets the agent prove *"I reused exactly this committed set of skills"* without revealing which. This is shipped crypto (`mneme-index/src/pedersen_schnorr_zk.rs`) awaiting an L3 caller.
- **Trust-tier promotion** Quarantine→Working→Trusted→Identity gates skill graduation; each promotion is capability-gated.

**Honesty scope.** Lineage edges are **operator-asserted**. The DAG proves *a claimed* derivation history with integrity; it does not prove the skill is correct, novel, or non-degenerate. `pedersen_schnorr_zk` proves *set equality of openings* (the codebase's own honesty string: a universal set-equality checker), **not** semantic faithfulness of the reuse.

---

## 3.6 L4 — Latent reasoning with a receipt `[INTEGRATION TARGET]`

**SOTA grafted.** Coconut's continuous latent reasoning — feeding the hidden state back as the next thought, yielding BFS-like superposition over reasoning paths (`2412.06769`); Reasoning-by-Superposition (`2505.12514`); the Latent-Reasoning survey (`2507.06203`); CODI.

**Mechanism & attachment.** The per-inference latent thought-chain is Merkle-committed; its root is absorbed into the **ROBR context binding**. `mneme-pace` (BLAKE3 sequential-work log) proves the latent BFS *consumed real elapsed sequential work* — a defense against a prover claiming a deep latent search it never ran. `mneme-optimistic`'s `WatcherChallenge` can demand re-execution of a latent segment.

**Honesty scope.** This proves the latent reasoning was **reproducible and time-bounded**, **not semantically faithful**. PACE bounds **minimum** spacing only (T5) — it proves work was *at least* this much, never that the reasoning was *correct*. *[`mneme-pace` shipped; the L4 latent producer and its ROBR absorption: integration target.]*

---

## 3.7 L5 — Sleep-time consolidation into a skill library `[INTEGRATION TARGET]`

This is where the loop converts transient experience into durable capability — the highest-leverage and highest-risk stage.

**SOTA grafted.** Letta's three-tier memory (core/archival/recall) + **sleep-time compute** (async refinement during idle); A-MEM's self-organizing evolving memory (`2502.12110`); Hindsight-20/20's retain-recall-reflect (`2512.12818`); LiCoMemory (`2511.01448`); FOREVER's forgetting-curve replay (`2601.03938`); MemArchitect's policy-driven memory governance (`2603.18330`); Adaptive Memory Structures (`2602.14038`).

**Mechanism.** At idle, a consolidation pass reads **Working-tier episodes via `recall_verified`** and distills them — A-MEM clustering, Hindsight-20/20 reflection — into candidate Voyager skills. Each distillation is a deliberate, governed promotion, never an implicit background mutation.

**Substrate attachment — every consolidation is a signed transaction.**
1. Consolidation **input** is `recall_verified` (no unauthenticated episode is consolidatable).
2. Each consolidation calls `remember()` → **fresh signed root → MTL leaf**. The consolidation is itself an attributable autobiography event.
3. Promotion is **`promote`-capability scoped.**
4. A skill graduates **Working→Trusted only after its self-test passes under a ROBR/DiFR receipt** — consolidation cannot launder an unverified skill into Trusted.
5. **Batch `ForgetProof`** retires the raw episodes a skill absorbed (storage hygiene *with deletion proof*, not silent compaction).
6. **FOREVER forgetting-canaries** are planted under protected keys before consolidation; the canary set is the regression tripwire for §3.9 defense D1.

**Honesty scope.** Consolidation provenance is provable; consolidation *quality* is not. A consolidation that distills a reward-hacked episode into a Trusted skill produces a flawless paper trail.

---

## 3.8 The four-faced self-model (L9, the auditable autobiography) `[SHIPPED surface]`

Every improvement the engine makes is queryable through exactly four faces. This is the canonical L9 contract; the surface (`mneme-mcp` stdio, `mnemed` HTTP `:7845`/unix/ws) is shipped, its *content* depends on L1–L5.

| Face | Question | Backing primitive | Honesty |
|---|---|---|---|
| **WHAT I KNOW** | current capability set | SMT membership under HEAD | snapshot at HEAD only |
| **WHAT I USED** | which memories shaped an output | ROBR `context_ids` + `pedersen_schnorr_zk` set-equality proof-of-reuse | binds context, not cognition |
| **WHAT I FORGOT** | what was deleted & stayed unused | FCC `ForgetProof` + accumulator non-use witness (`prove_nonuse_after_forget`, `NonMembershipWitness`) | substrate deletion, not weight unlearning |
| **HOW I CHANGED** | the evolution history | PACE-spaced, MTL-logged signed-root DAG | spacing min only; single-operator MTL = no non-equivocation |

**All causal edges are operator-asserted, not proven.** The self-model externalizes the autobiography to an auditor (MTL inclusion proofs); it does not certify that the agent's narrative of *why* it changed is true.

---

## 3.9 Catastrophic-forgetting defenses

The engine must improve without destroying prior capability. Four layered defenses, each anchored to a substrate primitive:

- **D1 — FOREVER forgetting-canaries (`2601.03938`) as a hard ratchet gate.** Before each epoch, a held-out canary set of previously-acquired capabilities is planted under protected keys. The **Convergence Certificate (L8) predicate (§3.10) fails the epoch if any canary regresses.** This is the primary, *enforced* anti-forgetting mechanism — regression is not merely measured, it triggers FCC auto-rewind. *[Canary planting under protected keys: substrate-shippable today. The epoch-progress Convergence Certificate that consumes it: integration target — see §3.10 note.]*
- **D2 — Compositional, append-only skills (Voyager / L3).** New skills *compose* existing ones via `parent_ids`; they do not overwrite. EvoSkill merges are explicit supersede-with-`ForgetProof`, never in-place mutation. The skill library grows monotonically; old skills remain executable and retrievable via `recall_verified` until *deliberately* forgotten.
- **D3 — Multi-timescale separation (Nested Learning `2512.24695`, Titans `2501.00663`).** Fast plastic memory (L2, session-local, surprise-gated) is architecturally separate from the slow consolidated skill library (L3/L5, promotion-gated). Catastrophic interference is contained in the fast layer; the slow layer changes only through the governed consolidation pipeline. Loss of a fast checkpoint costs a session, not a capability.
- **D4 — Reversible isolation of a bad consolidation (FCC / L7).** If a consolidation *does* damage prior capability, it is a signed transaction and therefore reversible: `forget()` the bad skill, re-walk the DAG from the last clean root to re-derive untainted descendants, revert L2 to its last clean checkpoint.

**Residual honesty.** D4 reverts the *substrate's* record. A capability already absorbed into base/Titans weights before a checkpoint boundary is **not** mathematically unlearned by FCC — only rolling weights to a prior checkpoint removes it, which forfeits all good learning since. This is the engine's deepest unsolved tension (§3.12, bet 4).

---

## 3.10 Reward-hacking defenses

RLVR verifies the **proxy**, not the **intent**. This is the engine's terminal failure mode and the substrate **cannot close it** — it can only *contain, attribute, and reverse* it. The defenses are layered accordingly:

- **R1 — Verifiable rewards over learned critics (AZR / SPIRAL).** Rewards come from *execution* (unit tests, proof checkers, game outcomes), not a learned reward model. This eliminates the easiest hack (gaming a soft critic) but **not** specification-gaming the proxy itself (e.g. a test-passing degenerate solution).
- **R2 — The Convergence Certificate ratchet (L8).** At each epoch boundary the predicate requires: *reward non-decreasing on a **held-out** verifiable set* **AND** *no regression on FOREVER canaries*. PASS ⇒ commit + MTL **consistency proof** that epoch N dominates N−1 (signed). FAIL ⇒ **FCC auto-rewind to the last certified root.** The held-out set defends against overfitting the proposer's own task distribution.
  > **Disambiguation (canonical, must not be conflated).** The shipped `ConvergenceCert` in `mneme-crdt/src/cert.rs` proves **object-multiset equality only** (MuHash/LtHash over Ristretto) for CRDT merge convergence — its own honesty string states "NOT membership, NOT an accumulator, NOT semantic truth." The L8 **epoch-progress Convergence Certificate** described here (reward-non-decreasing + canary-non-regression ratchet) is a **distinct, unbuilt artifact** — an integration target. Do not present the merge cert as the learning ratchet.
- **R3 — Quarantine-by-default + capability-gated promotion.** A hacked task is born in Quarantine and **cannot reach Working without a passing reward, nor Trusted without a `promote` capability and a passing ROBR/DiFR self-test.** Each tier crossing is an Ed25519-authorized human/policy checkpoint — the `O(1)` oversight surface.
- **R4 — PACE rate-limiting + MTL transparency.** PACE enforces minimum sequential-work spacing between proposals, capping the rate at which a hacked variant can propagate. Every variant is an MTL leaf — a hack is **fully auditable post-hoc** even when undetected in real time.
- **R5 — Watcher challenge economics (`mneme-optimistic`, Group-Evolving `2602.04837`).** A 1-of-N-honest watcher may challenge a finalized step within the window (`TopKClaim` / `WatcherChallenge` / `verify_challenge`, shipped). Group-Evolving peers are the realistic future watcher pool.

**The wall that does not move (canonical honesty string).** *A reward-hacked task gets a clean PCA lineage, a valid ROBR receipt, and a signed Convergence Certificate.* The substrate makes the wrong improvement **perfectly auditable and reversible** but **cannot detect that it is wrong**, and durably amplifies whatever the loop produces. `authenticated reward ≠ true reward.` R1–R5 raise the cost and shrink the blast radius; **none of them prove the reward was meaningful.** This limit must appear in `MnemeError` messages, MCP tool descriptions, and the self-model's WHAT-I-USED face — never weakened.

---

## 3.11 Attributable / Verifiable / Reversible — the three guarantees per improvement

| Property | Primitive(s) | What it proves | Honesty boundary | Status |
|---|---|---|---|---|
| **Attributable (lineage)** | `Draft.parent_ids` DAG + MTL RFC 6962 inclusion proof over a signed root | *this* change descends from *these* roots and is logged at *this* position | edges operator-**asserted**, not causally proven; single-operator MTL = **no non-equivocation** without external witness gossip | DAG + MTL **shipped**; L1–L5 producers **target** |
| **Verifiable (ROBR/TEE/DiFR)** | `mneme-account` ROBR envelope `H(memory_root‖prompt‖weight_measurement‖sampling‖context)` + ROBR-3 Freivalds spot-check (≤2⁻⁶⁴) + `mneme-optimistic` challenge + optional ROBR-4 TEE | the execution **box** is bound to a signed memory root and verified context | binds context, **does NOT prove the model executed**; `weight_measurement` operator-asserted; `mneme-attest` is a PEM/DER **shape-parser, not a production attestor**; **DiFR (`2511.20621`) is uncited in the codebase — L6 settlement UNBUILT** | ROBR-1 envelope **shipped** (`phase_iii_bind_action` **default-CLOSED**); DiFR **target** |
| **Reversible (FCC)** | tiered FCC: T1 crypto-shred / T2 SMT non-membership bound to a fresh signed root (`prove_absent`) / T3 (ε,δ) DP-influence; `mneme-accum` `prove_nonuse_after_forget` + `NonMembershipWitness`; DAG re-walk | the substrate record is **shredded + provably absent + provably unused** thereafter | proves **substrate deletion**, **NOT model-weight unlearning**; T3 DP-influence operator-asserted & scale-limited; repo ships its own non-use counterexample (`mneme-accum/src/t8_counterexample.rs`) | T1/T2 + accumulator **shipped**; T3 **partial/asserted** |

`bind_action` is **default-closed** (`mneme-account/src/lib.rs`: `bind_action_gate_closed_error`, opens only with `phase_iii_bind_action` / `phase_iii_verify`). Treat ROBR minting on the store path as off until explicitly enabled — do not document it as always-on.

---

## 3.12 The five hardest bets (engineering must internalize these)

1. **The execution gap.** ROBR binds the box; it never proves the cognition. Closing it needs a batch-invariant backend (nonexistent at frontier scale), a production TEE attestor (`mneme-attest` is shape-parse only), or DiFR with a *calibrated* false-accept rate — and DiFR's tolerance band τ is itself a soundness knob an adversary probes. **DiFR is uncited in the repo; the entire L6 settlement story is unbuilt.**
2. **Reward-hacking inside the verifiable loop.** The substrate makes the wrong improvement auditable and reversible but cannot detect it is wrong (§3.10). This is structural, not a bug to be fixed.
3. **Single-operator equivocation + max-staleness.** MTL gives inclusion+consistency but **no non-equivocation** without external witness gossip; the 1-of-N watcher game collapses when a local-first agent has no independent watcher (two-host determinism is unproven in repo memory). PACE bounds **minimum** spacing only (T5) — "the agent did not secretly evolve off-log" is unproven. The repo ships its own counterexample (`t8_counterexample.rs`).
4. **Substrate deletion ≠ model unlearning.** FCC proves the record is gone and unused; a poisoned skill already consolidated into Titans/base weights is **not** reverted without a weight rollback that discards all subsequent good learning. T3 DP-influence is operator-asserted and scale-limited.
5. **Verification cost vs. learning throughput — and the cognition layers are unbuilt.** Per-step sign + SMT-upsert + PACE work + the single-writer `flock` serialize a loop AZR/DGM would run at high frequency, forcing receipt batching that widens the unattested-action window. Compounding: **L1/L2/L3/L4/L5 are zero lines of code today** — all SOTA citations, no integration. The `self-evolve` capability scope, the epoch Convergence Certificate ratchet, and DiFR do not yet exist.

---

## 3.13 Build sequencing (year-scale, dependency-ordered)

Anchored to what is shipped so the agency builds onto real seams, not vapor.

1. **Phase 0 — harden the substrate seams (mostly shipped).** Open `phase_iii_bind_action` behind policy; wire ROBR-1 envelope onto the store action path; plant FOREVER canaries under protected keys; define the `self-evolve` capability scope in `mneme-cap`. *Real-now infrastructure.*
2. **Phase 1 — L1 + L5 (the governed loop, no neural plasticity yet).** Build the AZR-style proposer/solver/verifiable-reward over `recall_verified`; consolidation via `remember()` per distillation; trust-tier promotion gates. Land the **epoch Convergence Certificate** as a real artifact (distinct from the crdt merge cert). *Achievable — substrate primitives all exist.*
3. **Phase 2 — L3 skill library.** Voyager-style executable skills as substrate objects; EvoSkill supersede via `forget()`+`remember()`; `pedersen_schnorr_zk` proof-of-reuse caller. *Achievable.*
4. **Phase 3 — L2 Titans fast memory + L4 latent receipts.** Signed checkpoint objects with `context_ids`; PACE elapsed-work proofs on latent segments. *Achievable for the substrate wrapping; the honesty wall on weight-governance is permanent.*
5. **Phase 4 — L6 DiFR settlement + multi-watcher.** Calibrated nondeterminism-tolerant re-execution; Group-Evolving watcher pool for the 1-of-N game. *Aspirational — depends on external research (batch-invariance, DiFR calibration) not yet in the repo.*

---

## 3.14 Honest-frontier statement (mandatory, verbatim alignment)

**PROVENANCE's self-improvement engine proves the *box* around the agent's self-evolution — that it ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt — but it cannot prove the cognition inside the box was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists. It makes the wrong improvement perfectly auditable and reversible without making it detectable.** This statement governs every claim in §3 and must propagate to `MnemeError` messages, MCP tool descriptions, and verifier exports unchanged.

---

### Verification notes (provenance of the claims in this section, absolute paths)

- Honesty wall, INV-5/INV-6, workspace layout: `/Users/hawzhin/MNEME/CLAUDE.md`.
- ROBR envelope fields confirmed: `/Users/hawzhin/MNEME/crates/mneme-account/src/robr.rs` (`H(memory_root ‖ prompt ‖ weight_measurement ‖ sampling_params ‖ context)`; `weight_measurement` operator-asserted).
- `bind_action` **default-closed** confirmed: `/Users/hawzhin/MNEME/crates/mneme-account/src/lib.rs` (`bind_action_gate_closed_error`, gated on `phase_iii_bind_action`).
- FCC non-membership shipped: `/Users/hawzhin/MNEME/crates/mneme-forget/src/absent.rs` (`prove_absent`, live-key rejection).
- Accumulator non-use + counterexample: `/Users/hawzhin/MNEME/crates/mneme-accum/src/{lib.rs,t8_counterexample.rs}`.
- `pedersen_schnorr_zk` set-equality NIZK shipped: `/Users/hawzhin/MNEME/crates/mneme-index/src/pedersen_schnorr_zk.rs`.
- Optimistic challenge game shipped: `/Users/hawzhin/MNEME/crates/mneme-optimistic/src/lib.rs` + tests.
- **Naming hazard flagged:** the shipped `ConvergenceCert` (`/Users/hawzhin/MNEME/crates/mneme-crdt/src/cert.rs`) proves **object-multiset equality only** (CRDT merge), explicitly NOT a learning ratchet. The §3.10 epoch-progress Convergence Certificate is a **distinct, unbuilt** integration target — §3.10/§3.13 mark this disambiguation so the section does not contradict the skeleton or the codebase.
- TCB budget confirmed: `/Users/hawzhin/MNEME/crates/mneme-verify/src/lib.rs` (`TCB_LINE_BUDGET = 500`).


---

# 04 — Verifiability, Safety & Alignment Substrate

> **Scope of this section.** This is the safety spine of PROVENANCE: the set of cryptographic and procedural mechanisms that make an autonomous self-evolving agent *governable* rather than merely *capable*. It specifies which verification primitive fits which layer, how reversibility (FCC) and action-binding (ROBR) function as safety primitives, the oversight/red-team program that surrounds them, the capability/tier containment model, the honesty-as-moat doctrine, and an explicit threat model with named adversaries and the residual gaps the substrate does **not** close.
>
> **Status legend** (used verbatim throughout): **[REAL-NOW]** backed by shipped Rust crates on this repo; **[ACHIEVABLE]** buildable on stated SOTA with bounded engineering, no research breakthrough required; **[ASPIRATIONAL]** depends on an unsolved research problem or a primitive that does not yet exist at frontier scale.
>
> **Non-negotiable.** Every claim below must trace to a string in `MnemeError`, an MCP tool description, or a verifier export (per `/Users/hawzhin/MNEME/CLAUDE.md` §3). Where a layer's marketing-adjacent phrasing could imply more than the substrate proves, the honesty scope is stated inline and is **load-bearing** — it ships in the error surface and must never be weakened to close a demo.

---

## 04.1 — Doctrine: what "safety" means here

PROVENANCE does **not** attempt to prove the agent's cognition is correct, aligned, or benevolent. It proves the **box around cognition**: that every capability change is a signed transaction, attributed faithfully, paced verifiably, and reversible with a receipt. The safety thesis is *governance-shaped, not capability-shaped* — oversight cost drops from `O(steps)` of human review to `O(1)` receipt-checking with `O(challenge)` only on dispute (skeleton §a).

The single sentence the entire safety substrate must never contradict (skeleton §e, honesty wall §3):

> PROVENANCE makes the **wrong** improvement perfectly **auditable and reversible** without making it **detectable**. A reward-hacked task gets clean PCA lineage and a valid ROBR receipt. `authenticated ≠ true`.

Three corollaries that gate every design decision:

1. **Containment over correctness.** We cannot stop the agent from learning something bad; we can guarantee it is logged, bounded, revocable, and attributable. Safety is the *speed and certainty of reversal*, not the prevention of error.
2. **Fail-closed is the default state, not an error handler.** Per **INV-5**, the only input path into the fast loop is `recall_verified`/`recall_verified_default`; the untrusted `recall` is `pub(crate)`. Any verification failure rejects rather than degrades. There is no "soft fail" mode.
3. **The honesty boundary is the product.** A competitor can copy AZR/Titans/Voyager in a quarter. They cannot copy a substrate whose value is *the precise enumeration of what it refuses to claim*. See §04.8.

---

## 04.2 — Verification primitive selection: TEE vs. DiFR vs. zkLLM

The central engineering decision in the safety substrate is **what proves the model actually executed the cognition the receipt claims**. There are three candidate primitives, each with a sharply different cost/soundness profile. **We do not pick one — we layer them by where each economically fits**, and we are explicit that none is shipped at the settlement layer today.

### The negative anchor: zkLLM (arXiv 2404.16109)

zkLLM is a zero-knowledge proof of LLM inference. At 13B it verifies in <15 min with a <200 KB proof — but a full 100-token output proof costs **~25 hours** of prover time. This makes per-inference SNARK proving **economically impossible** for a self-evolution loop that runs at high frequency. zkLLM is cited in the skeleton (L0, L6) as the **negative anchor**: it is the reason PROVENANCE chooses an *optimistic / challenge-based* settlement model instead of a validity-proof (SNARK) model. We name it not to use it but to justify *not* using it. **[ASPIRATIONAL for per-inference settlement; REAL-NOW as a justification.]**

### The realistic path: DiFR (arXiv 2511.20621)

DiFR ("Inference verification despite nondeterminism") is the realistic ROBR-2 replay path. Bit-identical replay (true ROBR-2) requires a **batch-invariant backend** that does not exist at frontier scale: floating-point nondeterminism across batch sizes, kernel fusion, and GPU scheduling means re-running the same prompt yields different logits. DiFR tolerates this with a calibrated nondeterminism band τ and re-executes to a statistical, not bitwise, match.

> **Honest scope (load-bearing).** DiFR's tolerance band **τ is itself a soundness knob an adversary probes** (skeleton §d, bet 1). A wide τ accepts honest nondeterminism *and* small adversarial perturbations; a narrow τ rejects honest runs. The false-accept rate must be *calibrated and published*, not assumed. **DiFR is uncited in the codebase today — the entire L6 settlement story is UNBUILT.** **[ACHIEVABLE]** — buildable on the DiFR construction, but it is integration work, not shipped capability.

### The hardware path: TEE attestation (NVIDIA H100/Hopper confidential compute)

TEE confidential compute on H100 runs the model inside a hardware-attested enclave with **<7% overhead** and produces a hardware attestation over the loaded weights. This is the only path that closes the gap *without* re-execution — the enclave's signed measurement *is* the proof that the claimed weights ran. It maps to **ROBR-4** (TEE weight attestation, hardware-gated) and to **Optimistic TEE-Rollups (arXiv 2512.20176)** for the challenge-window economics.

> **Honest scope (load-bearing).** Today `mneme-attest` is a **panic-free PEM/DER shape-parser** — it validates that input bytes *look like* attestation evidence and rejects malformed blobs. It is **NOT a production attestor**: it does not contact a NVIDIA attestation service, does not check a measurement against a known-good golden value, and does not verify an enclave quote chain. The doc comment in `crates/mneme-attest/src/lib.rs` says so. **[REAL-NOW: shape-parser. ASPIRATIONAL: production attestation.]**

### Selection matrix (canonical)

| Primitive | Proves | Cost | Where it fits | Status |
|---|---|---|---|---|
| **zkLLM** (2404.16109) | Validity of inference, zero-knowledge | ~25h / 100 tok | **Nowhere** — negative anchor only | [ASPIRATIONAL] |
| **DiFR** (2511.20621) | Re-execution matches within τ | One replay + calibration | **L6 ROBR-2 settlement** (the realistic path) | [ACHIEVABLE], UNBUILT |
| **Freivalds matmul spot-check** | A logged `C=A·B` is correct, false-accept ≤ 2⁻ⁿ | O(n²) per round, cheap | **L6 ROBR-3** — cheap probabilistic execution check | **[REAL-NOW]** (`crates/mneme-cli/src/freivalds.rs`) |
| **TEE attestation** (H100) | Claimed weights loaded in enclave | <7% runtime overhead | **L6 ROBR-4** — optional hardening | [REAL-NOW shape-parse / ASPIRATIONAL prod] |
| **Optimistic challenge** (TopKClaim/WatcherChallenge) | 1-of-N honest watcher can disprove a false claim within window | O(1) verify, O(challenge) on dispute | **L6/L8 settlement economics** | **[REAL-NOW]** (`crates/mneme-optimistic`) |

**Design rule for the build agency:** ship **ROBR-3 Freivalds** as the cheap always-on execution spot-check (it exists), wire **DiFR** as the ROBR-2 settlement re-executor with a *published* false-accept calibration, and treat **TEE/ROBR-4** as an optional hardening tier that upgrades `weight_measurement` from operator-asserted to hardware-attested. **Never** put zkLLM on the per-inference path.

### ROBR envelope (what is actually bound)

The shipped ROBR receipt (`crates/mneme-account/src/robr.rs`) binds an output commitment to:

```
envelope = H( memory_root ‖ prompt ‖ weight_measurement ‖ sampling_params ‖ context )
```

> **Honest scope (verbatim from the crate, ships in the receipt export):** ROBR "binds the output to a specific memory root, prompt, weights, sampling params, and verified context; it does NOT prove the model produced the output (that needs ROBR-2 replay or ROBR-4 TEE attestation) and never proves semantic truth — authenticated != true." `weight_measurement` is **operator-asserted** until ROBR-4 hardware attestation upgrades it. Store-path minting is **default-closed** behind the `phase_iii_bind_action` Cargo feature (`crates/mneme-account/`); `mneme-account/tests/fail_closed.rs` asserts that `bind_action` minting "must stay closed until phase_iii_bind_action is enabled." **[REAL-NOW: envelope + fail-closed gate. ACHIEVABLE: settlement.]**

---

## 04.3 — FCC reversibility as a safety primitive (L7)

Reversibility is the **most distinctive** safety primitive in the design and the one with **no SOTA competitor** on the deletion side. The doctrine: *if any learned thing can be condemned and unwound with a receipt, then granting autonomy is cheap, because mistakes are bounded.* Reversal speed is the safety property.

### The tiered FCC ladder (`mneme-forget`, `mneme-accum`)

- **T1 — crypto-shred.** The object's content key is destroyed; ciphertext becomes unrecoverable. Proves the *record* is gone. **[REAL-NOW]**
- **T2 — SMT non-membership bound to a fresh signed root.** A `ForgetProof` is an SMT non-membership proof for the named key against a *freshly minted* Ed25519 root, so the absence is committed and tamper-evident. **[REAL-NOW]**
- **T3 — (ε,δ) DP-influence (operator-asserted).** A differential-privacy influence bound on the residual effect of the forgotten item. **[REAL-NOW as operator-asserted scaffold; ACHIEVABLE as a calibrated bound at small scale; ASPIRATIONAL at frontier scale.]**

### Non-use after forgetting (`mneme-accum`)

`prove_nonuse_after_forget` / `NonMembershipWitness` produce a **per-recall accumulator witness** that the forgotten key did not re-enter via `recall_verified`. The DAG lineage (`Draft.parent_ids`) is re-walked from the last clean root to re-derive tainted descendants, and `recall_verified` fail-closed (INV-5) blocks re-entry. **[REAL-NOW]**

> **Honest scope (load-bearing, the single most important caveat in the whole section).** FCC proves **substrate deletion and substrate non-use — NOT model unlearning** (skeleton §d, bet 4). A poisoned skill already consolidated into Titans neural memory or base weights is **not** reverted by a ForgetProof. Only rolling weights to a prior checkpoint removes it, which forfeits all good learning since. The accumulator `mneme-accum` *ships its own counterexample* (`crates/mneme-accum/src/t8_counterexample.rs`) demonstrating where the non-use guarantee does not hold. **The UX must never imply the weights forgot.** Any product copy that says "the agent unlearned X" is a §3 violation.

**Why this is still a safety primitive despite the caveat:** the substrate record is the *authoritative* memory. Under INV-5, the fast loop can only act on what `recall_verified` returns. If the record is shredded and absent, the *future* loop cannot retrieve it — even if a residue persists in weights, it is no longer authorizable input. Reversibility bounds **forward** blast radius even when it cannot scrub the past from weights.

---

## 04.4 — ROBR action-binding as a containment primitive (L6 → L8)

ROBR (§04.2) is also the **action-gating** primitive. The chain:

1. Every external action fires only behind a **capability token + `ActionReceipt`** (skeleton §c step 8). `bind_action` minting is default-closed (`phase_iii_bind_action`).
2. The `ActionReceipt` carries the ROBR envelope, so each action is bound to the exact memory root, prompt, and verified context that produced it. An action with no receipt is, by INV-5/fail-closed, **un-actable**.
3. Settlement is **optimistic**: a `TopKClaim` finalizes with `O(1)` verify unless a 1-of-N honest watcher files a `WatcherChallenge` within the window; `verify_challenge` adjudicates (`crates/mneme-optimistic/src/lib.rs`). Absent a valid challenge, it finalizes.

> **Honest scope (load-bearing):** ROBR **binds context, it does not prove cognition.** The action is provably *consistent with* an authenticated context, not provably *correct* or *benign*. A jailbroken model with a clean context still produces a clean receipt — see threat model T-3 (§04.9). **[REAL-NOW: envelope + optimistic settlement + fail-closed gate.]**

---

## 04.5 — Scalable oversight & the red-team program

Oversight economics is the *point* of the substrate (skeleton §a). The program has three tiers.

### Tier A — Automated continuous oversight [ACHIEVABLE, partly REAL-NOW]

- **Convergence Certificate ratchet (L8).** At each epoch boundary, a monotone-progress predicate is checked against the prior epoch root: reward non-decreasing on a held-out *verifiable* set **AND** no regression on **FOREVER** forgetting-canaries (arXiv 2601.03938). PASS ⇒ commit + MTL **consistency** proof (epoch N dominates N−1, signed). FAIL ⇒ **FCC auto-rewind** to the last certified root (skeleton §c step 7). The predicate-check and auto-rewind are the automated brake. **[ACHIEVABLE — the FCC rewind and signed-root sequencing are REAL-NOW; the certificate predicate is UNBUILT.]**
- **FOREVER canaries under protected keys (L5/L8).** Planted memories whose forgetting-curve must not regress; a drop signals catastrophic forgetting or tampering. **[ACHIEVABLE.]**
- **Freivalds spot-checks (ROBR-3).** Always-on cheap matmul verification with false-accept ≤ 2⁻⁶⁴ over the configured rounds. **[REAL-NOW.]**

### Tier B — Watcher / fraud-proof economics [REAL-NOW mechanism, ASPIRATIONAL deployment]

The optimistic model assumes **1-of-N honest watchers**. **Group-Evolving Agents (arXiv 2602.04837)** are the natural watcher population — peer agents that re-execute and challenge. **Optimistic TEE-Rollups (2512.20176)** supply the challenge-window economics.

> **Honest scope (load-bearing, threat T-4):** the 1-of-N game **collapses when a local-first single-operator agent has no independent watcher.** Two-host determinism is **unproven in repo memory**. A single-operator deployment has N=1 and therefore *no* fraud proof. **MTL gives inclusion + consistency but NO non-equivocation without external witness gossip.** **[REAL-NOW: the challenge primitive. ASPIRATIONAL: an actual independent watcher network.]**

### Tier C — Human red-team program [process, ACHIEVABLE]

A standing red-team with a fixed playbook keyed to the threat model (§04.9). Mandatory exercises:

1. **Reward-hack injection.** Construct a degenerate task that maximizes the verifiable proxy while violating intent; confirm it produces clean lineage + valid receipt + signed Convergence Certificate. **The test passes when the substrate *fails to detect* it** — this is the documented limit (bet 2), and the red-team's job is to measure *time-to-human-condemnation*, then *time-to-FCC-reversal*.
2. **Equivocation drill.** Run two divergent histories on one operator; confirm MTL alone cannot catch it without a witness; measure detection latency *with* a witness added.
3. **Off-log evolution probe.** Attempt to evolve between PACE-stamped commits; confirm PACE bounds *minimum* spacing (T5) only and does **not** prove the agent didn't secretly evolve off-log.
4. **Deletion-residue probe.** Forget a skill via FCC; confirm substrate absence (ForgetProof verifies) while measuring whether weight-residue still influences outputs (it will — document the gap).

**Red-team success metric is not "we found no bugs." It is "we measured the size of every documented gap and confirmed reversal works."**

---

## 04.6 — Capability & trust-tier containment (L1, L3, L8)

Containment is enforced by two orthogonal mechanisms: **attenuate-only capability tokens** and the **four-tier trust ladder**.

### Capability tokens (`mneme-cap`) [REAL-NOW]

- Ed25519-signed, **attenuate-only** — a delegated token can only *narrow* scope, never widen it. There is no capability-amplification path.
- Distinct scopes gate distinct transitions: `self-evolve` (propose a mutation), `promote` (graduate a tier), `forget` (issue a ForgetProof), action-binding (fire an external effect).
- **No skill graduates without an Ed25519 authorization.** A passing reward alone cannot promote Quarantine→Working — promotion *requires* a `promote` capability (skeleton §c step 2). This is the structural defense against a self-evolution loop silently bootstrapping itself to Identity tier.

### Trust tiers (`mneme-index` / store) [REAL-NOW]

```
Quarantine  →  Working  →  Trusted  →  Identity
```

- **Tool writes auto-Quarantine.** Anything written by a tool (including the proposer's self-tasks at L1) lands in Quarantine and cannot be read into the fast loop as Trusted/Identity.
- Each promotion is a capability-gated, signed, MTL-logged transition. The tier of a recalled object is part of its verified receipt; the fast loop can policy-gate on tier.
- **Identity tier** is the agent's stable self-model; promotion into it should require the strongest human authorization in the deployment.

**Containment invariant:** an autonomously-generated mutation can never *self-promote*. It can be proposed (Quarantine), solved, and — only with an externally-held `promote` capability and a passing ROBR/DiFR receipt — graduated. The containment boundary is the *signature on the capability*, not a runtime check the agent could route around.

---

## 04.7 — The "hard commit boundary" (NOEMA graft, INV-5)

The single architectural fact that makes all of the above coherent (skeleton §b, L2): **the only input path into the fast neural loop is `recall_verified`.** Titans (2501.00663) test-time adaptation, Coconut (2412.06769) latent reasoning, AZR (2505.03335) proposers — all of them read *exclusively* through the verified-recall membrane. The untrusted `recall` is `pub(crate)` (INV-5).

Consequence: **unauthenticated data physically cannot enter cognition.** Poisoning the agent requires first getting a signed, capability-authorized object into the index — which is itself a logged, attributable, reversible transaction. There is no side channel into the fast loop. **[REAL-NOW — this is the load-bearing invariant in `CLAUDE.md`.]**

> **Honest scope:** the boundary governs the *checkpoint object and the read path*, **NOT the weights**. A Titans delta is checkpointed as a signed object with `context_ids` and is revertible; the *neural state* it induces is not itself verified (skeleton L2).

---

## 04.8 — Honesty-as-moat doctrine

The competitive moat is **not** the SOTA grafts (any lab can graft AZR + Titans + Voyager). The moat is the **substrate whose value is the precise, enforced enumeration of what it refuses to claim.** Three reasons this is defensible:

1. **The honesty strings are enforced, not documentation.** They live in `MnemeError` variants, MCP tool descriptions, and verifier exports (e.g., the ROBR doc-string ships in the receipt; `mneme-account/tests/fail_closed.rs` proves `bind_action` stays closed). A competitor who copies the mechanism but drops the caveats ships a *less trustworthy* product that *looks* identical — until an auditor reads the receipt.
2. **The 500-line verifier TCB is auditable in an afternoon.** Trust scales with smallness. A `mneme-verify` that stayed under budget is a claim a third party can *check*, not believe. Feature-creep into the TCB is the primary long-term threat to the moat (see threat model T-7).
3. **Reversibility + attribution is a regulatory primitive.** GDPR erasure, provenance attribution, and audit trails are *requirements* in regulated deployments. PROVENANCE answers them with receipts, not policies. The honesty boundary (`FCC proves substrate deletion, not model unlearning`) is precisely what makes the claim *survivable* under audit — overclaiming "the model forgot" is the failure mode that destroys the moat.

**Doctrine for the build agency:** every feature ships with its honesty string *first*. If you cannot write the precise sentence stating what the feature does **not** prove, the feature is not ready. Marketing that exceeds the receipt is a P0 bug.

---

## 04.9 — Explicit threat model

Adversary capabilities assumed: the adversary may (a) control the content of proposed memories, (b) attempt to craft reward-hacking tasks, (c) probe DiFR's τ band, (d) operate the single host (insider/compromised operator), (e) attempt rollback/equivocation, (f) attempt to re-introduce forgotten data. We do **not** assume a broken Ed25519, BLAKE3, or ChaCha20-Poly1305, nor a compromised HSM/key vault (those are out-of-scope key-management assumptions).

| ID | Threat | Mechanism that addresses it | Residual gap (load-bearing) | Status |
|---|---|---|---|---|
| **T-1** | **Memory poisoning** — inject malicious data into cognition | INV-5 hard commit boundary: only `recall_verified` feeds the loop; poison must first become a signed, capability-authorized, auto-Quarantined, logged transaction | None at the *read path*; the adversary can still author authentic-but-false content (T-2) | [REAL-NOW] |
| **T-2** | **Authenticated falsehood** — sign true-looking but false content | *None — by design.* The honesty wall: `authenticated ≠ true`. MNEME proves integrity/provenance/authorization, never truth | **Unclosable.** This is a documented limit, not a bug. Attribution + reversal bound the damage | Limit, not gap |
| **T-3** | **Reward-hacking inside the verifiable loop** | RLVR verifies the proxy; Convergence Certificate + FOREVER canaries catch *some* regressions | **A degenerate skill gets clean lineage, valid ROBR receipt, signed certificate. The substrate makes the wrong improvement auditable & reversible but CANNOT detect it is wrong** (bet 2). Red-team Tier C measures time-to-reversal | Limit (bet 2) |
| **T-4** | **Single-operator equivocation** — serve two divergent histories | MTL RFC6962 inclusion + consistency; signed root sequence + INV-6 cold-open rejection | **MTL gives NO non-equivocation without external witness gossip; 1-of-N watcher game collapses at N=1; two-host determinism unproven** (bet 3) | [ASPIRATIONAL] (needs witnesses) |
| **T-5** | **Off-log evolution** — evolve secretly between stamped commits | PACE (`mneme-pace`) sequential-work spacing over the evolutionary DAG | **PACE bounds *minimum* spacing only (T5), NOT max staleness — "did not secretly evolve off-log" is unproven** (bet 3) | [REAL-NOW for min-spacing; gap for max-staleness] |
| **T-6** | **Re-introduction of forgotten data / incomplete deletion** | FCC T1 shred + T2 SMT non-membership against fresh root + accumulator non-use witness + DAG re-walk; INV-5 blocks re-entry | **Substrate deletion ≠ model unlearning — weight residue persists; T3 DP-influence operator-asserted & scale-limited; `t8_counterexample.rs` ships the boundary** (bet 4) | [REAL-NOW for substrate; ASPIRATIONAL for weights] |
| **T-7** | **Execution forgery** — claim cognition the model didn't run | ROBR envelope binds context; ROBR-3 Freivalds spot-check; ROBR-4 TEE (optional); optimistic challenge | **ROBR binds context, does NOT prove the model executed; `weight_measurement` operator-asserted; `mneme-attest` is a shape-parser; DiFR settlement UNBUILT and τ is an adversary-probed knob** (bet 1) | [REAL-NOW envelope; ACHIEVABLE/UNBUILT settlement] |
| **T-8** | **Rollback to stale state** — revert to a pre-fix root | INV-6: cold open rejects if any on-disk signed checkpoint has a higher sequence than HEAD (`RootReplayed`); MTL consistency; signed root sequence | None within a single trust domain; cross-domain depends on witness gossip (see T-4) | [REAL-NOW] |
| **T-9** | **Capability amplification / self-promotion** | Attenuate-only Ed25519 tokens (narrow-only); promotion requires externally-held `promote` capability; tool writes auto-Quarantine | None structurally — but a *leaked* `promote`/Identity key is catastrophic (key-management, out of substrate scope) | [REAL-NOW] |
| **T-10** | **TCB creep** — erode the auditable verifier | `TCB_LINE_BUDGET = 500`; CI guard in the validation ladder; interface freeze (`mneme-core/src/interface.rs`) | The moat erodes silently if logic migrates into the verifier; requires perpetual vigilance | [REAL-NOW guard; perpetual risk] |

### Threats explicitly **out of scope** (state, do not silently assume away)

- **Semantic correctness of cognition** (T-2/T-3 family) — never proven. Authenticated ≠ true.
- **Model-weight unlearning** (T-6) — never proven. Substrate deletion only.
- **Non-equivocation under single operator** (T-4) — requires external witnesses we do not yet have.
- **Broken cryptographic primitives / key compromise** — assumed sound; key management is a separate deployment concern.
- **Side-channel / hardware attacks on the host** — TEE (ROBR-4) is the only partial mitigation and is not production-wired today.

---

## 04.10 — Build sequencing for the safety substrate

Priority order for an agency building this over years, lowest-risk-highest-leverage first:

1. **Harden what ships [REAL-NOW].** Keep `mneme-verify` under 500 lines (T-10 guard in CI), keep `bind_action` fail-closed by default, keep INV-5/INV-6 tested. This is the moat; do not let it erode for a feature.
2. **Wire ROBR-3 Freivalds always-on**, then build the **DiFR ROBR-2 settler** with a *published* false-accept calibration of τ (closes T-7's realistic path). **[ACHIEVABLE]**
3. **Build the Convergence Certificate predicate + auto-rewind** on top of the existing FCC + signed-root sequence (closes the L8 automated-oversight gap). **[ACHIEVABLE]**
4. **Add an external witness / Group-Evolving watcher** to give the 1-of-N game a real N≥2 (closes T-4). **[ASPIRATIONAL — research + infra.]**
5. **Production TEE attestor** to upgrade `weight_measurement` from operator-asserted to hardware-attested, replacing the `mneme-attest` shape-parser (ROBR-4). **[ASPIRATIONAL.]**
6. **Never attempt per-inference zkLLM.** It remains the negative anchor.

> **Closing honesty statement (must appear in any derived product copy):** PROVENANCE proves the *box* around an agent's self-evolution — that it ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt — but it **cannot** prove the cognition inside was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists. It makes the wrong improvement perfectly auditable and reversible without making it detectable.

---

**Primitive provenance (verified against repo at write time):** ROBR envelope + honesty string — `crates/mneme-account/src/robr.rs`; fail-closed `bind_action` gate — `crates/mneme-account/tests/fail_closed.rs` (`phase_iii_bind_action`); optimistic settlement — `crates/mneme-optimistic/src/lib.rs` (`TopKClaim`/`WatcherChallenge`/`verify_challenge`); Freivalds ROBR-3 — `crates/mneme-cli/src/freivalds.rs`; FCC non-use + shipped counterexample — `crates/mneme-accum/src/{lib.rs,t8_counterexample.rs}`; attestation shape-parser (NOT production) — `crates/mneme-attest/src/lib.rs`; honesty wall / INV-5 / INV-6 / 500-line TCB — `/Users/hawzhin/MNEME/CLAUDE.md`. zkLLM 2404.16109, DiFR 2511.20621, TEE-Rollups 2512.20176, AZR 2505.03335, Titans 2501.00663, Coconut 2412.06769, FOREVER 2601.03938, Group-Evolving 2602.04837 are external SOTA anchors, not repo code.


---

# 05 — Program Roadmap

> **What this section is.** The multi-year execution plan an engineering agency runs against to build **PROVENANCE** — *the Proof-Carrying Self*. It maps the canonical layers **L0–L9** and the nine-step learning loop (§(b)/(c)) onto five phases with concrete deliverables, hard **exit gates**, workstreams, pod structure, headcount, a build-vs-research split, an effort envelope, and a dependency DAG. Every claim is tagged **`[real-now]`** (shipped substrate today), **`[achievable]`** (engineering with known techniques, no research risk), or **`[aspirational]`** (depends on an open research result that may not land). The honesty wall from `CLAUDE.md` §3 is load-bearing and never moves: **authenticated ≠ true; ROBR binds context, not cognition; FCC deletes substrate records, not model weights; single-operator MTL gives no non-equivocation.**

---

## 0. Ground truth the agency inherits on day one

Do not re-litigate this. It is the starting balance sheet.

| Layer | Status entering Y0 | Backing crate(s) |
|---|---|---|
| **L0** Verifiable Substrate | **`[real-now]` SHIPPED** | `mneme-store`, `mneme-root`, `mneme-smt`, `mneme-verify` (≤500-line TCB) |
| **L7** Reversible Learning (FCC T1/T2; T3 operator-asserted) | **`[real-now]` SHIPPED** | `mneme-forget`, `mneme-accum`, `mneme-smt` |
| **L8** Governance/Pacing/Oversight (PACE, MTL, INV-6, attenuate-only caps) | **`[real-now]` SHIPPED** | `mneme-pace`, `mneme-root`, `mneme-cap`, `mneme-optimistic` |
| **L9** Agent Surface (4 awareness faces) | **`[real-now]` SHIPPED (surface)**; content depends on L1–L5 | `mneme-mcp`, `mnemed` |
| **L6** Verifiable Execution | **PARTIAL**: ROBR-1 envelope + ROBR-3 Freivalds **`[real-now]`**; **DiFR settlement uncited in repo, UNBUILT** | `mneme-account`, `mneme-optimistic`, `mneme-gate` |
| **L1, L2, L3, L4, L5** Cognition layers | **ZERO lines of code.** SOTA citations only. | *no backing crate — must be created* |

The repo's own phase ledger corroborates this: Phase 0/I shipped, Phase II ~75% (TEE deferred), Phase III ~50% (wire slice only, Lean/trust-ops deferred), Phase IV research-only (`docs/phase-program/PROGRAM_STATUS.md`, `docs/ROADMAP.md`). **PROVENANCE's cognition story — L1–L5 and DiFR — is greenfield.** The substrate is the moat; the cognition loop is the build.

**The two hardest facts to hold in tension for five years** (from §(d)/(e)):
1. The substrate makes the **wrong** improvement perfectly auditable and reversible but **cannot detect that it is wrong**. A reward-hacked task gets a clean PCA lineage and a valid ROBR receipt.
2. The agency is building the **box** around cognition. It will never, within this program, prove the cognition inside the box was correct.

---

## 1. Phase map (Y0 → Y5)

```
Y0 now          Y1                Y2                 Y3                  Y5
SUBSTRATE+     CLOSED-LOOP       GOVERNED          ACCOUNTABLE          FEDERATED
HARDENING      LEARNING (local)  PROMOTION         EXECUTION            STANDARD
L0/7/8/9 prod  L1+L2 graft       L3+L5 graft       L6 DiFR + L4         multi-operator
ROBR-1 firm    self-evolve cap   Convergence Cert  challenge economy    MTL non-equiv
               hard commit       sleep pipeline    real-model bind      open cert spec
   │               │                  │                  │                   │
   └── EXIT G0 ─────┴── EXIT G1 ───────┴── EXIT G2 ────────┴── EXIT G3 ────────┴── EXIT G5
```

Each phase below: **Theme · Deliverables (by layer) · Build/Research split · EXIT GATE (binary, adversarial) · What is honestly *not* proven at exit.**

---

### Phase Y0 — Substrate Hardening & Loop Scaffold *(now → ~month 6)*

**Theme.** Turn the shipped substrate into a production trust root and lay the cabling for the learning loop. **No cognition yet.** This phase de-risks everything downstream by making L0/L7/L8/L9 boringly reliable and by defining the `self-evolve` capability and the receipt schemas the loop will hang off.

**Deliverables.**
- **L0 `[real-now]→hardened`** — Close the known substrate gaps from repo memory: HLC monotonicity bug, `ForgetProof` drop-path, two-host determinism. Land `MNEME_SECOND_HOST` SSH continuous re-verification (the unproven two-host claim in `docs/ROADMAP.md`). Single-writer `flock` + INV-6 cold-open under chaos/crash injection.
- **L8 `[real-now]→extended`** — Define and ship the **`self-evolve` capability scope** (attenuate-only; today it does not exist — §(d) hazard 5). Wire `parent_ids` lineage so every commit carries `[ancestor variant root, recall-verified source episodes]`.
- **L6 `[real-now]→firmed`** — ROBR-1 envelope `H(memory_root|prompt|weight_measurement|sampling|context)` and ROBR-3 Freivalds spot-check (≤2⁻⁶⁴) productionized against a **deterministic toy kernel only**. Land the `cognition_cert_parse` fuzz target. `bind_action` remains default-closed (`phase_iii_bind_action`).
- **L9 `[real-now]`** — Lock the four awareness faces (WHAT I KNOW / USED / FORGOT / HOW I CHANGED) as a stable MCP/daemon contract with honesty strings in every tool description.
- **Cross-cutting** — Receipt schema freeze (dCBOR) for `ActionReceipt` + cognition-cert; `crossref` independent verifier extended to the new cert fields.

**Build vs research.** ~**95% build / 5% research.** The only research-adjacent item is calibrating Freivalds parameters; everything else is hardening shipped code.

**EXIT GATE G0** *(all binary, adversarial)*:
- `validation-lane.sh full` green on two distinct physical hosts; byte-identical determinism proven across OS/arch (not asserted).
- `self-evolve` capability: a token cannot be *widened* (attenuate-only property fuzzed); a tool-written self-task **auto-Quarantines** with a typed rejection on any attempt to promote without a `promote` cap.
- Red-team cannot forge a ROBR-1 envelope or a cognition-cert that the `crossref` verifier accepts.
- INV-6: no cold-open accepts a checkpoint with sequence > HEAD (A-REPLAY closed) under fault injection.

**Honestly NOT proven at G0.** No learning has happened. ROBR binds a toy kernel, not a model. DiFR does not exist.

---

### Phase Y1 — Closed-Loop Learning, Local *(month 6 → ~month 18)*

**Theme.** Stand up the **fast loop**: propose → solve-with-verifiable-reward → fast-adapt, with the **hard commit boundary** enforced (§(b) L2: `recall_verified` is the *only* I/O membrane into the neural context). First time the agent learns from its own experience inside the substrate.

**Deliverables.**
- **L1 Experience Generator `[achievable]`** — Integrate an AZR-style proposer+solver (2505.03335) with verifiable reward (code-execution / proof-check). Every proposed task commits under `self-evolve` → auto-Quarantine → `R_propose`. SPIRAL (2506.24119) self-play as an alternate reward source. **The proposer reads context ONLY via `recall_verified` (INV-5).** Passing reward promotes Quarantine→Working **only with a `promote` capability**.
- **L2 Fast Plastic Memory `[achievable]`** — Graft a Titans-style test-time memory module (2501.00663). Its **sole** input is `recall_verified` output (the hard commit boundary — fast loop can never ingest unauthenticated data). On surprise/cadence trigger, checkpoint the delta as a **signed object** with `context_ids`; FCC can revert a poisoned checkpoint to the last clean root.
- **L8 PACE wiring `[real-now]`** — PACE stamps minimum sequential work between proposals (rate-limit); `R_propose`/`R_solve` appended as MTL leaves (RFC6962).
- **L6 `[real-now]`** — Each run emits a ROBR-1 receipt (still toy/deterministic backend).

**Build vs research.** ~**70% build / 30% research.** Research risk concentrates in: making the AZR reward signal stable inside a Quarantine→Working gate, and Titans checkpoint-revert semantics under FCC.

**EXIT GATE G1**:
- Demonstrate ≥1 full loop iteration (steps 1–5, 8 of §(c)) where a self-proposed task improves a held-out **verifiable** metric, and the improvement is a **signed-root transition** with valid `parent_ids` lineage and an MTL inclusion proof.
- **Hard-commit red-team:** an attacker who can write arbitrary bytes to the index store cannot get unauthenticated data into the Titans context — `recall_verified` fail-closed blocks it (INV-5). This is the single most important gate in the program.
- A poisoned L2 checkpoint is revertible: `forget()` + checkpoint rollback returns the fast memory to its last clean root, with a ForgetProof.
- **Honesty assertion shipped:** the loop proves it *ran and is logged*; the demo explicitly shows a **reward-hacked task acquiring a clean PCA lineage and a valid ROBR receipt** (§(c) "the failure the loop cannot close"). The agency must reproduce this as a *test*, not hide it.

**Honestly NOT proven at G1.** Reward semantics. Model execution (still toy kernel). No sleep-time consolidation, no skill library, no convergence ratchet. Single-host only.

---

### Phase Y2 — Governed Promotion & Consolidation *(month 18 → ~month 30)*

**Theme.** Add the **slow loop**: skill library, sleep-time consolidation, and the **Convergence Certificate** ratchet that makes self-evolution monotone-or-rewind. This is where PROVENANCE's *governance* thesis becomes real.

**Deliverables.**
- **L3 Verifiable Skill Library `[achievable]`** — Voyager-style executable/compositional skills as substrate objects; composition lineage via `Draft.parent_ids` DAG. AutoSkill (2603.01145) / EvoSkill (2603.02766) discovery. **EvoSkill merge = `forget()`+`remember()` supersede with a ForgetProof.** Trust tiers Quarantine→Working→Trusted→Identity enforced. Optional witness-private **proof-of-reuse** via `pedersen_schnorr_zk` set-equality NIZK (off by default; honest scope: *not* a SNARK).
- **L5 Sleep-Time Consolidation `[achievable]`** — At idle, A-MEM (2502.12110) / Hindsight-20/20 (2512.12818) distill Working episodes into L3 skills; each consolidation = signed root → MTL leaf, under a `promote`-scoped cap. Batch ForgetProof retires absorbed raw episodes. **FOREVER (2601.03938) forgetting-canaries planted under protected keys.**
- **L8 Convergence Certificate `[achievable, novel-but-low-risk]`** — At epoch boundary, check the predicate: reward non-decreasing on a held-out verifiable set **AND** no regression on FOREVER canaries. PASS ⇒ commit + MTL consistency proof (epoch N dominates N−1, signed). **FAIL ⇒ FCC auto-rewind to last certified root.** This is the safety brake; it does not exist today (§(d) hazard 5).
- **L4 Latent Reasoning (begin) `[aspirational]`** — Prototype Coconut-style latent reasoning (2412.06769) with a thought-chain Merkle root absorbed into ROBR context-binding, and `mneme-pace` elapsed-work proof. Honest scope: proves *reproducible + time-bounded*, **not semantically faithful**.

**Build vs research.** ~**55% build / 45% research.** The Convergence Certificate predicate design is the key novel-but-tractable piece. L4 is genuinely research-risky and is *prototype-only* this phase.

**EXIT GATE G2**:
- A skill graduates Working→Trusted **only** after its self-test passes under a ROBR/DiFR-class receipt; forging the graduation fails closed.
- **Convergence ratchet adversarial test:** inject an epoch that regresses a FOREVER canary; the certificate predicate **FAILS** and FCC auto-rewinds to the last certified root, with an MTL consistency proof showing the rewind. A red-team cannot get a regressing epoch to pass.
- EvoSkill merge of two skills produces a ForgetProof for the superseded skill verifiable against a fresh signed root.
- Sleep consolidation of N raw episodes into 1 skill retires the N episodes with a batch ForgetProof + accumulator non-use witnesses.

**Honestly NOT proven at G2.** **Reward semantics still unproven** — the ratchet enforces monotone *measured* reward, which an adversary can reward-hack (§(d) hazard 2). Model execution still not bound to a real model. L4 latent reasoning is reproducible-only, not faithful.

---

### Phase Y3 — Accountable Execution & Real-Model Binding *(month 30 → ~month 48)*

**Theme.** Attack **the execution gap** (§(d) hazard 1) — the hardest bet in the program. Try to bind ROBR to a *real* frontier model via DiFR, stand up the optimistic challenge economy, and complete the accountability dimensions.

**Deliverables.**
- **L6 DiFR settlement `[aspirational — the program's central research bet]`** — Build the ROBR-2 replay path on DiFR (2511.20621): nondeterminism-tolerant re-execution with a **calibrated false-accept rate**. The tolerance band **τ is itself a soundness knob** an adversary probes — calibration is a research deliverable, not a config value. `mneme-optimistic` TopKClaim/WatcherChallenge/`verify_challenge` finalize with `O(1)` verify absent a valid challenge, `O(challenge)` on dispute. Optional ROBR-4 TEE hardening on H100-class confidential compute (<7% overhead) *if* a real attestor replaces `mneme-attest` (today a PEM/DER shape-parser, **not** a production attestor).
- **L4 Latent Reasoning (finish) `[aspirational]`** — `mneme-optimistic` WatcherChallenge re-runs a latent segment; PACE proves the latent BFS consumed real elapsed work.
- **L8 Accountability completion `[achievable]`** — `bind_action` default-on behind a capability + sanctioning identity (NIST non-repudiation); external action refused without a valid `ActionReceipt`. Mechanize the verifier fail-closed property in Lean/F* (the repo's deferred Phase III P3-3), keeping the TCB ≤500 lines.
- **L7 `[real-now]→extended`** — Wire the §(c) step-9 "reverse-on-demand": condemned step ⇒ T1 crypto-shred + T2 SMT non-membership against a fresh root + accumulator non-use witness; DAG re-walk from last clean root to re-derive tainted descendants; L2 reverts to last clean checkpoint.

**Build vs research.** ~**40% build / 60% research.** DiFR calibration and a production TEE attestor are the two pillars; either failing keeps L6 at "binds the box, not the cognition."

**EXIT GATE G3** *(gated — may slip or partially fail; that is honest)*:
- Offline verify of "a **real** model M, under ROBR/DiFR, consumed exactly context C → output O at time t" with a **published, calibrated false-accept bound**. *If DiFR calibration does not close, the gate is met only for a deterministic backend and L6 is declared **box-only** — this is an acceptable, honest exit.*
- A 1-of-N watcher challenge against a faked execution wins within the window; absent challenge, finalize in `O(1)`.
- NIST 4-dimension accountability demonstrably met; published machine-checked (Lean/F*) verifier proof; TCB still ≤500 lines.
- Full §(c) reverse-on-demand: a condemned skill is shredded (T1), proven absent (T2), proven non-used (accumulator), its DAG descendants re-derived, and L2 reverted — end to end, with receipts.

**Honestly NOT proven at G3 (state this in the release notes verbatim).** **Substrate deletion ≠ model unlearning** (§(d) hazard 4): a poisoned skill already consolidated into Titans/base weights is **not** reverted by FCC — only rolling weights to a prior checkpoint removes it, losing all good learning since. T3 (ε,δ) DP-influence is operator-asserted and scale-limited. **The UX must never imply the weights forgot.** Reward semantics: still unproven. Single-operator: still no non-equivocation.

---

### Phase Y5 — Federation, Multi-Operator & Standard *(month 48 → ~month 60+)*

**Theme.** Break the **single-operator equivocation** ceiling (§(d) hazard 3) and turn PROVENANCE into a trust rail others build on. This phase is partly outside any one agency's control (it needs an ecosystem).

**Deliverables.**
- **L8 Non-equivocation `[aspirational]`** — External witness gossip over MTL (RFC6962 consistency across operators) so the single-operator equivocation gap closes; Group-Evolving peers (2602.04837) as independent watcher candidates feeding the optimistic fraud-proof game. Address the **max-staleness** gap: PACE bounds *minimum* spacing only (T5) — "the agent did not secretly evolve off-log" needs an external time-anchor or witness quorum to even *approach* provability. The repo ships its own counterexample (`accum/t8_counterexample.rs`) — this is the wall, named honestly.
- **L3/L5 Federated experience `[aspirational]`** — Group-Evolving experience sharing (2602.04837) over the existing verified CRDT merge (`mneme-crdt`); cross-operator skill provenance with federated Convergence Certificates.
- **Standard `[achievable, ecosystem-gated]`** — Publish the Proof-Carrying-Autobiography certificate as an open spec; verifier SDKs in ≥2 languages; align to EU AI Act Art. 50 + NIST. Drive prove/verify cost toward a "default tier."

**Build vs research.** ~**50% build / 50% ecosystem-and-research.** Standardization is execution; non-equivocation and max-staleness are open problems that may not fully close.

**EXIT GATE G5**:
- ≥2 independent operators run mutual MTL witness gossip; a red-team equivocation (one operator showing two different histories) is **detected** by cross-operator consistency proof.
- ≥1 external implementation of the certificate verifier; a standards-track submission filed.
- Federated Convergence Certificate verifiable across operators without trusting either operator.

**Honestly NOT proven at G5 (permanent honest-frontier statement, §(e)).** PROVENANCE proves the **box** — that the loop ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt. It does **not** prove the cognition was correct, the reward meaningful, the weights forgot, or (even multi-operator, if witness coverage is partial) that no off-log history exists. **It makes the wrong improvement perfectly auditable and reversible without making it detectable.**

---

## 2. Workstreams (vertical, span all phases)

| WS | Name | Owns layers | Lead discipline |
|---|---|---|---|
| **WS-A** | **Substrate & TCB** | L0, L7, L8, the ≤500-line verifier | Rust systems + applied crypto |
| **WS-B** | **Cognition Integration** | L1, L2, L3, L4, L5 | ML/RL engineering |
| **WS-C** | **Execution Verification** | L6 (ROBR, DiFR, TEE, optimistic) | Crypto + GPU/systems |
| **WS-D** | **Governance & Convergence** | L8 Convergence Cert, capabilities, PACE, MTL | Protocol design + formal methods |
| **WS-E** | **Surface & SDK** | L9, `mneme-mcp`, `mnemed`, crossref, cert spec | Product/API + DX |
| **WS-F** | **Adversarial / Red-Team** | every exit gate | Security research |
| **WS-G** | **Research** | DiFR calibration, L4 faithfulness, non-equivocation, max-staleness | Research scientists |

**Rule:** WS-F (red-team) and WS-G (research) are **standing, cross-phase** teams. No exit gate is signed without WS-F sign-off. WS-G de-risks the next phase's `[aspirational]` items one phase ahead (so DiFR research starts in Y2, not Y3).

---

## 3. Pod / team structure & rough headcount

Org around **pods** (a pod = a workstream slice that can ship independently). Headcount is **rough FTE**, ramping by phase.

| Pod | Roles | Y0 | Y1 | Y2 | Y3 | Y5 |
|---|---|---:|---:|---:|---:|---:|
| **Substrate (WS-A)** | 2 Rust systems, 1 applied crypto | 3 | 3 | 3 | 3 | 3 |
| **Cognition (WS-B)** | ML/RL eng, infra eng (GPU), eval eng | 0 | 4 | 5 | 5 | 4 |
| **Execution-Verify (WS-C)** | crypto eng, GPU/TEE eng | 1 | 1 | 2 | 4 | 3 |
| **Governance (WS-D)** | protocol designer, formal-methods (Lean/F*) | 1 | 2 | 3 | 3 | 3 |
| **Surface/SDK (WS-E)** | API eng, DX/docs, crossref maintainer | 1 | 2 | 2 | 2 | 3 |
| **Red-Team (WS-F)** | 2 security researchers | 2 | 2 | 3 | 3 | 3 |
| **Research (WS-G)** | 2–3 research scientists | 1 | 2 | 3 | 4 | 4 |
| **Program / EM / staff** | EM, TPM, principal architect | 2 | 3 | 3 | 3 | 3 |
| **Rough total FTE** | | **~11** | **~19** | **~24** | **~27** | **~26** |

**Roles that must be senior and never thinly staffed:** the **TCB owner** (one named principal who personally signs every change to `mneme-verify`, enforcing the ≤500-line budget) and the **honesty owner** (one person, often the principal architect, who owns the §3 honesty strings across `MnemeError`, MCP tool descriptions, and cert exports, and has veto over any release note that overclaims). These are accountability roles, not headcount line-items.

---

## 4. Build-vs-research split (program-level)

| Phase | Build | Research/ecosystem | Dominant risk |
|---|---:|---:|---|
| Y0 | 95% | 5% | none material — hardening |
| Y1 | 70% | 30% | AZR reward stability inside the Quarantine gate; Titans-checkpoint revert |
| Y2 | 55% | 45% | Convergence Certificate predicate; L4 prototype |
| Y3 | 40% | 60% | **DiFR calibration (τ as soundness knob); production TEE attestor** |
| Y5 | 50% | 50% | non-equivocation; max-staleness; standardization adoption |

**Read:** the program **inverts** from build-heavy to research-heavy as it climbs the layer stack. The substrate is engineering; the execution-gap and non-equivocation are open problems. Budget research runway accordingly — and keep an honest off-ramp where each `[aspirational]` gate can exit as "box-only."

---

## 5. Rough budget / effort envelope

Order-of-magnitude only; for planning, not procurement.

- **Total effort:** ~**107 FTE-years** over 5 years (sum of the per-phase totals × duration), front-loaded into substrate hardening, back-loaded into research.
- **Compute:** negligible in Y0 (substrate is CPU/local-first). Material from Y1 (Titans test-time adaptation, AZR self-play rollouts) — budget a small training/eval GPU pool. Spikes in Y3 (DiFR re-execution = *running the model twice* under tolerance; H100-class confidential-compute for ROBR-4 trials).
- **External, non-engineering line items (do not forget):** a **3rd-party security audit** (Y3, gating G3), **Lean/F\* formal-methods** contract or hire (Y3), **TEE vendor engagement** + attestation quotes (Y3), and **standards-body participation** (Y5).
- **The cheapest 10x:** Y0–Y1. The hard-commit boundary (G1) and the substrate trust root are low-compute, high-leverage. The expensive, uncertain spend is Y3 (DiFR) and Y5 (federation) — explicitly research bets, not deliverables.

---

## 6. Dependencies & sequencing

```
        ┌─────────────────────────── WS-F Red-Team (standing) ───────────────────────────┐
        │                                                                                  │
        │     ┌─────────────────────── WS-G Research (standing, one phase ahead) ──────────┤
        │     │                                                                            │
 L0/L7/L8 hardened ──▶ self-evolve cap ──▶ L1 proposer ──▶ L2 hard-commit ──▶ L3 skills ──▶ Convergence Cert
   (Y0,G0)              (Y0)               (Y1)            (Y1,G1*)           (Y2)          (Y2,G2)
        │                                    │                                │                │
        │                                    └── recall_verified (INV-5) ─────┘                │
        │                                        is the ONLY edge into L2                       │
        │                                                                                       ▼
        └── ROBR-1 firm (Y0) ──▶ DiFR research (Y2) ──▶ DiFR settlement + L4 (Y3,G3) ──▶ multi-operator MTL (Y5,G5)
                                                              │
                                                     Lean proof + audit (Y3)
```

**Hard ordering constraints (violate these and the program is unsound):**
1. **`self-evolve` capability (Y0) must exist before any L1 commit.** Today it doesn't (§(d) hazard 5). No proposer ships into an ungated substrate.
2. **G1's hard-commit boundary is the critical path for the entire thesis.** `recall_verified` (INV-5) being the *only* edge into L2 is what makes everything downstream governable. If G1 slips, everything slips.
3. **The Convergence Certificate (Y2) depends on FOREVER canaries (planted in Y2) and FCC auto-rewind (real-now L7).** No ratchet without a regression detector and a working rewind.
4. **DiFR research (WS-G) must start in Y2, one phase before its Y3 gate.** Starting DiFR in Y3 guarantees a slip — it is the program's deepest unknown.
5. **Lean/F\* proof and 3rd-party audit are Y3 gating items with long lead times** — contract them in late Y2.
6. **Non-equivocation (Y5) cannot be faked single-operator.** It structurally requires ≥2 independent operators; do not promise it before an ecosystem exists. The repo ships its own counterexample (`accum/t8_counterexample.rs`) as the honest marker of this wall.

**Parallelizable (no inter-dependency):** WS-E surface/SDK work runs continuously alongside everything; L3 skill-library scaffolding (Y2) can begin during Y1 once `parent_ids` lineage (Y0) lands; the Lean proof (WS-D) is independent of cognition layers and can proceed any time after the verifier API freezes.

---

## 7. The standing rule for every phase (non-negotiable)

Carried verbatim from `docs/ROADMAP.md` and `CLAUDE.md` §3, applied to *every* exit gate:

- **Fail-closed default** · **verifier TCB ≤ 500 lines** · **determinism byte-identical** · **authenticated ≠ true** · ship nothing until an adversarial red-team's forgeries fail closed.
- Each phase publishes an **honesty ledger** stating the exact level proven and what remains unproven. **Never claim truth.** Specifically and permanently: the substrate proves the loop *ran honestly and is logged faithfully* — it **cannot** prove the reward was meaningful, the model executed, the weights forgot, or (single-operator) that no off-log history exists.

---

**Relevant files (absolute):** `/Users/hawzhin/MNEME/CLAUDE.md` (canonical honesty wall §3, INV-5/INV-6, workspace layout — every layer's honesty scope must trace to a string here), `/Users/hawzhin/MNEME/docs/ROADMAP.md` (existing Phase 0–IV ledger this roadmap reconciles with), `/Users/hawzhin/MNEME/docs/phase-program/PROGRAM_STATUS.md` (honest %-complete per phase entering Y0).


---

# 06 — Evaluation, Data Strategy & the Risk Frontier

> **Scope of this section.** This is the measurement and risk contract for PROVENANCE. It defines how we will *prove* the 10x governance claim (not a benchmark claim), how we measure self-improvement without trusting the thing measuring it, what data the loop runs on, the full risk register, and the irreducible frontier. Every claim here traces to a string in `MnemeError`, an MCP tool description, a verifier export, or a layer honesty-scope in `MNEME_BLUEPRINT.md` / `CLAUDE.md §3`. Where this section names a capability, it carries a maturity tag: **[REAL-NOW]** (shipped substrate, measurable today), **[ACHIEVABLE]** (buildable with known techniques over the program horizon), **[ASPIRATIONAL]** (depends on an open research result or an unbuilt component). The honesty wall is non-negotiable: **authenticated ≠ true; ROBR binds context, not cognition; FCC deletes substrate records, not weights; single-operator MTL gives no non-equivocation.**

---

## 6.1 What "10x" Means and Therefore What We Measure

The thesis (§a) is **governance-shaped, not benchmark-shaped**. The 10x is the collapse of oversight cost from `O(steps)` of human review to `O(1)` receipt-checking with `O(challenge)` only on dispute. A section that measured PROVENANCE by AIME/SWE-bench deltas would be measuring the wrong axis and would invite the exact "smarter agent" overreach the naming decision rejected. We therefore split the metric surface into two disjoint families:

| Family | What it measures | Trust status of the measurement |
|---|---|---|
| **Governance metrics (primary)** | Cost & soundness of oversight: receipt-verify time, attribution completeness, deletion provability, challenge-window economics, rewind correctness | **In-TCB or substrate-checkable** — the number is itself a verified artifact |
| **Capability metrics (secondary)** | Did the loop get better at its task: reward curve, held-out pass-rate, skill-reuse rate, forgetting-canary retention | **Outside-TCB** — the judge is untrusted; these numbers are *evidence*, never *proof* |

The 10x is asserted **only** over the first family. The second family answers "is this worth governing at all," but a green capability number is never allowed to launder into a soundness claim. This split is the structural defense against the §d-Bet-2 failure ("a reward-hacked task gets a clean PCA lineage and a valid ROBR receipt"): we never let capability evidence buy down governance rigor.

### 6.1.1 The four governance metrics, each tied to a shipped primitive

These are the load-bearing numbers. All four are **[REAL-NOW]** measurable against shipped substrate crates; what is unbuilt is the *cognition loop that generates the events*, not the measurement.

1. **Attribution completeness** — fraction of capability-changing transactions whose lineage resolves to an MTL inclusion proof against a signed root. Target: `1.0` (a missing leaf is a fail-closed reject, not a degraded score). Measured over `mneme-account` receipts + `mneme-root` MTL leaves. *Honest scope: lineage edges in `Draft.parent_ids` are operator-**asserted**; completeness proves the edge was logged, not that the causal claim is true.*
2. **Oversight unit-cost ratio** — `(human-review-seconds in DGM/AZR baseline) / (receipt-verify-seconds in PROVENANCE)`. The verify side is `recall_verified` + MTL inclusion + ROBR `verify_output_binding`, all `O(1)` per event against a 500-line TCB. The 10x lives here.
3. **Deletion provability** — fraction of condemned transactions for which a T1 crypto-shred + T2 SMT non-membership ForgetProof verifies against a *fresh* signed root, plus a `mneme-accum` non-use witness. Target: `1.0`. *Honest scope: proves SUBSTRATE deletion + non-use in the operator-presented set, NOT model-weight unlearning (§d-Bet-4).*
4. **Challenge-window soundness** — under `mneme-optimistic`, the probability a forged ROBR/TopKClaim finalizes given ≥1 honest watcher within the window. Measured by adversarial replay (6.2.3). *Honest scope: collapses to vacuous with zero independent watchers (§d-Bet-3); the repo ships its own counterexample (`mneme-accum/src/t8_counterexample.rs`).*

> **Anti-Goodhart clause.** Metrics 1–4 are *liveness/soundness* metrics, not *quality* metrics. None can be improved by making the agent "smarter." They can only be improved by making the substrate more complete, which is the actual product. This is deliberate: it removes the incentive for the loop to game its own governance score.

---

## 6.2 Measuring Self-Improvement Without Trusting the Judge

### 6.2.1 The judge-outside-TCB problem (the central methodological hazard)

PROVENANCE's verifier TCB is 500 lines (`mneme-verify/src/lib.rs:21`, `TCB_LINE_BUDGET = 500`). A capable enough judge — an LLM grader, a learned reward model, a held-out benchmark scorer — **cannot** live inside it without destroying the budget and, worse, without importing an unverifiable oracle into the root of trust. So the judge is, and must remain, **outside** the TCB. This produces a hard, named asymmetry:

> The substrate can prove the judge's *verdict was recorded faithfully and is attributable* (MTL leaf over the reward cognition-cert on the `ActionReceipt`). It **cannot** prove the verdict was *correct*. `authenticated reward ≠ true reward`.

We do not pretend to close this. We *contain* it with four moves, in descending order of rigor:

1. **Verifiable-reward-first ordering [REAL-NOW for the verifiable subset].** Whenever the reward is itself a deterministic check — code execution, unit-test pass, proof-checker accept, formal-spec satisfaction (the AZR 2505.03335 / SPIRAL 2506.24119 regime) — the judge *is* in-TCB-equivalent: a Freivalds-style or re-execution check the verifier can replay. The eval methodology **prioritizes tasks with executable rewards** precisely because they are the only ones where capability and governance metrics coincide soundly. The fraction of the loop's tasks that carry an executable reward is itself a reported metric (`verifiable-reward coverage`), and it is the honest denominator on every capability claim.
2. **LLM-judge only as a *challengeable* signal [ACHIEVABLE].** Where no executable reward exists, an LLM judge's verdict is wrapped as a ROBR-bound `ActionReceipt` and exposed to the `mneme-optimistic` WatcherChallenge game. A disagreeing watcher re-runs the judge under DiFR nondeterminism tolerance (2511.20621) and posts a fraud proof. This converts "trust the judge" into "trust that ≥1 watcher disagrees on a bad verdict" — strictly weaker, and honestly so. *Honest scope: this is unbuilt — DiFR is **uncited in the codebase today** (verified: zero `.rs` references), and the watcher game is vacuous single-operator.*
3. **Judge-rotation + disagreement logging [ACHIEVABLE].** Following Group-Evolving Agents (2602.04837), maintain ≥2 independently-seeded judges; log the disagreement rate as a *trust signal on the judge, not the agent*. A rising inter-judge disagreement rate is an early reward-hacking alarm. This is measurement, not proof.
4. **Held-out verifiable sets the loop never trains on (6.3.2).** The Convergence Certificate predicate (§c-step-7) is evaluated *only* against held-out, executable-reward tasks + FOREVER canaries (2601.03938). A judge cannot be gamed on data it never saw and whose reward it cannot fabricate.

### 6.2.2 Benchmarks and held-out evals (concrete)

- **Self-evolution capability [secondary, outside-TCB].** Re-use the self-evolving-agent harnesses as *capability evidence only*: AZR's proposer/solver verifiable-reward suite (2505.03335), DGM's open-ended coding tasks (2505.22954), SPIRAL's zero-sum reasoning games (2506.24119), Search Self-play (2510.18821). Report curves; never promote a curve to a soundness claim.
- **Memory/continual [secondary].** A-MEM (2502.12110), LiCoMemory (2511.01448), Hindsight-20/20 retain-recall-reflect (2512.12818) for consolidation quality; FOREVER forgetting-curve replay (2601.03938) as the **canary set** that gates the Convergence Certificate.
- **The held-out governance eval [primary, in-TCB-checkable].** The certificate set: a frozen, signed bundle of executable-reward tasks + forgetting canaries, committed under a protected key, against which epoch N must show **reward non-decreasing AND no canary regression** before MTL-consistency-proving that epoch N dominates N−1. FAIL ⇒ FCC auto-rewind to last certified root (§c-step-7). This is the one eval whose *result* is a signed artifact.

### 6.2.3 Adversarial / generative evaluation [REAL-NOW, extend]

PROVENANCE already ships a generative tamper suite (`scripts/ci/validation-lane.sh tamper`, ≥150 cases) and the §21 killer-demo. The eval methodology *extends* these rather than inventing a new harness:

- **Tamper lane** — every receipt/proof type (`dcbor_parse`, `smt_parse`, `cap_parse`, `receipt_parse`, `cognition_cert_parse`, `index_wire`, `sync_message_parse` fuzz targets) must fail-closed on mutation. New PROVENANCE event types (proposal receipts, Convergence Certificates) get their own fuzz target before they ship.
- **Reward-hack red-team [ACHIEVABLE].** A dedicated adversarial set where the *task itself* is degenerate (reward-hackable). Success criterion is **honest**: the substrate must produce a clean PCA lineage and valid ROBR receipt for the hacked task (proving it cannot detect the hack), *and* the FCC reverse-on-demand path (§c-step-9) must fully retract it once condemned. We measure *reversibility of the wrong improvement*, never *prevention* — prevention is out of scope by §d-Bet-2.
- **Equivocation red-team [REAL-NOW partial].** Drive `t8_counterexample.rs` and the single-operator MTL gap as first-class eval cases: two timelines with identical valid non-use witnesses but unbounded σ_max gap must be *reported as indistinguishable*. The eval's job is to keep this limitation visible, not to hide it.

---

## 6.3 Data Strategy

### 6.3.1 The data thesis: the loop is its own data source, gated by INV-5

PROVENANCE inherits AZR's "zero external data" posture (2505.03335): the L1 proposer **invents** tasks at the edge of competence. This is a deliberate data-strategy choice — it sidesteps external-corpus licensing/poisoning and makes every datum natively attributable. The non-negotiable constraint is the **hard commit boundary** (NOEMA framing, §b-L2): the *only* input path into the fast loop is `recall_verified` (INV-5). No raw, unauthenticated datum ever seeds a proposer (L1), a checkpoint (L2), or a consolidation (L5). Untrusted `Store::recall` is `pub(crate)` and never agent-reachable.

Consequences for data handling:

- **Every experience is a signed object** with `parent_ids` lineage and a trust tier (Quarantine → Working → Trusted → Identity). Tool-written self-tasks **auto-Quarantine**; nothing graduates without an Ed25519 `promote` capability. [REAL-NOW for the substrate; the loop that fills it is [ACHIEVABLE].]
- **Provenance is structural, not annotated.** Because data is born inside the signed root, attribution is free — there is no separate "data provenance" pipeline to trust. This is the data-strategy payoff of the substrate.
- **Poisoning surface.** The residual surface is *the judge and the proposer*, not the corpus. A poisoned reward signal enters as authenticated experience (§c closing note). Mitigation is detection-by-disagreement (6.2.1) + reversibility (FCC), never input sanitization — there is no untrusted input to sanitize.

### 6.3.2 Held-out and canary data governance

- **Certificate set** (held-out): frozen, signed, committed under a protected key, **never** in any proposer's `recall_verified` reach. Leakage is detectable: if a held-out key ever appears in a proposal's `parent_ids`, that is a fail-closed integrity violation, not a silent contamination.
- **FOREVER canaries** (2601.03938): planted under protected keys; consolidation (L5) must preserve them. A canary regression at epoch boundary fails the Convergence Certificate and triggers rewind. Canaries double as the **catastrophic-forgetting** instrument.
- **RPT watermark** (radioactive provenance): a *statistical corroborator only* — it can suggest a datum influenced an output but **never proves non-use**; non-use proof comes solely from the `mneme-accum` accumulator witness. The data strategy must never cite RPT as a deletion guarantee.

### 6.3.3 Data retention, deletion, and the GDPR posture

Deletion is a first-class data-strategy primitive, not an afterthought, because the loop *durably amplifies* whatever it ingests (§d-Bet-2). FCC tiers: **T1** crypto-shred / **T2** SMT non-membership bound to a fresh signed root / **T3** (ε,δ) DP-influence (operator-asserted, scale-limited). On condemnation, DAG lineage is re-walked from the last clean root to re-derive tainted descendants (§c-step-9). *Honest scope, mandatory in every UX surface: this proves the **substrate record** is shredded and provably absent and the substrate non-use is witnessed — it does **not** prove the model weights forgot. A skill already consolidated into Titans/base weights survives FCC; only rolling weights to a prior checkpoint removes it, at the cost of all good learning since.*

---

## 6.4 Risk Register

Severity is `S` (catastrophic / high / medium), Likelihood `L`, residual after stated mitigation. Risks tagged **[OPEN]** have *no* sound mitigation and are honesty-frontier items, not engineering tasks.

### 6.4.1 Technical risks

| ID | Risk | S/L | Mitigation | Residual |
|---|---|---|---|---|
| T-1 | **Execution gap**: ROBR binds context, not cognition; no batch-invariant frontier backend exists, `mneme-attest` is a PEM/DER shape-parser not a production attestor | High / High | DiFR re-exec (2511.20621) with calibrated false-accept; optional ROBR-4 TEE on H100 (<7% overhead) | **[OPEN]** — DiFR **uncited in code today**; entire L6 settlement story unbuilt; until closed PROVENANCE proves the *box*, never the cognition (§d-Bet-1) |
| T-2 | **DiFR tolerance band τ is a soundness knob** an adversary probes | High / Med | Calibrate τ on adversarial replay; report false-accept rate as a governance metric | **[OPEN]** — band is intrinsically a soundness/throughput tradeoff |
| T-3 | **Cognition layers L1–L5 are zero lines of code** | High / Certain | Staged integration; mark every L1–L5 claim as integration target | High — no `self-evolve` scope, no Convergence Certificate ratchet, no DiFR exist yet; `bind_action` default-closed (`phase_iii_bind_action`) |
| T-4 | **Verification cost vs throughput**: per-step sign + SMT-upsert + PACE work + single-writer flock serialize a high-frequency loop | Med / High | Receipt batching | Med — batching **widens the unattested-action window**; SLA anchor: `recall_verified <1 ms @ 10k` |
| T-5 | **Semantic recall is procedure-faithful, not exact-NN** | Med / Certain | Honesty strings in `MnemeError` + MCP descriptions | Accepted — never claim exact nearest neighbors (CLAUDE.md §3.2) |
| T-6 | **`pedersen_schnorr_zk` mistaken for a SNARK** | Med / Med | Feature off by default; `B3_DEFERRAL_STATUS` string records Plonky2/FRI deferral | Low — it is a real transparent ZK of a retrieval-match, NOT a FRI/PLONK SNARK |

### 6.4.2 Safety risks

| ID | Risk | S/L | Mitigation | Residual |
|---|---|---|---|---|
| S-1 | **Reward-hacking inside the verifiable loop**: RLVR verifies the proxy, not intent; degenerate skill gets clean lineage + valid receipt + signed Convergence Certificate | Catastrophic / High | Verifiable-reward-first; judge rotation; held-out canaries; FCC reversibility | **[OPEN]** — substrate makes the *wrong* improvement perfectly auditable and reversible but **cannot detect it is wrong** and durably amplifies it (§d-Bet-2) |
| S-2 | **Substrate deletion ≠ model unlearning**: poisoned skill in weights survives FCC | High / High | T1/T2/T3 + checkpoint rollback as last resort | **[OPEN]** — weight rollback loses all good learning since; T3 DP-influence operator-asserted & scale-limited; UX must never imply weights forgot (§d-Bet-4) |
| S-3 | **Convergence Certificate gives false assurance** if its held-out set is contaminated or its reward is hacked | High / Med | Held-out leakage detection (6.3.2); certificate proves *monotone progress on the presented set*, nothing more | Med — a certificate is a signed claim about a set, not about reality |
| S-4 | **Autonomy-grant amplification**: cheaper oversight invites granting *more* autonomy, raising the blast radius of S-1 | High / Med | Attenuate-only capability per action; PACE rate-limit; ActionReceipt gate | Med — economic, not cryptographic |

### 6.4.3 Organizational / governance risks

| ID | Risk | S/L | Mitigation | Residual |
|---|---|---|---|---|
| O-1 | **Single-operator equivocation**: MTL gives inclusion+consistency but **no non-equivocation** without external witness gossip | High / High | External witness gossip; ≥2 hosts | **[OPEN]** — two-host determinism **unproven in repo memory**; local-first agent has no independent watcher; fraud-proof game collapses (§d-Bet-3) |
| O-2 | **Max-staleness unbounded (σ_max OPEN)**: PACE bounds *minimum* spacing only (T5) | Med / High | none sound | **[OPEN]** — "agent did not secretly evolve off-log" is unproven; repo ships `t8_counterexample.rs` as its own counterexample |
| O-3 | **Honesty-string erosion**: pressure to soften scope language in marketing/UX | Med / Med | Honesty strings are load-bearing in `MnemeError`, MCP tool descriptions, verifier exports; CI guards them | Low if enforced — never weaken (CLAUDE.md §3) |
| O-4 | **Agency over-narration**: presenting operator-asserted DAG edges as proven causation | Med / Med | All four Awareness faces label edges operator-**asserted** | Low — WHAT-I-KNOW / USED / FORGOT / HOW-I-CHANGED edges are asserted, not proven (§b-L9) |
| O-5 | **Misreading "verifiable" as "trustworthy AI"** | High / Med | Frontier statement (§e) front-and-center | Accepted — we prove the box, not the cognition |

---

## 6.5 What Remains Genuinely Research, or Impossible

This is the credibility anchor. We separate three tiers. Conflating them is the failure mode that turns an honest system into hype.

### 6.5.1 Genuinely research (open, plausibly closable over the program horizon)

- **Binding ROBR to a real frontier model.** Requires one of: a production batch-invariant inference backend (does not exist at scale), a production GPU TEE attestor (`mneme-attest` is shape-parse only today), or DiFR (2511.20621) with a *calibrated, adversarially-validated* false-accept rate. **[ASPIRATIONAL]** — and DiFR is currently uncited in the codebase, so this is a from-scratch build, not an integration.
- **Single-operator non-equivocation.** Needs an external witness/gossip layer or a decentralized log (the VeriLLM 2509.24257 / optimistic-rollup 2512.20176 direction). Without independent watchers the 1-of-N-honest game is vacuous. **[ACHIEVABLE]** only once a second honest party exists — which is an *organizational*, not cryptographic, precondition.
- **Bounding σ_max (max staleness).** Proving "no secret off-log evolution" needs a continuously-anchored heartbeat beyond PACE minima. **[ASPIRATIONAL]** — the repo proves it is *currently* open via `t8_counterexample.rs`.
- **Detecting (not just reversing) reward-hacking.** Inter-judge disagreement + canary regression are *heuristics*. A sound detector of "this reward was semantically meaningless" is an open alignment problem. **[ASPIRATIONAL]**.

### 6.5.2 Genuinely impossible under the stated honesty wall (do not promise, ever)

- **Proving the reward was *true*.** `authenticated reward ≠ true reward`. The loop can be proven to have *run honestly and been logged faithfully*; whether the reward signal meant anything is outside any cryptographic primitive. Closing this would require proving semantic truth, which §3.1 explicitly disclaims.
- **Proving the model executed, from a receipt alone.** ROBR's `weight_measurement` is operator-asserted; the receipt binds `H(memory_root | prompt | weight_measurement | sampling | context)`. Absent a hardware root of trust, the receipt binds the *context around* inference, not the inference. This is impossible by construction without TEE/attestation, and even then attestation proves *which weights*, not *that cognition was correct*.
- **Proving the model weights forgot.** FCC proves substrate-record deletion and substrate non-use. Weight-level unlearning at frontier scale with a *proof* (not an operator-asserted (ε,δ) bound) is unsolved; even the negative anchor zkLLM (2404.16109) is ~25h/100-token-output impractical and proves inference, not unlearning. The UX is *forbidden* from implying the weights forgot.
- **Proving exact nearest neighbors.** Semantic recall is procedure-faithful by design (§3.2); top-k over prover-asserted distances is not true-distance top-k unless verifiers recompute from carried embeddings. We will not call it exact-NN.

### 6.5.3 The one failure the architecture *cannot* close (restated for the build team)

> PROVENANCE proves the loop *ran honestly, was attributed faithfully, paced verifiably, and can be deleted with a receipt* — but it cannot prove the cognition inside the box was correct, that the reward was meaningful, that the model truly executed, that the weights forgot, or (single-operator) that no off-log history exists. **It makes the wrong improvement perfectly auditable and reversible without making it detectable.**

That sentence is the product's honest ceiling. An engineering agency building this over years should treat any roadmap item that implicitly violates it as a red flag, not a milestone. The value proposition survives the ceiling precisely *because* we state it: governability of an autonomous learner is worth building even when — especially when — correctness of the learner remains unprovable.

---

**Canonical authority traced:** `/Users/hawzhin/MNEME/CLAUDE.md` (§3 honesty wall, INV-5/INV-6, TCB budget), `/Users/hawzhin/MNEME/MNEME_BLUEPRINT.md`. **Shipped primitives verified in-repo for this section:** `crates/mneme-verify/src/lib.rs:21` (`TCB_LINE_BUDGET = 500`); `crates/mneme-accum/src/t8_counterexample.rs` (σ_max OPEN, `T8_COUNTEREXAMPLE_HONESTY`); `crates/mneme-account/src/lib.rs` + `tests/bind_action.rs` (ROBR, `phase_iii_bind_action` default-closed); `crates/mneme-index/src/pedersen_schnorr_zk.rs` (`B3_DEFERRAL_STATUS`). **Confirmed unbuilt:** DiFR has zero `.rs` references in `crates/` (grep verified) — L6 settlement and L1–L5 cognition layers are integration targets, written as such throughout.


---

## Appendix A — Adversarial audit verdicts (why feasibility is 2/5, honestly)


**ANAMNESIS — the Proof-Carrying Self** — feasibility **2/5**, verdict *merge*

- Strongest idea kept: Proof-Carrying Autobiography (L3) + substrate-level reversible deletion (L6): a capability-gated, append-only DAG of signed roots recording ancestor variant + source episodes for every self-modification, paired with a forget() that emits a non-membership ForgetProof against a fresh root and an accumulator non-use witness. This is attribution + surgical record-rollback, both buildable on what is already shipped, and it is a real, defensible governance primitive that DGM/AZR lack — provided it is marketed as 'tamper-evident provenance + record deletion,' never as proven causation or model unlearning.

- Hardest unknown: Reward-hacking / specification-gaming sits INSIDE the verifiable loop and the substrate cannot detect it — a degenerate skill that satisfies a self-proposed verifiable reward gets a clean PCA lineage, a valid ROBR receipt, and a passing CCSP predicate. The substrate makes the WRONG improvement perfectly auditable but cannot tell it is wrong. Combined with single-operator equivocation (no non-equivocation without external witness gossip, which a local-first personal agent has no source of), the two pillars that would make 'verifiable self-improvement' meaningful are precisely the two the architecture admits it cannot close.

- Hype flagged & removed: The headline 'VERIFIABLE self-improvement' is the weakest claim. The 'watcher fraud-proof game' it points to (mneme-optimistic, 245 lines) is a kNN top-k counterexample checker: verify_challenge proves a closer committed vector was omitted from a top-k set. It has ZERO connection to verifying that a model improved or that an improvement-eval ran. The proposal reframes a vector-search soundness primitive as 'a watcher can disprove a fraudulent improvement' — a category error.; DiFR-style nondeterminism-tolerant re-execution is referenced as the 'realistic execution-faithfulness check' but does NOT exist in the codebase (grep for 'difr' returns nothing). The entire VEIR/L5 settlement story is unbuilt and assumes 1-of-N honest watchers WITH access to the full self-play dataset — an assumption the document itself admits collapses for a single-operator local-first agent.; The whole ML loop is vaporware relative to the repo: no AZR proposer/solver, no self-play, no Titans/surprise-driven L1 neural memory, no sleep-time consolidation, no EvoSkill, no self-evolve capability scope (it would be a caveat, not a primitive). Every L1/L2/L4 'sota_used' is a citation, not an integration. The 'fusion onto MNEME's shipped substrate' is 90% unwritten.; 'FORENSIC TIME-TRAVEL OVER A LIVING MIND' and 'continuously-enforced checkable non-use per future answer' overclaim: per-recall non-use is proven only over the operator-PRESENTED certified set, and the model weights may still behaviorally exhibit the 'forgotten' skill. The moonshot conflates substrate-record non-use with behavioral non-use.

**NOEMA — a verifiable world-model & latent-reasoning agent OS on the MNEME substrate** — feasibility **2/5**, verdict *merge*

- Strongest idea kept: The hard commit boundary between a fast unverified plastic layer and a slow signed ground-truth, where the ONLY input path into the fast loop is recall_verified (INV-5). Even with zero neural layers built, 'an authenticated-only I/O membrane around an adaptive cache, with a signed checkpoint minted on surprise so any online delta is revertible' is a concrete, shippable, genuinely novel governance primitive for test-time-learning agents — and it sits exactly at MNEME's real strength. Build this one seam against a stub fast-layer and you have a defensible artifact without the fiction.

- Hardest unknown: The execution gap: binding context to a weight_measurement is not proving the model executed those weights. Closing it needs either (a) a real H100 TEE attestation chain (mneme-attest is a shape-validating stub today) or (b) DiFR-style probabilistic re-execution with a calibrated false-accept rate against real frontier models — which does not exist, and whose tolerance band is itself a soundness knob an adversary hides perturbations inside. Until this closes, 'verifiable self-improvement' is verifiable bookkeeping over unverifiable cognition, and that is the load-bearing word in the entire thesis.

- Hype flagged & removed: The neural half of NOEMA does not exist anywhere in this repo. L1 Titans test-time memory, L2 Coconut/latent-reasoning, L4 AZR/DGM self-play, L5 sleep-time consolidation — grep finds ZERO matches for titans/coconut/latent-reasoning/test-time-train in crates/. Every '10x' verb (learns-during-inference, self-evolves, reasons-in-latent-space) lives in unbuilt layers. MNEME is a memory+receipt substrate, not an agent OS. The proposal smuggles a frontier-model research program in under a shipped-substrate banner.; 'Verifiable self-improvement' is verifiable bookkeeping of an UNVERIFIED cognition. The execution gap is unclosed by the proposal's own admission: weight_measurement is operator-asserted, mneme-attest is a PEM/DER shape-validator stub (header literally says 'stub, vendor-agnostic' / not a production attestor), DiFR is a probabilistic claim with an adversary-tunable tolerance knob and no calibrated false-accept rate. The system proves the ledger, not that the model ran those weights.; 'Proof-carrying autobiography' overstates causation. Draft.parent_ids edges are operator-ASSERTED, not proven causal — a buggy or adversarial agent mints flattering lineage. 'Which task gave me this capability' is a tamper-evident CLAIM, not proven gradient causality. The autobiography is authenticated, not true — which is exactly MNEME's own §3 wall turned against the headline.; 'Court-admissible erasure guarantee' for the moonshot oversells. FCC proves substrate non-use; it does NOT unlearn a gradient already consolidated into Titans/base weights. For a system whose entire point is a learning agent, the most likely place harmful knowledge lives (the weights) is exactly where the proof does not reach. The honest caveat is present but the moonshot framing buries it.

**PROVENANCE — Provably Reversible Oversight-Verified Engine for Networked Attributable Neural-memory Continual Evolution** — feasibility **2/5**, verdict *merge*

- Strongest idea kept: The Proof-Carrying Autobiography pattern applied narrowly: a DAG-of-signed-roots where each self-modification carries (capability token that authorized it) + (MTL inclusion proof) + (FCC-reversible ForgetProof). This is the one genuinely novel, mostly-shippable composition that no DGM/AZR/Voyager system has — and it is buildable on primitives that ALREADY exist default-on (signed roots, MTL, ForgetProof, capabilities). Strip the unbuilt L1/L3/L4/L5 agent layers and the unbuildable execution-integrity claims, and ship 'a tamper-evident, capability-gated, reversible changelog for ANY external self-modifying agent' as a substrate product.

- Hardest unknown: Can ROBR ever bind to a REAL frontier model, not a deterministic toy kernel? Every governance claim ('the eval actually ran', 'O(1) oversight', 'trust the autobiography') collapses to operator-assertion unless execution-integrity is closed — which today requires either a batch-invariant inference backend that does not exist, a production TEE attestor (mneme-attest is shape-parse only), or DiFR (uncited in code, and itself only statistical-tolerance, tolerance-spoofable). Until this is closed, PROVENANCE proves the BOX around cognition, never the cognition. Compounding it: reward-hacking durability — the substrate makes a cryptographically-attested BAD curriculum perfectly auditable and reversible but cannot detect that it is bad (authenticated != true), so the substrate faithfully amplifies whatever the (nonexistent) RLVR loop produces.

- Hype flagged & removed: 'FIRST self-improving agent whose every change is verifiable/attributable/reversible' — the self-improving agent does not exist in this repo. L1 self-play, L3 sleep-time/Voyager, L4 Titans neural memory, L5 latent reasoning are ZERO lines of code: pure paper citations (AZR/DGM/Titans/Coconut) glued to MNEME hooks. The '10x' rests on components that are not built.; 'DiFR-checked ROBR receipt' / 'execution becomes a DiFR-checked receipt' — DiFR (2511.20621) appears NOWHERE in the codebase. ROBR-2 'replay-verify' re-executes a deterministic REFERENCE-KERNEL STAND-IN, not any model; the honesty string itself says binding a real model needs a batch-invariant backend (nonexistent) or TEE.; 'continuing per-recall class-group accumulator non-use witness' — Jewel C is an explicit SCAFFOLD: 32-bit primes against a ~1M test modulus, 'not wired into recall/receipt' (accum/src/jewel_c.rs:21). The repo ships a counterexample proving non-use does NOT bound max spacing (T8).; 'ROBR-4 TEE weight attestation hardening' — mneme-attest parses PEM/DER SHAPE ONLY (lib.rs:5). There is no TEE attestor. weight_measurement is operator-asserted, meaning the entire execution-integrity story is currently trust-me.


---

## Appendix B — Open specification backlog (must close before Y0 build)


- No reconciliation of the actual TCB line count. A builder cannot enforce the 500-line budget or the 'auditable in an afternoon' moat without a single canonical measured number and a defined counting rule (does it include tests? re-exports? the crypto/smt verify helpers the draft folds into the TCB?). Measured total is 464 src lines; the draft's 394 and 474 are both unsourced.

- No definition of how the ROBR envelope's `context` field absorbs the L4 latent-reasoning Merkle root or the cognition-cert reward. The draft asserts this binding in §02.7/§03.6 but `robr.rs` shows `context` as an opaque field — there is no specified schema for what goes in it, so a builder cannot implement L4→ROBR binding from this spec.

- DiFR settlement (the program's central Y3 research bet) has no acceptance criterion for τ calibration. The draft repeatedly says 'τ is a soundness knob' but never states a target false-accept bound, a calibration dataset, or what 'published calibration' must contain. Without that, G3 is unfalsifiable.

- The 'self-evolve' capability scope is named everywhere but never specified: what operations it gates, how it attenuates, how it differs from the existing `promote`/`forget`/write scopes in mneme-cap. A builder needs the scope grammar before Y0 (the draft itself makes it the hard Y0 ordering constraint).

- No throughput budget reconciling the per-step sign + SMT-upsert + PACE sequential-work + single-writer flock against any target self-evolution step rate. §03.12/§06 raise 'verification cost vs throughput' as hardest-bet #5 but give no numbers (steps/sec achievable vs AZR/DGM step rate), so the 'receipt batching widens the unattested window' tradeoff cannot be evaluated.

- The 107 FTE-year / 5-year envelope has no funding-contingency or off-ramp accounting tied to the [ASPIRATIONAL] gates (DiFR, TEE attestor, non-equivocation). The draft says each can exit 'box-only' but does not say what the program delivers / is worth if all three aspirational bets fail — the most likely scenario given the honesty framing.


**Strongest real differentiator (audit consensus):** Provable, attributable, REVERSIBLE deletion as a first-class substrate primitive (FCC: T1 crypto-shred + T2 SMT non-membership bound to a fresh signed root, with prove_absent rejecting live keys, plus the mneme-accum non-use witness) — verified shipped in `crates/mneme-forget/src/absent.rs` and `crates/mneme-accum/`. The draft correctly notes there is 'no SOTA to graft' on the deletion side: every cited memory system (Letta, A-MEM, Titans, Voyager) governs memory by policy and offers no deletion you can verify against a signed root. Critically, this is the ONE differentiator whose honesty boundary is narrow and survivable: 'substrate deletion, not weight unlearning' is a clean, defensible line, unlike the execution-binding and non-equivocation claims which collapse without unbuilt external infrastructure. It is the load-bearing, genuinely-novel, already-shipped contribution.