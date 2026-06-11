# Trick #2 — Homomorphic Context-Set Lock (research scaffold)

**Status:** feature-gated scaffold + tests — **not shipped** on recall/TCB paths.
**Honesty:** do not conflate this with Pedersen/Schnorr ZK retrieval match proofs
(`pedersen_schnorr_zk`, off by default) or with the Phase II strict context gate
(`context_gate`, off by default).

---

## 1. What Trick #2 is meant to prove (founder memo)

A **context-set lock** would let a verifier check that a model's output was derived
from an *exact, committed* set of recalled entries — without re-running inference and
without revealing private entry bodies to an untrusted host. The "homomorphic" framing
in the vision memo refers to binding output to a committed context multiset in a way
that survives log replay and offline audit.

That is **not** what Phase I receipts prove today. Phase I proves integrity,
provenance, authorization, and procedure-faithful retrieval over committed geometry —
not that a specific model forward pass consumed exactly those bytes.

---

## 2. What exists in-repo today (honest map)

| Component | Location | What it actually does | Trick #2? |
|---|---|---|---|
| Strict context gate | `context_gate` feature; `mneme-index::context_gate`, `mneme-store::context_gate`, `mnemed::context_gate` | Re-derives consumption attestation + optional output binding over **carried plaintext** when gate is open | **No** — bytes-only strict check, not homomorphic |
| Cognition cert v2 draft | `cognition_cert.rs` behind `context_gate` | Wire fields for attestation/output-binding drafts | **No** — schema seam, not a homomorphic proof |
| Pedersen/Schnorr ZK | `pedersen_schnorr_zk` feature | Proves committed value equality for retrieval-match witness privacy | **No** — equality-of-openings NIZK, not context-set lock |
| TEE attestation policy | `mneme-attest`, P3 scaffold | Fail-closed policy over verified claims | **No** — hardware path human-gated |

**Default builds:** all of the above are **off** or **fail closed**. There is no
production homomorphic context-set lock on the agent read path.

---

## 3. Scaffold boundaries (do not weaken)

1. **`context_gate` stays default-off.** Enabling it requires explicit feature flags and
   operator intent; cold paths must remain fail-closed when the gate is closed.
2. **No "homomorphic" marketing on BLAKE3 envelopes.** `commitment_binding` is a tagged
   hash envelope only — not zero-knowledge, not homomorphic.
3. **Pedersen/Schnorr remains retrieval-match ZK**, not a context-set lock. Do not rename
   or relabel it as Trick #2 in user-facing strings.
4. **Interface freeze:** `VerificationObject`, receipt fields, and certificate wire shapes
   in `mneme-core` require an integration-owner change request before adding a real lock
   proof field.

---

## 4. Minimum honest delivery before "shipped"

Before Trick #2 can leave research status, the repo needs at least:

1. A **normative statement** (frozen wire + verifier entry) of what is being proved:
   e.g. "output digest binds to committed context multiset hash H(C)" with explicit
   assumptions (model identity, assembly profile, replay window).
2. A **verifier-budgeted check** under the MNEME TCB discipline (or an explicitly
   audited Tier-2 surface with guard coverage), with fail-closed defaults.
3. **Negative tests** showing substituted context, truncated sets, or replayed outputs
   are rejected.
4. **§3 honesty strings** updated everywhere the feature surfaces — authenticated ≠ true;
   binding ≠ semantic correctness.

Until then, documentation and feature-gated scaffolds are the only honest posture.

---

## 5. Scaffold implementation (2026-06-11)

Feature context_set_lock (off by default): Pedersen sum + Schnorr NIZK sidecar, tests, crossref wire. Parked: cert v2 field, recall_verified/TCB, enclave proof.

---

## 6. Related docs

- Phase II task spec: [`docs/PHASE_II_TASK_SPEC.md`](../PHASE_II_TASK_SPEC.md)
- Context gate red-team notes: [`docs/redteam/PHASE_II_CONTEXT_GATE_NO_INJECTION.md`](../redteam/PHASE_II_CONTEXT_GATE_NO_INJECTION.md)
- Trick #1 (beacon spot-check): [`docs/research/TRICK1_BEACON_SPOT_CHECK.md`](TRICK1_BEACON_SPOT_CHECK.md)
- Vision / transparency log composition: [`docs/VISION_PROOF_CARRYING_COGNITION.md`](../VISION_PROOF_CARRYING_COGNITION.md)
