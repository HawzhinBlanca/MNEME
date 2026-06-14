# MNEME capability surface (offline-verifiable certificates)

Every capability below ships as a `mneme` CLI verb that emits a **signed,
offline-verifiable** artifact plus a `verify-*` checker. Each artifact embeds an
honesty string that states exactly what it proves — and, just as importantly, what it
does **not**. The cardinal rule (CLAUDE.md §3) holds across all of them:

> MNEME proves integrity, provenance, authorization, and faithful **execution of a
> declared procedure** — never **semantic truth**, never **exact nearest neighbors**.
> Authenticated ≠ true.

Read the "Proves / Does NOT prove" columns before relying on any artifact. A binding,
a spot-check, a statistical signal, and a cryptographic proof are different things, and
this table keeps them distinct on purpose.

## Recall & deletion (kernel-backed)

| Verb | Proves | Does NOT prove |
|---|---|---|
| `recall` / MCP `memory.recall` (key) | the returned entry is the committed value at this logical key under the signed root (fail-closed receipt) | anything about content truth |
| MCP `memory.recall` (with `embedding`) | procedure-faithful semantic recall over the committed candidate set under the **quantized** metric | true nearest neighbors; quantized top-k may differ from real-valued |
| `fcc` / `verify-fcc` | tiered forgetting closure over a real `ForgetProof`: **T1** wrapping-key destroyed (ciphertext unrecoverable), **T2** + proof-of-absence bound to the signed root; tier re-derived at verify (overclaim rejected) | that a downstream **model** which consumed the data has unlearned it (FCC-3/T3 frontier). Substrate deletion ≠ model unlearning |

## ROBR — Recall-to-Output Binding (behavioral receipts)

| Verb | Proves | Does NOT prove |
|---|---|---|
| `robr` / `verify-robr` | the output commitment is **bound** to `H(memory_root ‖ prompt ‖ weight_measurement ‖ sampling ‖ context)`; signed; envelope re-derived at verify | that the model actually produced the output; `weight_measurement` is operator-asserted until attested |
| `verify-robr --replay` | the committed output is the **bit-identical re-execution** of the declared deterministic reference kernel on the committed inputs | that the reference kernel is a real model — it is a deterministic stand-in until a batch-invariant inference backend + TEE (ROBR-4) |
| `robr-freivalds` | a logged matmul `C=A·B` checks out via Freivalds (false-accept ≤ 2⁻ʳᵒᵘⁿᵈˢ, exact integer arithmetic) | that the matrices are a real model's layers; it is a probabilistic spot-check, not a proof |
| daemon `recall` (http/unix) · MCP `memory.recall` with `robr_*` | the live recall mints a ROBR-1 receipt (`robr_receipt_b64`) binding the output commitment to the verified context under the current signed root; a partial `robr_*` set is rejected fail-closed | (same boundary as `robr`) that the model produced the output, or any semantic truth |

## CCR — causation & attribution over verified context

| Verb | Proves | Does NOT prove |
|---|---|---|
| `replay` / `verify-replay` | the counterfactual **context** changes when a named verified entry is removed (which memories entered context under the signed root) | model-output causation; semantic truth |
| `shapley` / `verify-shapley` | per-entry marginal-impact counts over a hash-bound judge command, deterministic from the seed | that the judge's execution was attested; truth of the judgment |

## MTL — Memory Transparency Log (CT-for-AI-memory)

| Verb | Proves | Does NOT prove |
|---|---|---|
| `mtl` / `verify-mtl` | the operator's signed head commits to this memory root at this index (RFC 6962 inclusion) | non-equivocation by the operator |
| `mtl-consistency` / `verify-mtl-consistency` | the current head is an **append-only extension** of an earlier head (RFC 6962 consistency) — rewriting logged history fails | that two *separately published* heads are mutually consistent (needs witness gossip — single-operator log) |
| `mtl --from-checkpoints` | the inclusion receipt is built from the kernel's authoritative committed root history (`Store::checkpoint_log_statements`), so the logged statements cannot drift from what was actually committed | non-equivocation (still single-operator) |
| `agent-card` / `verify-card` | a JWS/Ed25519-signed Agent Card advertises the operator's attestation endpoint (A2A discovery seed); pin the operator key out-of-band | that the endpoint is reachable, honest, or itself attested |
| `pace verify` over `meta/root-pace.log` (store `root_pace_log` feature, **default-off**) | a BLAKE3-sequential hash-chained pace-log of committed roots (`seq:preimage` labels), crash-safe atomic append | it is **NOT** an RFC 6962 transparency log — no inclusion/consistency proofs, single-operator; a derived, rebuildable artifact (every root is in the signed checkpoint log) |

## RPT — Radioactive Provenance Tracer (EXPERIMENTAL, off by default)

| Verb | Proves | Does NOT prove |
|---|---|---|
| `rpt-probe` | a **statistical** signal (z-score + p-value) that a token stream carries a record's per-DAG-node watermark | nothing cryptographically. **NEVER proves non-use** (no clean negative); signal only for partners that **train** on the data (not RAG); needs query access. Detection ≠ proof |

## How to read a verdict

- A `verify-*` exit code of `0` means the artifact verified under its stated boundary.
- Each command also prints its `honesty:` line — the authoritative scope statement.
- "Bound / logged / spot-checked / detected" are **not** "true." The substrate proves
  chain-of-custody and faithful execution; it never adjudicates whether a remembered
  fact is correct.

Frontier items deliberately **not** shipped (documented in
[WORK_ORDER_EXTERNALIZED_MIND.md](WORK_ORDER_EXTERNALIZED_MIND.md)): ROBR-2 real-model
replay (batch-invariant backend) → ROBR-4 TEE attestation, FCC-2/3 DP-influence /
certified unlearning, TTRP KZG constant-size proofs, MTL-3 cross-head **witness gossip**
for non-equivocation (the A2A Agent-Card discovery seed is shipped; multi-operator
gossip is not), RPT real-model contamination harness. Each is blocked on hardware or
research, and each is labeled with its trust assumption rather than faked.
