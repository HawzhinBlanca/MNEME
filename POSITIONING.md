# MNEME Positioning

Where MNEME sits relative to databases, RAG stacks, and cryptographic verification — and
what it deliberately does **not** claim.

## Verifiable memory, not a truth oracle

MNEME is a **fail-closed verifiable recall system** for AI-agent memory. Every agent read can carry an
offline-checkable receipt against a signed root under a declared retrieval procedure.

```
  Query + capability
        │
        ▼
  ┌─────────────────┐
  │ verify_recall   │  proves: integrity, provenance, authorization,
  │ (fail-closed)   │          procedure-faithfulness over committed set
  └─────────────────┘
        │
        ▼
  Verified entries ──► does NOT prove: semantic truth of content
```

**What MNEME proves**

- Integrity — recalled bytes match committed objects.
- Provenance — writer identity and capability scope at write time.
- Authorization — read/write/promote/forget within issued capabilities.
- Temporal validity — bi-temporal coordinates on the signed root.
- Absence — authorized forget/shred cannot be selectively resurrected (INV-6 + tombstones).

**What MNEME does not prove**

- **Semantic truth.** An authorized writer can sign false content; verification succeeds
  because the signature and procedure are valid (*authenticated ≠ true*).

## Procedure-faithfulness vs exact nearest neighbors

Vector recall in MNEME is **verifiable**, not **optimal-by-default**.

| Claim | v0 / Phase I disposition |
|---|---|
| Membership + completeness over committed candidates | Proven (ProcedureFaithfulTopK / CompleteTopK paths) |
| Top-k over prover-asserted distances | Proven for the authenticated candidate set |
| True top-k by query-to-embedding distance | **Not proven** until verifiers recompute from carried embeddings |
| Global exact-NN optimality (no closer hidden point) | Phase IV research; no PIOP prover shipped |

Verifiable retrieval (§3) proves **procedure-faithfulness**, not exact nearest neighbors: the
declared retrieval procedure ran faithfully over committed, un-tampered data. Phase I
`ProcedureFaithfulTopK` proves membership/completeness plus top-k over prover-asserted distances;
true top-k ranking is not proven, and returned items are not top-k by true query-to-embedding distance until verifiers recompute from carried embeddings.

The optional `pedersen_schnorr_zk` feature adds a transparent ZK proof of faithful
retrieval-match execution — still not semantic truth and still not global exact-NN.

## Software verifier vs hardware TEE (Phase II)

| Layer | Role | Status |
|---|---|---|
| `mneme-verify` (≤500 lines) | Offline receipt gate in agent process | **Shipped** |
| TEE / enclave context binding | Bind model output to attested context | **Deferred** — human/hardware-gated |

Software verification is prerequisite: receipts must be mathematically checkable before any
future enclave wraps execution.

## Comparison sketch (honest)

| System class | Typical guarantee | MNEME difference |
|---|---|---|
| Vector DB / RAG | Approximate NN + trust operator | Receipt + signed root; fail-closed verify |
| Content-addressed store | Integrity of blobs | + capabilities, provenance, forget proofs |
| Blockchains | Global consensus | No chain; local signed roots + optional sync |
| ZKML / SNARK provers | Proof of inference | MNEME proves **memory + retrieval procedure**, not model inference truth |

## Release posture

- **Single-host v0** — certified for correctness, tamper, cross-impl vectors, MCP SDK recall.
- **Cross-physical-host** — root determinism proven (macOS/arm64 ↔ Windows/x86_64); SSH
  continuous re-verification requires `MNEME_SECOND_HOST` (operator-gated).
- **OSS release docs** — this file plus `SECURITY.md`, `CONTRIBUTING.md`, `THREAT_MODEL.md`;
  tag and public advisory process remain human release decisions.

See also: `README.md`, `docs/ROADMAP.md`, `docs/phase-program/PROGRAM_STATUS.md`.
