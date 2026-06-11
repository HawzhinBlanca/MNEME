# MNEME Human Tasks

Last updated: 2026-06-11

This file is the parking lot for reliability and readiness work that cannot be
completed by a local autonomous agent without external credentials, hardware, or
operator decisions. Autonomous runs should keep hardening local code and tests,
and update this file only when a genuinely human-gated item changes.

## External Credentials And Hosts

| Task | Human input needed | Current in-repo substitute |
|---|---|---|
| Live LLM MCP loop | Provide `ANTHROPIC_API_KEY`, install `@anthropic-ai/sdk`, and set `MNEME_MCP_BIN` if the default binary is not used. | DELIVERED 2026-06-11 — live loop proven (`e2e/mcp/live-agent.test.mjs`, pass 1/fail 0). No-credential substitutes still run in CI. |
| SSH peer re-verification | Configure a distinct physical peer and CI secrets: `MNEME_SECOND_HOST` and `MNEME_DETERMINISM_SSH_KEY`. | Cross-runner determinism proof and dual-workspace checks remain the no-secret proof path; SSH is for continuous ops re-verification. |
| Cloud KMS/HSM continuous proof | Provide a real `AWS_KMS_KEY_ID`, cloud credentials, or a GCP/PKCS#11 endpoint. | `EnvelopeKeyVault`, `scripts/kms/dek-from-aws.sh`, and the HSM/KMS adapter contract compile and document the seam. |

## Hardware, Formal Methods, And Governance

| Task | Human input needed | Why local agents should not fake it |
|---|---|---|
| TEE/enclave attestation | Select hardware/provider, provision attestation environment, and define accepted report policy. | Software placeholders must stay fail-closed; a mock report does not prove enclave execution. |
| Lean verifier proof | Assign a formal-methods owner and proof acceptance criteria. | The repository can document proof obligations, but a claimed machine-checked proof needs actual Lean artifacts and review. |
| Semantic VO distance-recompute interface change | Integration owner must approve the v-next `VerificationObject`/certificate shape, contract-version bump, and release policy for carrying candidate embeddings. See `docs/research/SEMANTIC_VO_DISTANCE_RECOMPUTE_VNEXT.md`. | `mneme-core::VerificationObject` and certificate wire fields are frozen seams; local agents must not silently mutate them to retire the distance-binding caveat. |
| CompleteTopK store recall path | **Landed** | `SemanticIndex::recall_receipt_zkann(CompleteTopK)` issues ball-tree proofs from live embeddings; store `certify` + offline `verify-cert` green. |
| CompleteTopK cross-impl vector | **Landed** | Appendix B `cognition_cert_complete_topk.cbor` + `mneme-crossref` field-8 decode/verify. |
| Real embedding compression sweep | Provide a fixed embedding corpus (e.g. 10k vectors, documented license) for 768/1536-d `|F|/n` benchmarks. | Synthetic `complete_knn_compression` test documents curse-of-dimensionality; cannot claim real-RAG compression without data. |
| Trust-ops pilot | Choose pilot operators, rotation policy, audit cadence, and incident workflow. | These are organizational controls, not code-only deliverables. |
| Phase IV prover/interop commitments | Decide whether to fund global exact-NN PIOP work and external SDK/package compatibility targets. | Current Phase IV material is research/sketch work; shipping claims need product and ecosystem decisions. |

## P3 Local Scaffolds (landed on `master` — not external P3 proof)

In-repo substitutes for human-gated P3 proofs — **landed** via PR #37 @ `28f3cf47`.
Passing `validation-lane.sh p3-local` proves scaffold scripts and local checks only;
live KMS/HSM, distinct physical host, TEE enclave, and Lean proofs remain operator-gated.

| Scaffold | Status @ `28f3cf47` | Notes |
|---|---|---|
| OSS release docs | **Landed** | Root `SECURITY.md`, `CONTRIBUTING.md`, `THREAT_MODEL.md`, `POSITIONING.md`; tag/release decision still human-gated |
| Convergence local smoke | **Landed** | `scripts/ci/convergence-two-host.sh --local-smoke`; distinct-host still needs `MNEME_SECOND_HOST` |
| KMS/HSM conformance harness | **Landed** | `scripts/kms/conformance-local.sh` local vault round-trip; live endpoint proof still operator-gated |
| TEE attestation policy gate | **Landed** | `scripts/ci/attestation-policy-local.sh` fail-closed parser; live vendor quotes human-gated |
| Formal obligations scan | **Landed** | `scripts/ci/formal-obligations-local.sh` TCB guard + budget inventory; Lean proof human-gated |
| `validation-lane.sh p3-local` | **Landed** | Aggregate local gates — see `docs/P3_LOCAL_SCAFFOLDS.md` |

## Handling Rule

- Do not store secrets, temporary credentials, hostnames with embedded usernames,
  or private endpoint details in this file.
- When one of these tasks becomes available, run the documented proof path and
  replace the row with evidence links instead of marking it done from intent.
