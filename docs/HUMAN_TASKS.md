# MNEME Human Tasks

Last updated: 2026-06-08

This file is the parking lot for reliability and readiness work that cannot be
completed by a local autonomous agent without external credentials, hardware, or
operator decisions. Autonomous runs should keep hardening local code and tests,
and update this file only when a genuinely human-gated item changes.

## External Credentials And Hosts

| Task | Human input needed | Current in-repo substitute |
|---|---|---|
| Live LLM MCP loop | Provide `ANTHROPIC_API_KEY`, install `@anthropic-ai/sdk`, and set `MNEME_MCP_BIN` if the default binary is not used. | `scripts/ci/mcp-agent-sim.sh` and `e2e/mcp/sdk-client.test.mjs` cover deterministic and SDK-client paths without credentials. |
| SSH peer re-verification | Configure a distinct physical peer and CI secrets: `MNEME_SECOND_HOST` and `MNEME_DETERMINISM_SSH_KEY`. | Cross-runner determinism proof and dual-workspace checks remain the no-secret proof path; SSH is for continuous ops re-verification. |
| Cloud KMS/HSM continuous proof | Provide a real `AWS_KMS_KEY_ID`, cloud credentials, or a GCP/PKCS#11 endpoint. | `EnvelopeKeyVault`, `scripts/kms/dek-from-aws.sh`, and the HSM/KMS adapter contract compile and document the seam. |

## Local Toolchain Remediation

| Task | Human input needed | Current in-repo substitute |
|---|---|---|
| Restore protobuf codegen execution on this Mac | Approve, reinstall, or otherwise repair the local `protoc` execution path. Current evidence: the vendored `protoc-bin-vendored-macos-aarch_64` binary exits before printing a version, and Homebrew `protoc` is blocked by macOS library-load policy for its `abseil` dependency. | Source-level cert hardening checks and `mneme-core` embedding tests still run; `mneme-cli` and `mnemed` Cargo gates remain blocked until protobuf codegen can execute. |

## Hardware, Formal Methods, And Governance

| Task | Human input needed | Why local agents should not fake it |
|---|---|---|
| TEE/enclave attestation | Select hardware/provider, provision attestation environment, and define accepted report policy. | Software placeholders must stay fail-closed; a mock report does not prove enclave execution. |
| Lean verifier proof | Assign a formal-methods owner and proof acceptance criteria. | The repository can document proof obligations, but a claimed machine-checked proof needs actual Lean artifacts and review. |
| Semantic VO distance-recompute interface change | Integration owner must approve the v-next `VerificationObject`/certificate shape, contract-version bump, and release policy for carrying candidate embeddings. See `docs/research/SEMANTIC_VO_DISTANCE_RECOMPUTE_VNEXT.md`. | `mneme-core::VerificationObject` and certificate wire fields are frozen seams; local agents must not silently mutate them to retire the distance-binding caveat. |
| Trust-ops pilot | Choose pilot operators, rotation policy, audit cadence, and incident workflow. | These are organizational controls, not code-only deliverables. |
| Phase IV prover/interop commitments | Decide whether to fund global exact-NN PIOP work and external SDK/package compatibility targets. | Current Phase IV material is research/sketch work; shipping claims need product and ecosystem decisions. |

## Handling Rule

- Do not store secrets, temporary credentials, hostnames with embedded usernames,
  or private endpoint details in this file.
- When one of these tasks becomes available, run the documented proof path and
  replace the row with evidence links instead of marking it done from intent.
