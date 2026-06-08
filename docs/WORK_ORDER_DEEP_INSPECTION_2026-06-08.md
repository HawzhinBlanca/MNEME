# MNEME — Prioritized Work Order (deep-inspection findings, 2026-06-08)

**Source:** multi-agent deep inspection of branch `harden/differential-adversarial`
(11 subsystem maps + full CLI e2e + 5 research briefs + adversarial verification).
**Author:** watcher/reviewer agent. **For:** the autonomous hardening agent.

These are gaps the green validation ladder + deep-cert **do not cover** — the gates
exercise the paths they test and were blind to these. None is a regression; all are
structural. Items tagged **[CONFIRMED]** were re-verified against the code by hand;
**[EVIDENCE]** are agent findings with file:line cited (high confidence, verify before fix).

**Honesty-boundary reminder (do not weaken):** authenticated ≠ true; procedure-faithful
≠ exact-NN; `commitment_binding` = BLAKE3 envelope (not ZK); `pedersen_schnorr_zk` = real
transparent ZK, off by default, not a SNARK. Several P0 items below are honesty-boundary
defects *in shipped source* — fixing them protects the product's core claim.

Acceptance criteria are written so the 30-min watch sweep (fmt/clippy/TCB-budget/honesty/
tests/tamper/determinism/cross-impl) stays green after each change.

---

## P0 — Honesty defects in shipped source + the one confirmed correctness bug
*(cheap, brand-critical, do first; ~1–2 days total)*

### WO-1 — A-REPLAY HLC regression check is numerically wrong  **[CONFIRMED]** ✅ DONE
- **Where:** `crates/mneme-root/src/lib.rs:127` `check_replay` does `current.hlc_max < last`
  on two `[u8;14]` arrays (lexicographic from byte 0); `crates/mneme-core/src/hlc.rs:64`
  `to_bytes()` writes `wall_ms` **little-endian** → numeric order scrambled (e.g. 256 sorts < 255).
- **Severity:** defense-in-depth bug (NOT a full INV-6 break — the primary A-REPLAY defense is
  sequence/checkpoint monotonicity, which is sound; that's why gates stay green).
- **Fix:** compare via `Hlc::from_bytes(..).cmp(..)` (struct `Ord` is correct), or change
  `to_bytes` to big-endian for the high-water-mark. Keep the on-disk format decision documented.
- **Acceptance:** new test feeds two roots whose `wall_ms` differ in a way that crosses a byte
  boundary (e.g. 255 → 256) and asserts `check_replay` rejects the true regression and accepts the
  true advance; all existing root/store/e2e tests stay green.

### WO-2 — False `aws-kms` Cargo-feature claim in shipped docstring  **[CONFIRMED]** ✅ DONE
- **Where:** `crates/mneme-crypto/src/envelope_vault.rs:2` claims master key "via `aws-kms` feature".
  No `[features]` section and no aws/kms dep exist in `mneme-crypto/Cargo.toml`.
- **Fix:** reword to "master key from `MNEME_KMS_MASTER_KEY_HEX` (e.g. an AWS KMS data key fetched
  out-of-process by `scripts/kms/dek-from-aws.sh`)". Remove the phantom feature reference.
- **Acceptance:** `grep -rn 'aws-kms' crates/mneme-crypto` returns nothing implying a Cargo feature.

### WO-3 — MCP `CONTRACT.md` describes an rmcp server that doesn't exist  **[EVIDENCE]** ✅ DONE
- The transport is a hand-rolled JSON-RPC 2.0 stdio loop (serde_json); there is no `rmcp` dep.
- **Fix:** rewrite to describe the real public surface (`MemoryHandlers`/`dispatch`/`tool_definitions`/
  `open_runtime`) and the hand-rolled loop; drop the `rmcp`/`MnemeMcpServer ServerHandler` claim.
- **Acceptance:** CONTRACT matches `crates/mneme-mcp/src/*`; no `rmcp` reference remains.

### WO-4 — Stale "Skeleton/placeholder" comment contradicts the code  **[EVIDENCE]** ✅ DONE
- `crates/mneme-core/src/accountability.rs:88` calls `ForgetProof` a skeleton whose `shred_commit`/
  `absence_path` "nothing populates or verifies yet" — but they ARE populated
  (`mneme-account/.../forget.rs`) and verified (`mneme-account/.../verify.rs`).
- **Fix:** update the comment to reflect that they are populated+verified. (See also WO-19.)

### WO-5 — Remove the stale protoc "blocker" from `HUMAN_TASKS.md`  **[CONFIRMED]** ✅ DONE
- The entry claims `mneme-cli`/`mnemed` Cargo gates "remain blocked until protobuf codegen can
  execute." Both build clean via vendored protoc; `env -u PROTOC cargo build -p mnemed` with the
  proto touched (forced codegen) succeeds; vendored + Homebrew protoc both run `--version`.
- **Fix:** delete or rewrite the entry to reflect that codegen works (vendored protoc).

### WO-6 — `TCB_MANIFEST.md` is out of sync with the trusted surface  **[EVIDENCE]** ✅ DONE
- Tier-2 lists `verify_ads_vo` but the code calls `verify_semantic_receipt_tcb_gate`, and never names
  `procedure.rs`/`provenance.rs`/`commit.rs`/`semantic_zk.rs`/`zkann.rs`. The manifest's own rule
  ("untrusted-byte parsers must be in the guard lint set") is violated for the semantic path.
- **Fix:** name the real entry point + every transitive trusted file. (Pairs with WO-9.)

### WO-7 — `mneme audit` subcommand is a non-functional stub  **[CONFIRMED]** ✅ DONE
- `crates/mneme-cli/src/main.rs:412` routes `Audit` to `require_path_exists()` → always exit 3,
  despite help text "Print provenance, writers, tiers, tombstones."
- **Fix:** implement it (read-only provenance/writer/tier/tombstone dump) OR change the help text to
  honestly say "not yet implemented" and return a typed `Unsupported`.

### WO-8 — Missing root `LICENSE` file  **[EVIDENCE]** ✅ DONE
- `Cargo.toml` declares Apache-2.0 but no `LICENSE` file exists. Blocking for any OSS release (L4).
- **Fix:** add the Apache-2.0 `LICENSE` text at repo root.

---

## P1 — Correctness scope + deployment hardening
*(~1–2 weeks; unblocks L2/L3 trust)*

### WO-9 — Bring the semantic TCB gate into the guarded/budgeted surface  **[EVIDENCE]** ✅ DONE
- `verify_semantic_recall` trusts ~1066 prod lines in `mneme-index`
  (`verify_semantic_receipt_tcb_gate` → `verify.rs`/`procedure.rs`/`provenance.rs`/`commit.rs`/
  `semantic_zk.rs`/`zkann.rs`) that are **outside** `verify-tcb-guard.sh` scope and the 500-line
  budget; uses HashMap/HashSet (guard-forbidden) + 4 unaudited `as usize` casts on attacker-influenced
  `Procedure` fields.
- **Fix:** (a) extend the guard lint set to those files with explicit justified allow-markers, replace
  the 4 casts with checked conversions, and resolve the HashMap iteration determinism; or (b) move the
  gate logic into `mneme-verify` under budget. Document a "budget-raise tied to guard-scope expansion"
  procedure so logic never leaks out of the audited surface again.
- **Acceptance:** guard lints the semantic surface; manifest (WO-6) names it; tests green.

### WO-10 — State zkANN ranking honesty (membership ≠ ranking)  **[EVIDENCE]** ✅ DONE
- zkANN/ADS rank by prover-supplied distances; a compromised store can demote the true nearest and
  surface a different authentic member. "exact dominance ⇒ true top-k" is overclaimed.
- **Fix:** make the public claim explicit — membership + completeness are proven, top-k *ranking* is
  not — in `MnemeError`/contract/honesty strings; or implement a verified distance bound.

### WO-11 — `MNEME_NO_FSYNC` is a silent production durability kill-switch  **[EVIDENCE]** ✅ DONE ✅ DONE
- Checked in prod write paths (`atomic.rs:26,31,41`; `layout.rs:629,643`; vault/envelope). Any process
  with the env set silently disables all durability fsyncs, no warning, no audit trail.
- **Fix:** gate behind `cfg(debug_assertions)`/a test-only feature so release builds can't honor it; if
  kept, read once at `Store::open`, emit a loud one-time warning, and persist a store-meta "durability
  disabled" flag a later cold-open/audit can detect.

### WO-12 — No inter-process store lock  **[EVIDENCE]** ✅ DONE
- `open_store_lock` (`atomic.rs:152`) is `#[allow(dead_code)]` and does no `flock`. Two processes on one
  store dir can interleave transactions and strand an UNMARKED partial state cold-open would accept.
  Threatens L2.
- **Fix:** take a real advisory `flock LOCK_EX` on a lockfile in `Store::open`, hold for the Store
  lifetime, fail with a typed `StoreLocked`; document the single-writer-process invariant in CLAUDE.md.

### WO-13 — No `.incomplete` repair/recovery tooling + orphan-object GC  **[EVIDENCE]** ✅ DONE
- `abort_transaction` keeps `.incomplete` (fail-closed by design) but the only recovery is manual
  `rm .incomplete` (used in tests). A transient IO error → permanently un-openable store. Partial-write
  object blobs also leak with no GC.
- **Fix:** add `mneme repair` / `Store::recover` that re-validates on-disk state vs HEAD and clears the
  marker only if self-consistent, else reports what's partial; sweep orphan blobs; document the runbook.

### WO-14 — Daemon production hardening  **[EVIDENCE]** ✅ DONE
- **Original finding:** mnemed minted an ephemeral operator key + `Store::create` on every boot
  (caps from a prior boot failed verify); no Unix `SO_PEERCRED`/`getpeereid` uid check; `--http`
  accepted `0.0.0.0` with no TLS; daemon API test files were suspected orphaned under
  `autotests = false`.
- **Disposition:** `boot_daemon_state` persists the operator key and opens existing stores;
  Unix sockets check same-uid peer credentials; HTTP binds refuse non-loopback addresses without
  TLS; `api_integration` is the declared aggregate target for `http_api`/`grpc_api`/`sync_ws`, and
  `unix_ready` is compiled by the Unix/redteam targets. Evidence commit: `af70b2d`.

### WO-15 — Zeroize secrets  **[EVIDENCE]** ✅ DONE
- No `zeroize` anywhere; master key, `ObjectKey`, ed25519 `SigningKey` never wiped on drop. Table stakes
  for L3 and the HSM story.
- **Fix:** add `zeroize`; wrap master + per-object keys in `Zeroizing`/`ZeroizeOnDrop`; zeroize bytes
  popped on `shred()`; enable ed25519-dalek `zeroize` feature.

### WO-16 — Forget: chameleon redaction is placeholder; shred witness under-binds  **[EVIDENCE]** ✅ DONE
- `forget_redact` builds a `TrapdoorKey` then passes it unused (`_trapdoor`); the redaction slot is a
  publicly-recomputable BLAKE3. `shred_witness_commit` binds only key_hash/object_id/Option<KeyId> — not
  proof the vault key bytes are gone.
- **Fix:** wire the trapdoor or feature-gate/remove the redaction path honestly; bind a vault-tombstone
  hash (or AEAD-still-fails witness) into the shred witness.

---

## P2 — Close the L1 MCP gap + L3 delivery
*(~1 week of code; the headline use case + audit artifacts)*

### WO-17 — MCP `recall` is exact-key-only despite a `query` param  **[EVIDENCE]** ✅ DONE
- Maps `query` → `LogicalKey.name`, `embedding:None`, `default_key_procedure` → exact key lookup. An
  agent passing natural language silently gets empty results. No HNSW wired into MCP.
- **Fix:** wire the semantic recall path behind an explicit `mode` arg, OR rename the param to
  `name`/`key` and state "exact logical-key lookup, not semantic search" in the description.
- **Acceptance:** a live-subprocess test where a non-exact-key query returns the documented result
  (either semantic hits, or an explicit not-found that the description predicts).

### WO-18 — MCP failure surface + input safety + seed custody  **[EVIDENCE]** ✅ DONE
- **Original finding:** tool failures returned JSON-RPC `-32000` (some hosts hide from the model)
  instead of `CallToolResult{isError:true}` with the honesty footer; no input size caps/rate limiting;
  operator seed persisted plaintext to `<store>/.operator_seed`; a new tool-writer key was
  auto-authorized each boot.
- **Current disposition:** tool failures, size caps, and idempotent tool-writer derivation are in place;
  operator seed custody is centralized in `mneme-crypto::operator_seed`; KMS-backed runs seal/migrate the
  seed at `keys/operator_seed.sealed` under `MNEME_KMS_MASTER_KEY_HEX` (XChaCha20-Poly1305 envelope,
  same master as `EnvelopeKeyVault`); no-master runs require an explicit process-custody seed and fail
  closed instead of reading or creating plaintext `.operator_seed`. Unit tests cover round-trip reopen,
  legacy migration, tamper (`ObjectTampered`), and wrong-master fail-closed; CLI e2e rejects init without
  custody; `source_invariants` blocks frontend `.operator_seed` writes.
- **Fix:** route MnemeError tool failures as `isError:true` (+honesty footer), JSON-RPC errors only for
  protocol faults; add content/query size caps; use `EnvelopeKeyVault` for the operator seed and make
  tool-writer authorization idempotent.

### WO-19 — Surface `ForgetProof` as a self-contained signed deletion certificate  **[CONFIRMED]** ✅ DONE
- **Original finding:** `Store::forget` dropped the proof; `mnemed/src/unix.rs:756` computed
  `prove_absent` and discarded it (`let _proof = ...`); MCP had no forget-proof tool. The L3
  "prove a deletion" artifact had no complete delivery surface.
- **Current disposition:** CLI `mneme forget --emit-proof`, MCP `memory.forget_proof`, mnemed HTTP
  `DELETE /v1/forget-proof/{namespace}/{name}`, and mnemed Unix `ForgetProof` now return canonical
  `ForgetProof` CBOR bound to the post-commit signed root.
- **Fix:** add a CLI `mneme forget --emit-proof <path>` and an mnemed endpoint that return the
  `ForgetProof`; ideally make it a single offline-verifiable signed blob (or bundle the matching Root).

### WO-20 — Audit event export (L3)  **[EVIDENCE / research]** ✅ DONE
- **Original finding:** `mneme.audit` tracing covered verified-recall rejection, promote, and forget,
  but the dropped sync-peer hook was a dead store-kernel stub.
- **Current disposition:** `mneme.audit` tracing events cover `verify_recall` rejection, promote,
  forget, and mnemed sync peer drops from the production sync client plus WebSocket server
  suppressed/drop paths. Sync peer events carry `peer` and `reason`.
- **Fix:** emit structured OpenTelemetry events on every `verify_recall` rejection, promote, forget, and
  dropped sync peer (the who/when/from-what). Named in the blueprint §15.4.

---

## P3 — Long-tail capabilities (mostly human/hardware-gated — see research briefs)

- **L2 two-host CONVERGENCE proof:** A1 already proves cross-host *root* determinism (macOS/arm64 ↔
  Windows/x86_64, `XHOST_DETERMINISM_PROOF.md`). The gap is that the determinism scripts run only
  single-node `foundation-gate`; the **CRDT merge/anti-entropy** path is never run cross-host and
  convergence is asserted on roots, not the object SET. `scripts/ci/convergence-two-host.sh` now
  compares deterministic object-set digests after merge convergence, supports same-host
  `--local-smoke`, and fails closed under `MNEME_STRICT_CROSS_HOST=1` unless
  `MNEME_SECOND_HOST` is set. The real proof still needs a distinct physical host.
- **Real KMS/HSM adapter:** AWS+GCP+PKCS#11 envelope, two-tier KEK rotation, conformance harness.
  `mneme_crypto::run_key_vault_conformance` and `scripts/kms/conformance-local.sh` now provide
  the no-secret adapter contract scaffold, including same-id/different-key conflict rejection.
  Live AWS/GCP/PKCS#11 proof and two-tier KEK rotation remain external-endpoint work.
- **TEE attestation:** off by default, Nitro first (COSE/CBOR, simplest single root), then SGX-DCAP /
  SEV-SNP; a frozen `AcceptedReportPolicy` (pinned root, measurement allowlist, nonce/freshness).
  `mneme-attest` now has `verify_accepted_report_policy` and
  `scripts/ci/attestation-policy-local.sh` for local fail-closed policy checks over already-verified
  claims; real vendor quote verification and hardware evidence remain external.
- **Formal methods:** `docs/FORMAL_METHODS_SCAFFOLD.md` and
  `scripts/ci/formal-obligations-local.sh` now inventory the local proof-obligation scaffold: TCB
  guard self-test, current TCB guard scan, TCB line-budget test, and honesty-doc boundary test.
  Real Lean/F*/Kani/Bolero proof artifacts remain human-gated.
- **P3 local aggregate gate:** `docs/P3_LOCAL_SCAFFOLDS.md` and
  `scripts/ci/validation-lane.sh p3-local` run the no-secret convergence, KMS/HSM, TEE policy, and
  formal-obligation scaffolds together while preserving the human-gated proof boundaries.
  `scripts/ci/p3-local-watch-history-summary.sh` validates retained watch history rows and emits
  the recent pass/fail streak for hourly reports. `scripts/ci/p3-local-hourly-report.sh` reruns
  the local lane and writes a durable local-only `hourly-report.json` artifact, retained snapshots,
  and compact `hourly-report-index.json` with retained `reports` plus `latest_report_sha256`;
  `scripts/ci/p3-local-hourly-report-verify.sh` verifies that saved report without rerunning the lane.
- **OSS release:** LICENSE (WO-8), `SECURITY.md`, `CONTRIBUTING.md`, `THREAT_MODEL.md`, and
  `POSITIONING.md` are present with guarded honesty strings. Remaining release actions are human
  content review, merge/release decision, and tag.

---

## Suggested sequence
P0 (1–2 d) → P1 correctness/hardening (1–2 wk) → P2 L1+L3 delivery (1 wk) → P3 (weeks–months, gated).
After each P0/P1/P2 item, the watch sweep should stay green; P3 items unlock the per-layer ceilings
documented in the readiness review. Cross-reference: `docs/REMAINING_ITEMS.md`, `docs/HUMAN_TASKS.md`,
`docs/TCB_MANIFEST.md`.

---

## Completion log (2026-06-08 session, branch `harden/differential-adversarial`)

| WO | Status | Evidence |
|----|--------|----------|
| WO-1 | DONE | `cmp_wire` in `hlc.rs`; `check_replay` uses numeric compare; test `check_replay_rejects_numeric_hlc_regression_across_byte_boundary` |
| WO-2 | DONE | `envelope_vault.rs` docstring; `grep -rn 'aws-kms' crates/mneme-crypto` clean |
| WO-3 | DONE | `mneme-mcp/docs/CONTRACT.md` describes hand-rolled JSON-RPC + `MemoryHandlers`/`dispatch` |
| WO-4 | DONE | `accountability.rs` ForgetProof comment matches `mneme-account` populate/verify |
| WO-5 | DONE | protoc blocker row removed from `HUMAN_TASKS.md` |
| WO-6 | DONE | `TCB_MANIFEST.md` names `verify_semantic_receipt_tcb_gate` + transitive files |
| WO-7 | DONE | `mneme audit` help text + honest `StoreUnavailable` exit (not fake path check) |
| WO-8 | DONE | root `LICENSE` (Apache-2.0) added |
| WO-9 | DONE | Semantic Tier-2 surface added to `verify-tcb-guard.sh`; self-test catches `HashSet` + `panic!`; procedure bounds use checked conversions; `TCB_MANIFEST.md` ties future semantic scope/budget changes to guard coverage |
| WO-10 | DONE | `ProcedureMismatch` + `RetrievalDominanceFailed`, verifier/MCP/CLI honesty exports, contracts, crossref, and feature-gated status strings now state membership/completeness is proven while true top-k ranking is not; source/tests guard the phrases |
| WO-11 | DONE | `durability_fsync_enabled()` debug-only; `audit_durability_at_open` warns + writes `meta/durability_disabled.json` |
| WO-12 | DONE | `open_store_lock` advisory `flock`; `Store` holds lock for lifetime; `LockHeld`; CLAUDE.md single-writer invariant |
| WO-13 | DONE | `repair_store` + `mneme repair`; verify-then-clear `.incomplete`; orphan object blob sweep |
| WO-14 | DONE | `boot_daemon_state` persists operator + opens store; loopback HTTP refused; Unix `getpeereid`/`SO_PEERCRED`; `api_integration` aggregate target compiles/runs `http_api`/`grpc_api`/`sync_ws` and `unix_ready` is compiled by Unix/redteam targets; fixed mnemed HTTP bind parse type inference; evidence `af70b2d` |
| WO-15 | DONE | `zeroize` on `KeyPair` drop + vault `shred`; `ed25519-dalek/zeroize` feature |
| WO-16 | DONE | Chameleon trapdoor wired in `forget_redact`; `shred_witness_commit` binds `vault-tombstone-v1` + key id |
| WO-17 | DONE | MCP `key` param + description states exact logical-key lookup; `query` deprecated alias |
| WO-18 | DONE | Tool failures return `isError:true` + honesty footer; content/query size caps; idempotent tool-writer derivation; `mneme-crypto::operator_seed` seals/migrates `keys/operator_seed.sealed` under `MNEME_KMS_MASTER_KEY_HEX`; round-trip/tamper/wrong-master tests + CLI init fail-closed + frontend custody invariant |
| WO-19 | DONE | `mneme forget --emit-proof`; MCP `memory.forget_proof` (full ForgetProof CBOR + signed-root fields, `isError:true` + honesty footer on failures); mnemed HTTP `DELETE /v1/forget-proof/{namespace}/{name}`; mnemed Unix `ForgetProof`; smoke: `mcp_forget_proof_tool_returns_verifiable_cbor_and_signed_root_fields`, `stdio_forget_proof_returns_verifiable_cbor_and_signed_root_fields`, `mcp_forget_proof_failure_returns_is_error_with_honesty_footer` |
| WO-20 | DONE | `mneme.audit` tracing events on verify_recall rejection, promote, forget, and mnemed sync peer drops; daemon client/server hooks wired and dead store stub removed |
| P3 OSS docs | NOT-SHIPPED | Planned: root `SECURITY.md`, `CONTRIBUTING.md`, `THREAT_MODEL.md`, `POSITIONING.md` + honesty-doc guards. No files on branch @ `3b44142`; tracked in `docs/HUMAN_TASKS.md`. |
| P3 local scaffolds (aggregate) | NOT-SHIPPED | Planned research/scaffold only: convergence-two-host local smoke, KMS/HSM conformance harness, TEE attestation policy gate, formal-obligations scan, `validation-lane.sh p3-local` aggregate. Spec sketched in prior session notes; **no scripts or docs committed** on branch @ `3b44142`. Human-gated external proofs unchanged. |
| P0 gate | GREEN | `scripts/ci/validation-lane.sh quick` after all P0 fixes |
| P1/P2 gate | GREEN | `scripts/ci/validation-lane.sh quick` + `tamper` after WO-9..WO-20 feasible slice |
| P1/P2 closeout | SOFTWARE-COMPLETE | WO-1..WO-20 done; `cargo test -p mnemed` 299/299; stale `source_invariants` refs refreshed after `decode_hex32` + `load_content_addressed_objects` refactor (no symbol restore needed) |
| P3 determinism (local) | GREEN | `scripts/ci/validation-lane.sh determinism` @ `3b44142` |
| P3 tamper (local) | GREEN | `scripts/ci/validation-lane.sh tamper` @ `3b44142` |
| PR #8 e2e fix | SHIPPED | `3b44142` — Node CLI smoke passes `MNEME_KMS_MASTER_KEY_HEX` custody for init/verify (WO-18 sealed operator seed) |
| Stash disposition | DROPPED | `non-wo14`, `post-wo20-wip`, `wip-after-wo20`, `non-wo20`, `wo20-temp` dropped @ `3b44142` — superseded by committed WO-14..WO-20 work; older branch stashes on `master`/phase branches retained |
