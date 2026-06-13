# Work Order — The Externalized Mind (Capabilities 1–5)

**For:** the autonomous MNEME engineering agents. **Reviewer/verifier:** the watcher agent — every
task lands only when its **proof** (a runnable test/artifact) is green and I have re-verified it.
**Baseline:** `master` @ `v0.7.0` (`3fedc80f`). **Spec roots:** `docs/research/THE_EXTERNALIZED_MIND.md`,
`docs/research/VERIFIABLE_COGNITION_PROGRAM.md`.

## How to work (implement powerfully, prove everything)
1. **One isolated worktree/branch per task** (avoid cross-task collision; the post-merge classifier
   break taught us combined trees interact — verify the merged result, not just the branch).
2. **Fail-closed, typed errors, no panics on the trusted path.** If a task adds a parser of
   untrusted bytes, add it to `verify-tcb-guard.sh` and name it in `TCB_MANIFEST.md` (WO-9 rule).
3. **Every task ships a proof.** Acceptance = a committed test/bench/vector that demonstrates the
   guarantee AND a generative tamper suite (≥150 cases where a forgery is possible) that fails
   closed 100%. Byte-deterministic artifacts (two runs identical). CI green under `-Dwarnings`.
4. **Adversarial self-check before claiming done.** For each soundness claim, write the attack that
   would break it and show it's rejected. A wrong result is a finding, not something to hide.
5. **Honesty boundary widens, never weakens.** These capabilities expand MNEME beyond
   single-machine/tiny-TCB/fail-closed-only. **Every new tier MUST state its trust assumption in
   the artifact itself** (replay-verified vs TEE-attested; storage-erased vs influence-bounded;
   cryptographic vs statistical). Authenticated ≠ true remains absolute. No claim may exceed what
   its proof establishes.
6. **No frozen-seam edits** (`mneme-core/src/interface.rs`) without an interface-change request —
   use sidecar commitments until then.
7. **Report back per task:** the proof command, its output, the tamper-suite count + 0 forgeries,
   the trust assumption stated, and any deviation. Mark `[CORE]` (buildable now) vs `[FRONTIER]`
   (hardware/research-gated — deliver the honest scaffold + the stated gap, do not fake it).

---

## Capability 1 — ROBR: Recall-to-Output Binding Receipt  *(the strong-mode result; start here)*
Giants: TML batch-invariant kernels (bit-identical completions) + Freivalds (1977, O(kn²), err ≤ 2⁻ᵏ)
+ TEE attestation + MNEME signed roots. **Guarantee:** "this output is the deterministic, reproducible
consequence of this verified memory state under this attested model" — court-grade causal binding.
Builds directly on the shipped CCR replay code (`crates/mneme-cli/src/replay.rs`) and tonight's
proven cross-host bit-identical determinism.

- **ROBR-1 `[CORE]` — Receipt envelope.** New `mneme-robr` crate (or `mneme-cli` module). Define
  `RobrCertV1` binding `H(memory_root ‖ prompt_commit ‖ weight_measurement ‖ sampling_params) →
  output_token_commit`, Ed25519-signed, strict length-prefixed wire, fail-closed decode, internal
  consistency checks. **Proof:** round-trip test; **every-byte-flip tamper suite (≥256 cases) all
  reject**; signed-but-inconsistent cert rejected; byte-identical re-encode.
  - **✅ LANDED** as `mneme-cli` module `robr.rs` (`RobrReceiptV1`) + `mneme robr` /
    `mneme verify-robr` subcommands. Envelope = `H(root ‖ prompt_hash ‖ weight_measurement ‖
    sampling_params ‖ context_hash) → output_token_commit`, Ed25519-signed, strict
    length-prefixed wire reusing the CCR fail-closed `Reader`. Verify re-derives the envelope
    from the bound inputs and rejects any signed-but-inconsistent receipt. **Proof:** `robr.rs`
    unit tests (round-trip, every-byte-flip, truncation/trailing, wrong-pinned-pk,
    envelope-mismatch, **200-case generative tamper, 0 forgeries**) + `tests/robr_e2e.rs`
    (CLI receipt → offline verify → tampered fails closed code 4). Honesty: binding only —
    not model-output causation (ROBR-2/4), `weight_measurement` operator-asserted until TEE.
- **ROBR-2 `[CORE]` — Replay verifier (no TEE).** A `mneme robr verify --replay` path that re-runs a
  **deterministic, batch-invariant** reference kernel over the committed (memory_root, prompt,
  sampling) and asserts **bit-identical** output-token equality to the receipt. Use a small
  deterministic toy kernel as the reference adapter; document the vLLM/SGLang batch-invariant
  integration seam. **Proof:** honest receipt verifies; a 1-token-altered output fails closed;
  determinism test — two replays byte-identical (mirror foundation-gate ×2). State trust assumption:
  *"replay-verified: verifier re-ran the deterministic kernel; trusts the kernel determinism, not a TEE."*
  - **✅ LANDED.** `robr::reference_kernel` (deterministic BLAKE3-XOF over the binding
    envelope; envelope-sensitive, host-independent) + `replay_reproduces_output`.
    `mneme robr --reference-kernel` mints a replay-verifiable receipt; `mneme verify-robr
    --replay` re-executes and asserts bit-identical output, else fails closed (exit 4).
    **Proof:** unit tests (kernel determinism + envelope-sensitivity, replay accepts
    kernel output, replay rejects non-kernel output, replay fails when a bound input
    changes) + e2e (`robr2_reference_kernel_receipt_replay_verifies`,
    `robr2_replay_rejects_non_reference_kernel_output`). Honesty (`ROBR_REPLAY_HONESTY`):
    re-executed not asserted; the reference kernel is a deterministic STAND-IN — binding
    to a real model needs a batch-invariant inference backend (vLLM/SGLang seam) and
    ROBR-4 TEE for weight attestation; never semantic truth.
- **ROBR-3 `[CORE]` — Freivalds spot-check path.** For each logged per-layer matmul `C=A·B`, verify
  `A(Br)=Cr` for random `r` over `k` rounds (O(n²)/round, soundness err ≤ 2⁻ᵏ) instead of recompute.
  **Proof:** correct products accept; a single tampered product entry is caught with empirical rate
  ≥ 1−2⁻ᵏ over N trials (report the measured detection rate); FP/quantization handling stated
  (fixed-point or interval-Freivalds — name which).
  - **✅ LANDED.** `freivalds` module: `MatMulClaim` + `freivalds_verify` checks
    `A·(B·r) == C·r` over Fiat–Shamir 0/1 challenge vectors bound by commitment to
    `(shape, A, B, C)`, **exact integer (i128) arithmetic — fixed-point, no FP** (so it
    is deterministic and host-independent), false-accept ≤ 2⁻ʳᵒᵘⁿᵈˢ (default 64).
    `mneme robr-freivalds [--tamper]` demo. **Proof:** unit tests (50 honest products all
    accept; **100 single-entry tampers all caught** at 64 rounds; challenge binds to the
    matrices + is deterministic; malformed shape fails closed; all-wrong product
    rejected) + e2e (`robr3_freivalds_demo_accepts_honest_and_detects_tamper`). Honesty:
    probabilistic spot-check, not a proof; logged matrices are a deterministic stand-in
    until a real inference backend (ROBR-2/4).
- **ROBR-4 `[FRONTIER]` — TEE attestation envelope.** Add `weight_measurement` provenance + an
  `AcceptedReportPolicy` (vendor, pinned root, measurement allowlist, nonce/freshness) as an
  off-by-default field; parse a real Nitro/SGX-DCAP report. **Proof:** a sample real report verifies
  under policy; a stale/forged report fails closed. Honest gap: Apple Silicon has no TDX-class
  confidential GPU — the M-series story is the replay branch (ROBR-2), not local TEE; say so.

## Capability 2 — FCC: Forgetting-Closure Certificate  *(GDPR Art. 17 into the model)*
Giants: MNEME crypto-shred/absence + certified unlearning (Koloskova ICML'25, Guo) + DP
deletion-capacity (Sekhari NeurIPS'21) + ZK proof-of-unlearning (Eisenhofer'25). **Guarantee:**
"authenticated deletion" → "bounded behavioral forgetting," with the cert honestly stating which tier.

- **FCC-1 `[CORE]` — Tiered certificate (T1+T2).** Chain a deletion event into a `ForgettingClosureCert`
  with **T1 storage erasure** (existing crypto-shred + proof-of-absence) and **T2 retrieval erasure**
  (proof the record is removed from the authenticated ANN/Merkle-HNSW index via re-rooting). The cert
  field `tier_achieved ∈ {T1, T1+T2}` is mandatory and signed. **Proof:** after forget, T1 absence
  verifies AND T2 shows the record absent from the re-rooted index (membership query fails closed);
  tamper suite forging any tier rejects; cert states tier explicitly.
  - **✅ LANDED (cert framework + storage-erasure tiers).** `fcc` module:
    `ForgettingClosureCertV1::from_forget_proof` builds a signed cert over a real
    `ForgetProof`; mandatory `tier_achieved` is **re-derived at verify** from the carried
    evidence and an overclaimed tier is rejected even when signed. Tiers as shipped:
    **T1 = crypto-shred** (wrapping key destroyed), **T2 = crypto-shred + proof-of-absence**
    bound to the signed root. `mneme fcc` / `mneme verify-fcc`. **Proof:** unit (T2
    round-trip, T1 when no absence, redact-without-shred has no closure, overclaim
    rejected even if signed, every-byte-flip, truncation/trailing, wrong-pinned-pk) +
    e2e (shred→T2 cert→offline verify; tamper fails closed exit 4; missing key fails
    closed). **DEFERRED:** the work-order's distinct "T2 = retrieval-erasure from the
    authenticated ANN/HNSW index via re-rooting" proof is NOT yet implemented — the
    shipped T2 is storage-erasure (shred + absence), not ANN-index-removal. Honesty
    (`FCC_HONESTY`): substrate deletion ≠ model unlearning (FCC-3/T3 frontier).
- **FCC-2 `[CORE/conditional]` — T3(a) DP-influence bound.** If (and only if) the model was trained
  under DP, emit a `(ε,δ)` influence-bound tier; otherwise emit `tier_achieved` unchanged with an
  explicit `T3: not-applicable (model not DP-trained)`. **Proof:** the cert never claims T3 without a
  DP training attestation input; a non-DP store produces the honest not-applicable tier.
- **FCC-3 `[FRONTIER]` — T3(b) certified-unlearning receipt.** Newton-step/retrain checkpoint hash +
  ZK proof-of-unlearning (Spartan, no trusted setup). Scale-limited for large LLMs — deliver the wire
  + verifier for small models, document the smoothness/scale gap. **Proof:** small-model unlearning
  receipt verifies; honest scale-limit statement.

## Capability 3 — TTRP: True-Top-k Retrieval Proof  *(largely already shipped — upgrade it)*
**Status note:** the completeness primitive already exists — `crates/mneme-index/src/complete_knn/`
(ball-tree pruning certs, 180-case tamper suite, CR-1..7) proves true top-k in low/moderate dim. This
capability is the **efficiency + high-dim** upgrade, not a from-scratch build.

- **TTRP-1 `[CORE]` — KZG/Merkle-HNSW constant-size proofs.** Add a KZG (or Merkle-HNSW hybrid)
  commitment so the completeness proof is constant-size (~48 B) instead of frontier-linear. **Proof:**
  proof size is O(1) in n; verifies against the committed set; tamper suite (omit/forge candidate)
  rejects. KZG trusted-setup caveat stated (or use a transparent alternative and say which).
- **TTRP-2 `[CORE]` — Honest HNSW recall@k bound.** For approximate (HNSW) search, prove **recall@k
  under the declared graph**, not absolute optimality (HNSW can miss the true NN). **Proof:** the
  claim string says "recall@k under declared graph," and a test shows the bound holds; no
  "absolute nearest neighbor" claim anywhere.

## Capability 4 — RPT: Radioactive Provenance Tracer  *(EXPERIMENTAL — statistical, not crypto)*
Giants: watermark radioactivity (Sander NeurIPS'24) + TRAK influence (Park ICML'23) + provenance DAG.
**Guarantee:** detect that a record's content propagated into a downstream model X — attribution-grade
provenance surviving exfiltration. **Identity flag:** this is a *statistical* guarantee (p-values, query
access), NOT fail-closed crypto — keep it in a clearly-labeled `experimental` feature, off by default.

- **RPT-1 `[CORE]` — Per-record watermark keyed to DAG node.** When a record is emitted into generated
  text, stamp a watermark keyed to its provenance-DAG node id. **Proof:** watermark is recoverable
  from emitted text at the keyed node; quality-delta measured and reported.
- **RPT-2 `[FRONTIER/research]` — Radioactivity detection harness.** Statistical test (p-value) that a
  downstream corpus/model trained on the watermarked text. **Proof:** demonstrate p < 1e-3 at a stated
  contamination level on a toy downstream model; state the query-access + quality-cost assumptions and
  that this is detection-with-p-value, not a hard proof.

## Capability 5 — MTL: Memory Transparency Log  *(product → infrastructure)*
Giants: Certificate Transparency + IETF SCITT (COSE signed statements + append-only log + inclusion
receipts) + C2PA + eIDAS 2.0 + A2A signed Agent Cards. **Guarantee:** a vendor-neutral, append-only,
publicly-auditable log where MNEME roots, deletion certs, and ROBRs are registered as signed statements
— the TLS-cert-transparency play for AI memory.

- **MTL-1 `[CORE]` — Single-operator SCITT-profile log.** Append-only verifiable log that ingests
  MNEME signed roots / FCC certs / ROBR certs as **COSE signed statements** and issues **inclusion
  receipts**; offline-verifiable inclusion + consistency (RFC 6962-style) proofs. **Proof:** register
  N statements → each inclusion receipt verifies; a forged/omitted entry fails the consistency proof;
  append-only violation (rollback) is detected (reuse the A-REPLAY discipline).
- **MTL-2 `[CORE]` — A2A discovery seed.** A signed Agent Card (JWS) advertising the memory-attestation
  endpoint so agents discover each other's logs. **Proof:** card verifies; tampered card rejected.
- **MTL-3 `[FRONTIER]` — eIDAS QTSP operation.** Standards/operations, not code — document the profile
  and the QTSP requirement; out of code scope.

---

## Sequencing (build cores first; frontiers are honest roadmap)
1. **ROBR-1 → ROBR-2 → ROBR-3** (the strong-mode 10X, no hardware; stands on tonight's determinism proof).
2. **FCC-1 → FCC-2** (GDPR tiered cert; T1/T2 ship now on existing shred/absence/index).
3. **MTL-1 → MTL-2** (the transparency-log rail).
4. **TTRP-1 → TTRP-2** (efficiency/high-dim upgrade of the shipped completeness primitive).
5. **RPT-1** then **RPT-2** (experimental, off by default, statistical — last, clearly labeled).

Frontiers (ROBR-4, FCC-3, MTL-3, RPT-2, TTRP KZG-setup caveat) ship as honest scaffolds with the
trust assumption + the stated gap — never as completed proofs. After each task, the watcher re-runs
the proof and the standard sweep (fmt/clippy/TCB-budget/honesty/tests/tamper/determinism/cross-impl)
before the next advances. Cross-reference: `docs/REMAINING_ITEMS.md`, `docs/TCB_MANIFEST.md`,
`docs/research/THE_EXTERNALIZED_MIND.md`.
