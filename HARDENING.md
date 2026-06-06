# MNEME — Hardening Log

Autonomous, hourly reliability/hardening pass. Each entry: what was audited or
improved, the evidence, and follow-ups. Human-needed items go to
[HUMAN_TASKS.md](HUMAN_TASKS.md).

## 2026-06-06 — Panic-surface audit + provenance fail-closed

**Audit (verified, no fix needed):** swept production (non-test) code in the TCB
and kernel crates for panic surfaces (`unwrap`/`expect`/`panic!`/`unreachable!`/
slice-index) on untrusted-input paths:

- `mneme-verify` (TCB): **0** — panic-free.
- `mneme-store`, `mneme-root`, `mneme-crypto`: **0**.
- Untrusted-input parsers all guard before indexing:
  - `dcbor.rs`: `read_bytes(n)` returns exactly `n` bytes or errors; map-key
    slice uses forward-only cursor positions (proven in-range); length reads are
    minimal-form checked.
  - `hex.rs::decode_hex32`: length `== 64` checked, `chunks_exact(2)`.
  - `smt/wire.rs::parse_proof_blob`: `is_empty()` checked before `bytes[0]`.
  - `cap/wire.rs`, `smt/wire.rs`: use bounded `read_exact::<N>` → fixed arrays.

  Conclusion: the verifier/parse attack surface is fail-closed on malformed
  input (consistent with the existing fuzz targets). No bug found.

**Fix (defense in depth):** `mneme-dag` topological sort
(`crates/mneme-dag/src/lib.rs`) used `.expect("id present")`,
`.expect("child tracked")`, and an unchecked `*deg -= 1`. Unreachable for
validated input (duplicate-id / dangling-parent / cycle are already rejected
with `ProvenanceBroken`), but a CORE provenance path must be *provably*
panic-free, and `-= 1` could underflow-panic in debug builds. Converted all
three to fail-closed `Result` (`ok_or(MnemeError::ProvenanceBroken)?`,
`checked_sub`). Evidence: `cargo clippy -p mneme-dag --lib --tests -D warnings`
clean; `cargo test -p mneme-dag` 15 passed.

**Follow-ups:** none blocking. `mneme-dag::sequence()` keeps an infallible
`u64::try_from(usize).expect(...)` (cannot fail on supported targets); left as-is
to avoid a needless signature change.

## 2026-06-06 — Real bug: panic-on-corruption in sidecar hex decode (fail-closed)

**Found + fixed (genuine latent panic bug).** `mneme-store/src/layout.rs::parse_hex32`
validated only the *byte* length (`s.len() == 64`) then sliced the `&str` by
byte range (`&s[i*2..i*2+2]`). A corrupted/tampered sidecar packing 64 bytes of
multibyte UTF-8 (e.g. `"€"` + 61 ASCII == 64 bytes, not 64 chars) makes that
slice land on a non-char boundary → **panic**, not a typed error. `parse_hex32`
decodes 10 untrusted on-disk sidecar fields (key-index, object-keys, tombstones,
embeddings), so a single bad byte on disk could crash store open/recall — a
fail-closed violation.

Reproduced the panic (`byte index 2 is not a char boundary`). Fixed by
delegating to the canonical byte-safe `mneme_core::decode_hex32` (already
hardened + tested for this exact multibyte case), which also removes the
duplicated decoder. Added 3 regression tests in `layout.rs` (multibyte→
`SchemaDrift` without panic, lowercase roundtrip, wrong-length reject).

Evidence: `clippy -p mneme-store --lib --tests -D warnings` clean; new tests
pass; `validation-lane determinism` OK with pinned digests
`25e3…/e14b…/b479…` unchanged (decode is byte-identical for valid hex).

## 2026-06-06 — Same-class slice sweep (clean) + Node 20→24 CI action bump

**Sweep (verified clean).** After the hour-2 `&str`-byte-slice panic, swept the
whole workspace for the same bug class: `&s[a..b]` / `s.get(a..b)` / `split_at`
on untrusted input. Every other site is guarded:
- `layout.rs:184/206` `&hex[..2]` — `hex` is always `hex_encode(id)` (64 ASCII
  chars), never untrusted.
- `mneme-index-wire.rs` `&bytes[1..]` / `&input[pos..]` — `is_empty()` /
  `pos >= len` guards (the fuzz-hardened "never panics" parsers).
- `mneme-store-merge.rs` `split_at(NONCE_LEN)` — `len() < NONCE_LEN` guard.
- `pedersen-schnorr-zk.rs` `proof_bytes[0..64]` — `len() != PROOF_LEN` guard.
- `mneme-smt/tree.rs` slice is on fixed 32-byte arrays (depth-bounded).

Conclusion: the hour-2 bug was an isolated outlier; slicing discipline is
otherwise sound. No code change.

**Node 20→24 action bump.** GitHub forces node24 on JS actions 2026-06-16,
which would break the node20-pinned actions powering CI (incl. the
two-physical-host determinism pipeline). Verified the first node24 major for
each via `gh api` (v5 of the artifact actions is still node20) and bumped:
`actions/checkout@v4→v5`, `actions/setup-node@v4→v5`,
`actions/upload-artifact@v4→v6`, `actions/download-artifact@v4→v7`. Pure 1:1
`uses:` version swaps across 6 workflows (27/27). The upload@v6→download@v7 path
in the determinism compare job is the only behavioural risk — validated
empirically by CI (cross-runner `compare digests` must stay green). `rust-cache@v2`
left as-is (third-party, not in GitHub's deprecation notice).

## 2026-06-06 — Bound unbounded sidecar journals (on-open compaction)

**Found + fixed (scalability/reliability).** Store `open`
(`open_pinned_with_vault`) replays the per-sidecar append-only journals
(`key_index` / `object_keys` / `embeddings`) into memory but never truncated
them afterward. Single-entry `remember`/`forget` only *append* to those journals
(full `persist_*` that truncates them runs only on batch/rekey), so a long-lived
single-write store — the common agent-memory case — grew the journals
O(total writes) and replayed the whole journal on every cold open (O(writes)
startup). Less severe than the fixed 46 GB snapshot, but real.

Fix: `layout::compact_oversized_sidecars` runs once on open and folds any journal
that has outgrown its base snapshot back in, via the existing crash-safe
`persist_*` path (atomic base write then journal drop; replay is idempotent so a
crash in between re-applies the same state). Threshold-gated
(`JOURNAL_COMPACT_FLOOR_BYTES = 256 KiB`, overridable via
`MNEME_JOURNAL_COMPACT_FLOOR_BYTES`) so small/short-lived stores never pay an
O(N) rewrite on open. Digest-neutral: the signed root derives from the in-memory
index roots, not sidecar bytes.

Evidence: clippy `-D warnings` clean; new `journal_outgrew_base` unit test +
existing layout tests pass; e2e 39, tamper 2, chaos 2 (crash/corruption soak,
exercises the open path), determinism OK with pinned digests `25e3…/e14b…/b479…`
unchanged.

## 2026-06-06 — Replay-floor scan: O(commits) → O(1) verifications per open

**Found + optimized (perf, security-critical path).** `mneme-root::
max_signed_checkpoint` runs on every store open (A-REPLAY / INV-6 replay floor)
and read + dcbor-parsed + **Ed25519-verified every** `roots/<seq>.root.cbor` to
find the max validly-signed sequence. `roots/` grows one file per commit, so
open was O(commits) with a signature verification per checkpoint (~1M verifies ≈
50 s at 1M commits — the dominant cost).

Optimization: still read + parse every checkpoint so I/O errors propagate exactly
as before (an *unreadable* max checkpoint must fail closed, else an attacker
could lower the replay floor by hiding it), but defer the expensive Ed25519 check
to a **descending-by-seq scan that stops at the first valid checkpoint** — which
is the max signed sequence. Behaviorally identical (same max, same hlc, same
skip/propagate rules); only the verification *count* drops from O(commits) to
O(1) in the common case.

Evidence: clippy `-D warnings` clean; `mneme-root` 11+ tests incl `check_replay`;
`validation-lane tamper` OK (`tamper_root_hlc_replay` + A-REPLAY forgery cases);
chaos soak 2 (stale/forged-root replay detection); determinism OK, pinned digests
`25e3…/e14b…/b479…` unchanged.

**Design follow-up (human):** `roots/` itself still grows one small file per
commit (the audit/replay ledger). Per-commit I/O+parse on open remains O(commits)
even with O(1) crypto; at very large commit counts the 1-file-per-commit inode
load is the next ceiling. Whether/how to prune or pack the ledger is a policy
decision — logged to HUMAN_TASKS.md.

## 2026-06-06 — Add dependency-CVE scanning (RustSec) to CI

**Gap closed (supply-chain security).** The repo had no dependency-vulnerability
scanning. Added `.github/workflows/security-audit.yml`: `cargo audit` against the
RustSec advisory DB on every dependency change and weekly (to catch
newly-published advisories against an unchanged lockfile). The job uses the
stable toolchain only for the tool (cargo-audit parses `Cargo.lock`, never builds
the workspace, so the 1.86.0 build pin is unaffected) with `--locked`.

Verified the current lockfile is clean before adding the gate: ran cargo-audit in
a `rust:latest` container (the 1.86.0 local toolchain can't compile cargo-audit —
its deps need rustc ≥1.89) — loaded 1120 advisories, scanned 341 dependencies,
**0 vulnerabilities** (exit 0). So the new CI check passes on PR #9.

Note: cargo-audit is not locally runnable under the project's pinned 1.86.0
toolchain; use `docker run --rm -v "$PWD/Cargo.lock:/work/Cargo.lock:ro" \
rust:latest sh -c 'cargo install cargo-audit --locked && cargo audit --file \
/work/Cargo.lock'` to reproduce locally.
