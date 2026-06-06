# MNEME — Human Tasks

Items that need a human decision, external infrastructure, or an outward-facing
action I should not take unilaterally. The autonomous hardening loop appends
here whenever it hits something it cannot finish on its own.

Status legend: ☐ open · ☑ done · ⏳ in progress (human)

## Decisions / approvals

- ☐ **Merge PR #9** (`codex/lean-core-classification`). Fully green CI, mergeable;
  meets all 5 README LEAN conditions. Awaiting your review + merge.
- ☑ **CUT-candidate deletions** (resolved 2026-06-06 on "do all"): deleted the two
  genuinely-dead ones (`piop-research.rs` + its `piop_research` feature;
  `scripts/piop-flat-prototype`); **kept** `crypto-fault-injection-smoke.sh`
  (active crypto-lane gate) and `cognition_cert_v1.rs` (a real test) — cutting
  those would reduce coverage. See CLASSIFICATION.md / EXPERIMENTAL.md.
- ☑ **`mneme-crossref` classification** → kept **DEFER** (assurance, not runtime TCB).
- ☑ **Deletion-propagation scope for v1** → **single-store signed lineage**;
  multi-peer CRDT propagation stays DEFER.

## Infrastructure (optional, beyond what CI already proves)

- ☐ **Bare-metal SSH determinism peer** — CI cross-runner (`gh-ubuntu` vs
  `gh-macos`) already proves two-physical-host determinism. A dedicated
  `MNEME_SECOND_HOST=user@host` SSH peer would add an ops-controlled proof if you
  want one; needs a reachable second box + SSH key.
- ☐ **Sustained soak / large-disk perf box** — the 1M fsync 200-sample run now
  fits easily (~6 GiB after the write-amp fix). A long-running soak (hours/days,
  big disk) for endurance numbers would need a dedicated machine.

## Design decisions (policy, not pure engineering)

- ☐ **Checkpoint ledger (`roots/`) growth.** One small signed file per commit,
  unbounded (the audit + replay-floor ledger). The replay-floor *scan* is now
  O(1) in crypto (HARDENING.md 2026-06-06), but per-commit I/O + the inode count
  remain O(commits) at very large scale. Decide whether v1 prunes/packs old
  checkpoints (faster open, smaller disk) or keeps the full ledger for audit.
  My lean default: keep the full ledger for v1; revisit if a deployment shows
  open latency from inode load.

## CI coverage gaps (low priority)

- ☑ **Clippy coverage widened** (2026-06-06): `validation-lane quick` now lints
  `mneme-account`, `mneme-mcp` (lib+tests) and `mneme-cli` (bins+tests) in
  addition to wave-0/1 + store/verify. Fixed the latent lints this surfaced
  (`mneme-account` needless_return earlier; 3 const-`assert!` sentinels in
  phase_ii/iii test files now use `black_box`).
- ☐ **`mnemed` clippy** still not in the CI clippy lane — it could not be verified
  locally (its build script needs `protoc`, and Docker was unavailable mid-pass).
  Add `-p mnemed` to the quick-lane clippy once verified (CI runners have protoc).

## Notes for review

- ☐ **Node.js 20 action deprecation** in workflows (`actions/checkout@v4`,
  `upload/download-artifact@v4`). GitHub forces Node 24 from 2026-06-16. I can
  bump these action versions myself in a future hour unless you'd rather pin —
  flagging because it touches CI config. (Tracked for autonomous handling.)
