# MNEME — Human Tasks

Items that need a human decision, external infrastructure, or an outward-facing
action I should not take unilaterally. The autonomous hardening loop appends
here whenever it hits something it cannot finish on its own.

Status legend: ☐ open · ☑ done · ⏳ in progress (human)

## Decisions / approvals

- ☐ **Merge PR #9** (`codex/lean-core-classification`). Fully green CI, mergeable;
  meets all 5 README LEAN conditions. Awaiting your review + merge.
- ☐ **Approve CUT-candidate deletions** (none deleted yet, per the review rule):
  `experimental/research/mneme-index-piop-research.rs`,
  `scripts/piop-flat-prototype`,
  `scripts/ci/crypto-fault-injection-smoke.sh` scaffold,
  fixture-dump helpers under `experimental/cognition-cert`.
- ☐ **`mneme-crossref` classification** — keep DEFER (assurance) or promote to
  CORE? (My recommendation: keep DEFER.)
- ☐ **Deletion-propagation scope for v1** — single-store signed lineage (current)
  vs multi-peer CRDT propagation. (My recommendation: single-store for v1.)

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

## Notes for review

- ☐ **Node.js 20 action deprecation** in workflows (`actions/checkout@v4`,
  `upload/download-artifact@v4`). GitHub forces Node 24 from 2026-06-16. I can
  bump these action versions myself in a future hour unless you'd rather pin —
  flagging because it touches CI config. (Tracked for autonomous handling.)
