# AGENTS.md

This file is for **Codex CLI / OpenAI Codex / non-Claude coding agents**
working in this repository. The canonical build/test commands, architecture
invariants, and §3 honesty boundary live in [`CLAUDE.md`](CLAUDE.md) and apply
to every agent — read that first. This file only documents **Codex-specific**
deltas that the canonical file deliberately omits (because they would not
make sense for Claude Code, and vice versa).

## Codex-specific deltas

### Tooling surface

- Codex is invoked via `codex` (OpenAI's CLI) or the in-VS Code extension.
  Unlike Claude Code, **Codex has no native MCP client** for the `mneme-mcp`
  binary. Do not add tools that route through MCP from Codex; the
  `mneme-mcp` server is designed for Claude Code / Claude Desktop.
- Codex sandboxes shell commands by default. Long-running test suites
  (`validation-lane.sh full`, `bench-recall-optional.sh`, the ≥30s fuzz
  targets) must be run with `sandbox: "danger-full-access"` or the
  workspace permission set to `["network", "filesystem-write"]` — they
  need write access to `out/`, `proof/`, and `Cargo.lock` and may write
  several hundred MB of `target/` artifacts.

### Verifier TCB and `forbid(unsafe_code)`

- `crates/mneme-verify/src/lib.rs` carries `#![forbid(unsafe_code)]`. When
  Codex's diff-suggestions touch this crate, do not let it auto-insert
  `unsafe { … }` blocks to "fix" borrow-checker complaints. The fix is
  to re-shape the safe code, not to bypass the lint. If a real
  unsafe-adjacent primitive is genuinely needed, **stop and ask the
  operator** — the existing TCB discipline is intentional.

## Why two agent files exist

`CLAUDE.md` is the **canonical, universal** guidance (build/test/invariants).
It was authored first, is the most heavily reviewed, and is the only file
the integration-owner agent reads. `AGENTS.md` is the **Codex-specific
delta** and deliberately stays slim — it references `CLAUDE.md` for
everything else so the two never drift on the load-bearing content.

If you change a build command, an architecture invariant, or a §3 honesty
string: **edit `CLAUDE.md` and mirror it into `AGENTS.md` only if the
change is Codex-specific.** The discipline is: one source of truth for
load-bearing content, one delta file per non-canonical agent.
