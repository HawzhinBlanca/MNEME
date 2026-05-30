# MNEME end-to-end tests

## UI (Playwright) — not applicable yet

The [MNEME blueprint](../MNEME_BLUEPRINT.md) v1 adoption surface is **`mneme-cli`** (§14.2) and **`mneme-mcp`** (§14.1). There is no web UI or terminal UI (TUI) in scope for v0.

Browser E2E is scaffolded under `e2e/ui/` and runs only when you set:

```bash
export MNEME_UI_BASE_URL=https://your-dashboard.example
npm run test:e2e:ui
```

Until then, Playwright specs are skipped with an explicit reason (not fantasy green tests).

### Planned UI scenarios (when a dashboard exists)

| Journey | Blueprint ref |
|--------|----------------|
| Onboarding / store open | §7 `Store::open`, fail-closed |
| Search / recall with min tier | §14.1 `memory.recall`, §13.4 tiers |
| Remember + quarantine tier | §14.1 `memory.remember` |
| Forget + prove absent | §9.5, §13.2 |
| Settings / trust & capabilities | §12 capabilities |

### Artifacts on failure

- Screenshots / video / trace: `e2e/test-results/`
- HTML report: `playwright-report/` (after `npx playwright show-report`)

## CLI integration (active)

Critical CLI journeys are covered in:

- **Rust:** `crates/mneme-cli/tests/cli_e2e.rs` (`cargo test -p mneme-cli`)
- **Node smoke:** `e2e/cli/*.test.mjs` (invokes built `mneme` binary)

### Run commands

```bash
# Store kernel e2e (blueprint §19 v0 + §21)
cargo test -p mneme-store --test e2e

# Rust CLI e2e
cargo test -p mneme-cli --test cli_e2e

# Build CLI + full npm harness (CLI + opt-in UI)
cargo build -p mneme-cli
npm install
npm run playwright:install   # first time only
npm run test:e2e
```

Default `MNEME_BIN` in Node tests: `target/debug/mneme` after `cargo build -p mneme-cli`.

### Exit codes (CLI contract)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Usage / missing paths |
| 3 | Store kernel not wired (fail-closed until `mneme-store` lands) |
