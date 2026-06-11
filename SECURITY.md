# Security Policy

MNEME is a verifiable memory substrate for AI agents. Correctness, tamper resistance,
and fail-closed verification are core design goals — not optional hardening.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `master` (pre-release) | Yes | Active development; run `scripts/ci/validation-lane.sh quick` before reporting |
| Tagged releases | Yes | Only the latest tagged release receives backports |

## Reporting a vulnerability

**Do not** open public GitHub issues, pull requests, or chat threads for
security-sensitive findings.

Report privately via [GitHub Security Advisories](https://github.com/HawzhinBlanca/MNEME/security/advisories/new)
for this repository, or contact the repository maintainers through a private channel
they have published for your deployment.

Include:

1. A clear description of the vulnerability and plausible impact.
2. Steps to reproduce (minimal PoC preferred).
3. Environment: OS, architecture, Rust toolchain (`rust-toolchain.toml`), and relevant config.
4. Optional: suggested fix or mitigation.

## Coordinated disclosure

1. **Acknowledgment** — we aim to acknowledge receipt within 48 hours.
2. **Triage** — we reproduce and classify severity.
3. **Fix** — we prepare a patch; pre-release testing may involve the reporter.
4. **Advisory** — we publish an advisory with the fix release when ready.
5. **Credit** — reporters are credited unless they request anonymity.

## Out of scope

The following are documented product limits, not verifier bypasses:

- **Semantic truth.** Signed entries verify even when content is false (*authenticated ≠ true*).
- **Exact nearest neighbors.** Verifiable retrieval proves procedure-faithfulness over committed
  geometry, not that returned items are the true top-k by query-to-embedding distance.
- **Non-optimal ANN rankings** unless they bypass the verification gate or panic inside the
  budgeted TCB (`mneme-verify`, ≤500 lines).
- **Denial of service** from inputs outside documented size/rate limits when those limits are
  enforced at the API boundary.

See `README.md` (Honesty boundary) and `docs/TCB_MANIFEST.md` for the full §3 disposition.
