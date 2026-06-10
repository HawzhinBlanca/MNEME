# Security Policy

We take the security and integrity of MNEME extremely seriously. As a verifiable memory substrate for AI agents, correctness and resistance to tampering, replay, and information leakage are core tenets of our architecture.

This document outlines our security disclosure process and supported versions.

## Supported Versions

Only the following versions of MNEME receive security updates:

| Version | Supported | Notes |
|---|---|---|
| v0.5.x | Yes | Current active development branch |
| < v0.5.0 | No | Legacy prototypes / Phase I developer previews |

## Reporting a Vulnerability

If you discover a security vulnerability in MNEME, please **do not report it publicly** via GitHub issues, PRs, or public chat. Instead, report it privately through one of the following channels:

* **Security Email:** security@mneme.io
* **Encrypted Report:** For sensitive findings, please encrypt your email using our PGP public key (located at `docs/security_key.asc` or fetched from standard keyservers using fingerprint `F89E D07E D5E6 DA0D 1083 4872 739F 2F9B 0500 5EED`).

### What to Include in a Report

To help us triage and resolve your report quickly, please include:
1. **Description:** A detailed explanation of the vulnerability and its potential impact.
2. **Steps to Reproduce:** Clear, step-by-step instructions or a minimal reproducible example (PoC script/code).
3. **Environment:** OS, architecture, Rust compiler version, and any specific configurations used.
4. **Proposed Fix:** (Optional) If you have a fix or mitigation suggestion, please include it.

## Coordinated Disclosure Process

We follow industry-standard Coordinated Vulnerability Disclosure (CVD) principles:

1. **Acknowledgment:** We will acknowledge receipt of your report within **48 hours**.
2. **Triage & Validation:** We will investigate the issue and verify if it is reproducible. We will update you on our findings.
3. **Remediation:** We will work on a fix. If needed, we may coordinate with you to test the pre-release patch.
4. **Advisory & Release:** A security advisory will be published along with a new release containing the fix. We aim to resolve all validated reports within **90 days** of receipt.
5. **Credit:** Unless you request otherwise, we will gladly credit you in our security advisory and release notes for your responsible disclosure.

## Out of Scope

The following are considered out of scope for security vulnerabilities:
* Mismatches in semantic retrieval rankings (e.g., HNSW returning a non-optimal nearest-neighbor) unless it constitutes a complete bypass of the verification gate or triggers a denial-of-service panic inside the budgeted TCB.
* Disagreements on the truth of signed memory entries (as documented in our Honesty Boundary: *authenticated ≠ true*).
* Performance or denial of service issues triggered by sending excessively large inputs when outside the rate-limiting and buffer boundary limits.
