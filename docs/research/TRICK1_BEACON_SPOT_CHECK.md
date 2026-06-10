# Trick #1 — Probabilistically-Checkable Retrieval (Beacon Spot-Check Prototype)

**Status:** Prototype in `mneme-index` (`beacon_spot_check`, cognition cert field 7).  
**Date:** 2026-06-11.

## Idea

Bind a public [drand v2](https://drand.love/docs/http-api/) beacon into each cognition
certificate. A deterministic lottery over that beacon selects a fraction of recalls for
**spot-check audit**. Audited calls upgrade verification obligations; non-audited calls
keep the Phase I procedure-faithful label.

This is **statistical deterrence**, not a per-call ZK proof.

## Wire (cognition certificate v1 / v2 draft)

Optional map field **7** (`audit_beacon`), dCBOR map:

| Field | Type | Meaning |
|-------|------|---------|
| 1 | `u64` | drand round number |
| 2 | bytes (32) | drand `randomness` (SHA-256 of BLS signature) |
| 3 | bytes (32) | `audit_beacon_binding_digest(round, randomness, receipt.digest())` |

Binding domain tag: `MNEME-AUDIT-BEACON-BIND-v1`.

Certificates **without** field 7 verify exactly as before (fail-closed unchanged).

## Verification paths

### Offline (default)

1. Decode optional `audit_beacon`.
2. Recompute binding digest over embedded `receipt.digest()`; reject on mismatch.
3. Derive lottery ticket from `MNEME-AUDIT-LOTTERY-v1 ‖ randomness ‖ binding_digest`.
4. If not selected → return (procedure-faithful path only).
5. If selected → require `ExactDominance` wire level; optional embedding-backed
   `verify_spot_check_exact_nn` when the verifier holds query + candidate embeddings.

### Online (optional `beacon_online` feature)

Fetch `GET https://api.drand.sh/v2/beacons/{chain_hash}/rounds/{round}` for quicknet
(`chain_hash = 52db9ba70e0cc95f407f896a1a2089b94999e381114878045d418bd5422e8305`)
and require JSON `randomness` equals carried bytes after offline binding check.

BLS signature verification against drand group public key is **not** required for the
prototype when randomness is carried + online-fetched; full BLS verify is a future hardening step.

## Honesty boundary

Exported as `BEACON_SPOT_CHECK_HONESTY`:

- Non-audited calls: procedure-faithful, top-k over prover-asserted distances.
- Audited calls only: lottery-enforced exact-NN when embeddings are available to the verifier.
- Never semantic truth; not a SNARK; not zero-knowledge.

## Relation to `commitment_binding`

`commitment_binding` (BLAKE3 envelope) binds a single leaf commitment. Beacon spot-check
binds **public randomness into the whole receipt/cert domain** for audit lottery — complementary,
not a replacement.

## Default lottery rate

`DEFAULT_AUDIT_RATE_PPM = 100_000` (10% of beacon-bound certificates).
