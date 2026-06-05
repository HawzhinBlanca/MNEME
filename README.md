# MNEME

MNEME is a verifiable compliance-of-record layer for enterprise AI. The lean
product exposes three provable guarantees:

1. **Provenance:** prove what the AI knew and why with a signed provenance chain.
2. **Read integrity:** prove read-time integrity with fail-closed verification
   and quarantine attribution.
3. **Deletion evidence:** prove record-layer deletion with crypto-shred erasure
   receipts and proof-of-absence.

The source of truth for the lean refactor is [MNEME_BLUEPRINT.md](MNEME_BLUEPRINT.md).
The current branch evidence is in [CLASSIFICATION.md](CLASSIFICATION.md),
[EXPERIMENTAL.md](EXPERIMENTAL.md), and
[LEAN_CORE_READINESS.md](LEAN_CORE_READINESS.md).

## Honesty Boundary

Authenticated memory is not truth. MNEME proves integrity, provenance,
authorization, and deletion of the memory-and-record layer. Model-side
parametric residue is statistical attestation only, never cryptographic
deletion.

Verifiable retrieval proves procedure-faithfulness over committed,
untampered data. Semantic/ANN/ZK retrieval work is experimental and must not be
described as exact nearest-neighbor proof or semantic truth.

## Public Product API

The lean public API is the MCP four-call surface:

- `record-with-provenance`
- `recall-with-signed-chain`
- `erase-with-receipt-and-proof-of-absence`
- `verify`

The MCP erase call returns a verified `ForgetProof` erasure receipt plus an SMT
absence proof. CLI `audit`, `init`, and `determinism` are operator-only behind
`mneme-cli/operator_tools`, not public product API.

## Experimental Areas

The following areas are roadmap and default-off:

- Semantic/ANN retrieval and semantic verifier paths.
- Cognition certificates and Context Gate/TEE work.
- Attestation export/parser work.
- External `ActionReceipt` accountability.
- Chameleon-hash redaction.
- CRDT sync, daemon transports, federation/A2A.
- ZK/privacy retrieval and PIOP research.
- Bench/test helper surfaces.

See [EXPERIMENTAL.md](EXPERIMENTAL.md) for exact paths and feature flags.

## Validation Ladder

```bash
scripts/ci/validation-lane.sh quick
scripts/ci/validation-lane.sh tamper
scripts/ci/validation-lane.sh determinism
scripts/ci/validation-lane.sh full
```

`validation-lane.sh full` is a local correctness ladder. It does not prove a
real second physical host unless `MNEME_SECOND_HOST=user@host` is supplied to
the two-machine determinism script. Strict cross-host mode fails closed without
that peer.

Run the 1M fsync-on performance lane explicitly:

```bash
MNEME_BENCH_SCALE=1000000 \
MNEME_BENCH_SAMPLES=2000 \
MNEME_BENCH_WRITE_SAMPLES=200 \
scripts/ci/bench-recall-optional.sh
```

## Current Lean Status

Top-line status is recorded in [LEAN_CORE_READINESS.md](LEAN_CORE_READINESS.md).
Do not declare `LEAN` unless all of these are true:

- The trusted verifier surface shrank.
- Core forgery/tamper/soak/perf gates pass from a clean checkout.
- Golden determinism digests match on two physical hosts.
- The anti-fake audit has zero core findings.
- No public claim exceeds the honesty boundary above.

No CUT candidate may be deleted until [CLASSIFICATION.md](CLASSIFICATION.md) is
reviewed.
