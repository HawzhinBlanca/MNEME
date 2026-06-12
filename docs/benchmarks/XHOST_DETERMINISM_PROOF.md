# Cross-Host / Cross-OS / Cross-Arch Determinism Proof (§17.7)

**Result: BYTE-IDENTICAL across macOS/arm64 ↔ Windows/x86_64.**

This is the strict §17.7 cross-physical-host determinism proof — and it is stronger than
the blueprint requires: it crosses **three** axes at once (two physical hosts, two
operating systems, two CPU architectures), not just the host axis.

## Why this is sound (not transport theater)

The cross-host proof does **not** depend on any network transport. The foundation-gate
emits a `RunDigest` of five values, each a cryptographic digest over canonical dCBOR with
explicit little-endian integer encoding, computed from entirely fixed inputs (fixed
operator seed, deterministic fixture crypto, fixed bodies/session, fixed `--timestamp`,
no embeddings). **No path, hostname, OS string, wall-clock, or mtime enters any digested
value** (verified by reading `crates/mneme-cli/src/determinism.rs`: the digest is over
`roots/HEAD` bytes, `root.preimage_hash`, a BLAKE3 of the receipt fields, the absent-proof
digest, and `root.semantic_commit`). So two independent machines that build the same commit
and run the gate locally MUST produce identical digests — and a hand-compared match is
*more* convincing than an SSH-automated one, because execution is manifestly independent.

## Evidence (commit `df5997a`)

| Host A | Host B |
|---|---|
| macOS 25.5.0, **arm64** (Apple Silicon) | Windows 11 Pro, **x86_64** (MSVC, Rust 1.86.0) |

Both ran:

```
cargo run -q -p mneme-cli --features operator_tools -- determinism foundation-gate \
  --out <out> --timestamp '1970-01-01T00:00:00Z'
```

`run_a` digests — **identical on both hosts**:

| Field | Value |
|---|---|
| `root_preimage_hex` | `c2b9dbfda40b466168599a18393b4b8e441b5deced15b1424f0ef303bef9837f` |
| `receipt_digest_hex` | `aebbb7c86000ce2977f0832b4a4bcfcfea92279fb21324fe9a71b5a9fa743355` |
| `absent_proof_digest_hex` | `b479944e1b1c76a1628c4d8a6f3544fb690882124aeee3cf2ca2db91f5db1d88` |
| `semantic_digest_hex` | `cb84a95c083ee6df82d254c80049162e89988f0ef8ff84581b04a17af6159099` |
| `head_bytes_hex` | `a90101025820e974b1934370338f4d561b55ab342a53df861354b4f48cb41da1689b6730d54f0…07fc4b8ea12a7653b0a75ca8…0905` (full value matched byte-for-byte) |

**5 / 5 fields byte-identical.**

## Reproduce it

On each host (same commit), run `scripts/ci/xhost-determinism-compare.sh` to print the five
digests, then compare across hosts. The CI `determinism-cross-runner.yml` already proves the
ubuntu↔macos axis on GitHub hardware; this manual proof adds the Windows/x86 axis.

## Windows portability fix discovered during this proof

The Windows run initially failed with `Access is denied` on `meta/` because
`atomic.rs::sync_parent_dir` fsync'd the parent directory — a **Unix** durability primitive
(make a `rename` crash-durable) that Windows neither supports (a directory handle cannot be
`sync_all`'d) nor needs (NTFS uses the file's own `FlushFileBuffers` + transactional
rename). Fixed by gating directory fsync to `#[cfg(unix)]`; Windows keeps full *file*-level
durability (`sync_all` is never disabled), so the crash-unsafe `MNEME_NO_FSYNC` escape hatch
is **not** required on Windows. The digests above are unaffected — directory fsync is a
durability detail, not an input to any signed value (verified: Unix determinism remained
byte-identical after the fix).

## Honesty boundary

This proves *procedure-faithful, platform-independent reproduction of the signed root*. It
does not weaken the standing limits: authenticated ≠ true; verifiable retrieval proves
procedure-faithfulness, not exact nearest neighbors. Phase I `ExactDominance`
proves membership/completeness plus top-k over prover-asserted distances; true top-k ranking is not proven
and it is not top-k by true query-to-embedding distance
until verifiers recompute candidate distances.
