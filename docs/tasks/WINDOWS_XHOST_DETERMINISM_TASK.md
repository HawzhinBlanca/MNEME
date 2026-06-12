# Agent Task — Cross-Host Determinism Proof (MNEME, Windows/x86_64 peer)

You are an autonomous coding agent running on a **Windows x86_64 machine**. Your job is to
independently reproduce MNEME's deterministic "foundation gate" and confirm it produces
**byte-identical** digests to a reference machine (Apple Silicon / arm64). A match proves
**cross-host, cross-arch determinism** of the verifiable-memory substrate — a load-bearing
property: two independent machines, two CPU architectures, two operating systems, computing the
*same* signed-memory digests bit-for-bit. Work autonomously; only stop to ask the human if a step
needs a credential or an interactive installer you cannot complete headlessly.

## What you are proving
MNEME's `mneme determinism foundation-gate` builds a fixture memory store twice and emits five
cryptographic digests over fixed inputs (no host/path/OS/clock data enters them by design). If your
five digests equal the reference below, determinism holds across the host/arch boundary.

## Reference digests — target to match (built on macOS/arm64, tag `v0.7.0`, commit `3fedc80f`)
```
absent_proof_digest_hex = b479944e1b1c76a1628c4d8a6f3544fb690882124aeee3cf2ca2db91f5db1d88
head_bytes_hex          = a90101025820e974b1934370338f4d561b55ab342a53df861354b4f48cb41da1689b6730d54f03582079150dc4f251b743d90929601fcb151ffb7143cd07fc4b8ea12a7653b0a75ca8045820cb84a95c083ee6df82d254c80049162e89988f0ef8ff84581b04a17af6159099054e0400000000000000000000000101065820b59c4c5525ed34877cf19dc117e2abf553fbcfe7e26525ca47040be71cd13886075820c2b9dbfda40b466168599a18393b4b8e441b5deced15b1424f0ef303bef9837f0858409ce0ae1bf037c8199f0350bb888608c054ca5eccfe173ad524da132a4ad25189db93f69d1a5421bd013aa615eb2c972a9916aaaf8b245303cc279508a41ec1070905
receipt_digest_hex      = aebbb7c86000ce2977f0832b4a4bcfcfea92279fb21324fe9a71b5a9fa743355
root_preimage_hex       = c2b9dbfda40b466168599a18393b4b8e441b5deced15b1424f0ef303bef9837f
semantic_digest_hex     = cb84a95c083ee6df82d254c80049162e89988f0ef8ff84581b04a17af6159099
```

## Hard requirements (do not deviate — they change the digests)
- **Exact commit:** check out tag **`v0.7.0`** (`git checkout v0.7.0`). Confirm `git rev-parse HEAD`
  begins `3fedc80f`. Do not build any other commit.
- **Exact toolchain:** Rust **1.86.0** (the repo pins it in `rust-toolchain.toml`; `rustup` will
  honor it automatically — do not override).
- **Exact command:** `cargo run -q -p mneme-cli -- determinism foundation-gate --out <dir> --timestamp 1970-01-01T00:00:00Z`.
- Do **not** set `MNEME_NO_FSYNC` (directory fsync is correctly a no-op on Windows).

## Steps

1. **Detect environment.** Check whether `rustc`, `git`, and a working C linker exist:
   `rustc --version`, `git --version`, and (native MSVC) `where link.exe` or (GNU) `where gcc`.
   Pick the lowest-friction working path:
   - **Path A — WSL (preferred on a fresh box):** if WSL/Ubuntu is available (`wsl -l -q`), run the
     whole proof inside Ubuntu — standard Linux rustup, no Visual Studio needed. WSL-on-x86_64
     yields the same OS-independent digests, so it still proves arm64-vs-x86_64.
   - **Path B — native Windows MSVC:** requires Visual Studio C++ Build Tools (the MSVC linker).
   Choose A if WSL is present or you can `wsl --install` non-interactively; otherwise B.

2. **Install toolchain (if missing).**
   - WSL/Ubuntu: `sudo apt-get update && sudo apt-get install -y build-essential git curl python3`,
     then `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.86.0`
     and `source "$HOME/.cargo/env"`.
   - Native Windows: install `Rustlang.Rustup`, `Git.Git`, and
     `Microsoft.VisualStudio.2022.BuildTools` with the **"Desktop development with C++"** workload
     (winget). If the VS Build Tools installer is interactive and you cannot complete it headlessly,
     **stop and tell the human exactly what to click**, then resume.

3. **Get the source at the pinned tag.**
   `git clone https://github.com/HawzhinBlanca/MNEME.git`, `cd MNEME`, `git fetch --tags`,
   `git checkout v0.7.0`. Verify `git rev-parse HEAD` starts with `3fedc80f` — if not, abort and report.

4. **Build + run the gate.** From the repo root:
   `cargo run -q -p mneme-cli -- determinism foundation-gate --out out/xhost --timestamp 1970-01-01T00:00:00Z`
   (first build may take several minutes). Then also run `foundation-verify` to confirm internal
   consistency: `cargo run -q -p mneme-cli -- determinism foundation-verify out/xhost/foundation.report.json --output out/xhost/foundation.verify.json` and confirm it reports `verified: true`.

5. **Extract your five digests.**
   - WSL/Linux: `python3 -c "import json;d=json.load(open('out/xhost/foundation.report.json'))['run_a'];[print(f'{k} = {d[k]}') for k in sorted(d)]"`
   - Native Windows: `(Get-Content out\xhost\foundation.report.json | ConvertFrom-Json).run_a | Format-List`

6. **Self-verify field-by-field.** Compare each of your five digests to the reference above.
   Also confirm `foundation.report.json` shows `run_a == run_b` (the gate's own twice-built check).

## Report back (exactly this, fail-closed and honest)
- Which path you used (A/B), the OS/arch (`uname -a` or `systeminfo`), `rustc --version`,
  and `git rev-parse HEAD`.
- Your five digests, verbatim.
- A per-field verdict table: each field `MATCH` or `MISMATCH` vs the reference.
- The overall result: **`CROSS-HOST DETERMINISM: PROVEN`** only if all five match exactly and
  `foundation-verify` returned `verified: true`; otherwise **`MISMATCH`** with the differing
  fields and any deviation you had to make (toolchain version, build path, etc.).
- If anything blocked you (interactive installer, missing linker, network), say so plainly — do not
  fabricate a result. A wrong digest is a real finding, not a failure to hide.

## Stretch goal (only after the above is PROVEN)
Report whether the repo contains `scripts/ci/convergence-two-host.sh` (CRDT object-set convergence
across hosts). If present, note its usage; the human will sequence the convergence proof next. Do
not attempt it unless asked.
