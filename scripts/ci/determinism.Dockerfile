# Deterministic foundation-gate image (blueprint §17.7, audit B4 — Docker simulation).
#
# This image is the build half of the Docker cross-environment determinism check
# driven by scripts/ci/determinism-two-machine.sh --docker. It compiles ONLY the
# `mneme` CLI (the foundation-gate entrypoint) from a pinned toolchain so that two
# isolated containers launched from the SAME image can each run the gate and be
# compared byte-for-byte.
#
# Honesty boundary (per docs/MNEME_SECOND_HOST.md): containers share the host
# kernel and CPU architecture, so this is a same-kernel SIMULATION that isolates
# runtime entropy / clock / hostname / PID / filesystem. It is a strong proxy for
# §17.7 cross-host independence but is NOT a two-physical-machine proof. The
# authoritative cross-host proofs remain the cross-runner CI matrix and the
# optional MNEME_SECOND_HOST SSH peer.
FROM rust:1.86.0-bookworm

# pkg-config / libssl-dev / perl are insurance for any *-sys crate that sneaks
# into the mneme-cli closure; the gate itself needs none of them at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /mneme

# The build context is a clean rsync of the working tree (target/, out/, .git/
# excluded by the driver script). Cargo.lock is present, so build --locked to pin
# the exact dependency graph and fail closed on any drift.
COPY . .

RUN cargo build -p mneme-cli --locked \
    && test -x /mneme/target/debug/mneme

# Runtime invocation is supplied by the driver (foundation-gate --out /work/out).
# Default command prints the gate help so a bare `docker run` is self-describing.
CMD ["/mneme/target/debug/mneme", "determinism", "foundation-gate", "--help"]
