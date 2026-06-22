#!/usr/bin/env bash
# Build the mneme-verify-wasm browser auditor and run its Node verification test.
#
# Compiles the offline-verify path to wasm32, generates wasm-bindgen bindings for
# both Node (test) and web (Desk), and runs the Node test that verifies a real
# receipt and asserts fail-closed on tamper / wrong-key / garbage.
#
# NOTE: `cargo install wasm-bindgen-cli` is blocked on Rust 1.86 (a transitive
# `time` crate requires rustc >= 1.88), so this fetches the OFFICIAL PREBUILT
# wasm-bindgen binary matching the crate's wasm-bindgen version. A clean run
# prints "wasm-auditor: OK".
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VER="0.2.122"   # must match the wasm-bindgen dependency in mneme-verify-wasm/Cargo.toml

echo "wasm-auditor: ensure wasm32 target"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

echo "wasm-auditor: ensure prebuilt wasm-bindgen $VER"
WB="$(command -v wasm-bindgen || true)"
if [ -z "$WB" ] || ! "$WB" --version 2>/dev/null | grep -q "$VER"; then
  OS="$(uname -s)"; ARCH="$(uname -m)"
  case "$OS-$ARCH" in
    Darwin-arm64)   TRIPLE=aarch64-apple-darwin ;;
    Darwin-x86_64)  TRIPLE=x86_64-apple-darwin ;;
    Linux-x86_64)   TRIPLE=x86_64-unknown-linux-musl ;;
    Linux-aarch64)  TRIPLE=aarch64-unknown-linux-gnu ;;
    *) echo "wasm-auditor: unsupported platform $OS-$ARCH" >&2; exit 1 ;;
  esac
  mkdir -p .wasm-tools
  curl -fsSL "https://github.com/rustwasm/wasm-bindgen/releases/download/${VER}/wasm-bindgen-${VER}-${TRIPLE}.tar.gz" \
    | tar xz -C .wasm-tools
  WB="$(find .wasm-tools -name wasm-bindgen -type f | head -1)"
fi
echo "wasm-auditor: using $("$WB" --version)"

echo "wasm-auditor: build wasm32"
cargo build -p mneme-verify-wasm --target wasm32-unknown-unknown --release
WASM="${CARGO_TARGET_DIR:-$ROOT/target}/wasm32-unknown-unknown/release/mneme_verify_wasm.wasm"

echo "wasm-auditor: generate bindings (node + web)"
"$WB" --target nodejs --out-dir crates/mneme-verify-wasm/pkg-node "$WASM"
"$WB" --target web    --out-dir crates/mneme-verify-wasm/pkg-web  "$WASM"

echo "wasm-auditor: run node verification test"
node crates/mneme-verify-wasm/test/node-verify.cjs

echo "wasm-auditor: OK"
