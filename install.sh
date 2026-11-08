#!/usr/bin/env sh
# secai — one-command install: build the native core and link it.
# Usage:  ./install.sh           # build + link into ~/.local/bin
#         ./install.sh --link-only   # skip the build, link existing binary
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SECAI_BIN_DIR:-$HOME/.local/bin}"
BIN_SRC="$ROOT/core-rs/target/release/secai"

echo "==> secai installer"

if [ "$(id -u)" = "0" ] && [ -z "${SECAI_BIN_DIR:-}" ]; then
    BIN_DIR="/usr/local/bin"
fi

if [ "${1:-}" != "--link-only" ]; then
    command -v cargo >/dev/null 2>&1 || {
        echo "ERROR: cargo not found. Install Rust first: https://rustup.rs" >&2
        exit 1
    }
    echo "==> building native core (cargo build --release)"
    cargo build --release --manifest-path "$ROOT/core-rs/Cargo.toml"
fi

[ -f "$BIN_SRC" ] || {
    echo "ERROR: binary not found at $BIN_SRC — run without --link-only" >&2
    exit 1
}

mkdir -p "$BIN_DIR"
ln -sf "$BIN_SRC" "$BIN_DIR/secai"
echo "==> linked: $BIN_DIR/secai -> $BIN_SRC"

if ! command -v secai >/dev/null 2>&1; then
    echo "NOTE: '$BIN_DIR' is not on your PATH. Add it:"
    echo "      export PATH=\"$BIN_DIR:\$PATH\""
fi

echo "==> done. Try: secai validate findings.json"
