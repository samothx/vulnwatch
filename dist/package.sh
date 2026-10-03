#!/usr/bin/env bash
#
# package.sh: build the static musl binary and bundle it with the default config, watch list,
# systemd units and install.sh:  target/bundle/vulnwatch-<version>-x86_64-linux.tar.gz
# Trivy is not bundled: install.sh downloads the pinned release and checks its sha256.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test --quiet
cargo build --release --target x86_64-unknown-linux-musl
BIN=target/x86_64-unknown-linux-musl/release/vulnwatch
VERSION="$("$BIN" --version | cut -d' ' -f2)"
NAME="vulnwatch-$VERSION-x86_64-linux"
OUT="target/bundle/$NAME"

# The shipped config + watch list must load.
"$BIN" --config defaults/config.toml config check >/dev/null

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$BIN" README.md dist/install.sh dist/dispatcher-rules.toml "$OUT/"
cp -r defaults dist/systemd "$OUT/"
tar -C target/bundle -czf "target/bundle/$NAME.tar.gz" "$NAME"
sha256sum "target/bundle/$NAME.tar.gz"
