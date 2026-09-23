#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
revision=01b6174a1cbad249e93f31df97d4b2ed1d0e8638
mkdir -p artifacts
checkout=$(mktemp -d "${TMPDIR:-/tmp}/llull-buzz-upstream.XXXXXX")
trap 'rm -rf "$checkout"' EXIT INT TERM
git -C "$checkout" init -q
git -C "$checkout" remote add origin https://github.com/block/buzz
git -C "$checkout" fetch --depth 1 origin "$revision"
git -C "$checkout" checkout --detach FETCH_HEAD
test "$(git -C "$checkout" rev-parse HEAD)" = "$revision"
# Only the pinned executables. Private orchestration modules are not provider APIs.
cargo +1.98.1 build --locked --release --manifest-path "$checkout/Cargo.toml" -p buzz-agent -p buzz-acp
out="artifacts/upstream-${revision}"
mkdir -p "$out/licenses"
cp "$checkout/target/release/buzz-agent" "$checkout/target/release/buzz-acp" "$out/"
find "$checkout" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' \) -exec cp {} "$out/licenses/" \;
printf '%s\n' "$revision" > "$out/source-commit.txt"
sha256sum "$out/buzz-agent" "$out/buzz-acp" > "$out/SHA256SUMS"
