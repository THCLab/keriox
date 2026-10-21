#!/usr/bin/env bash
# Read the vectors keriox writes in its default wire format
# (test-vectors/keriox-legacy) with the keriox revision deployed clients are
# built from, pinned in legacy-check/Cargo.toml. Fails if that keriox cannot
# parse a stream, writes a message back differently or accepts other events
# of a key event log.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cargo run --quiet --locked --manifest-path "$here/legacy-check/Cargo.toml" -- \
    "$here/keriox-legacy" "$here/legacy-check/expected_differences.txt"
