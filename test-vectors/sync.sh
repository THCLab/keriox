#!/usr/bin/env bash
# Copy the CESR test vectors from a cesrox checkout into this repository and
# record the commit they come from.
#
#   test-vectors/sync.sh [CESROX_CHECKOUT]   (default: ../cesrox)
#
# The checkout must be clean so that UPSTREAM names exactly what was copied.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cesrox="$(cd "${1:-$here/../../cesrox}" && pwd)"

if [ -n "$(git -C "$cesrox" status --porcelain -- test-vectors/v2)" ]; then
    echo "error: $cesrox has uncommitted changes in test-vectors/v2" >&2
    exit 1
fi

rm -rf "$here/v2"
cp -r "$cesrox/test-vectors/v2" "$here/v2"
cp "$cesrox/test-vectors/harness.rs" "$here/harness.rs"
git -C "$cesrox" rev-parse HEAD > "$here/UPSTREAM"
echo "copied test-vectors/v2 from cesrox $(cat "$here/UPSTREAM")"
