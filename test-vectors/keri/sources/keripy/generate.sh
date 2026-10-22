#!/usr/bin/env bash
# Regenerate the keripy KERI protocol vectors in test-vectors/keri/v1/keripy
# and test-vectors/keri/v2/keripy from the revision pinned in
# requirements.txt. Requires uv and libsodium.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
venv="${VENV:-$here/.venv}"
rev="$(sed -n 's/^keri @ git+.*@\([0-9a-f]\{40\}\)$/\1/p' "$here/requirements.txt")"

if [ ! -x "$venv/bin/python" ]; then
    uv venv --quiet --python 3.14 "$venv"
fi
uv pip install --quiet --python "$venv/bin/python" -r "$here/requirements.txt"

out="$here/../.."
rm -rf "$out/v1/keripy" "$out/v2/keripy"
cd "$here"
"$venv/bin/python" -I -W ignore gen_vectors.py "$out" --keripy-rev "$rev" >/dev/null
echo "vectors written to $(cd "$out" && pwd)/v{1,2}/keripy (keripy $rev)"
