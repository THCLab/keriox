#!/usr/bin/env bash
# Read the vectors keriox writes (test-vectors/keriox) with the keripy
# revision pinned in keripy/requirements.txt and compare the outcome with
# keripy/cross_check.txt, the list of vectors keripy does not confirm. Pass
# --bless to rewrite that list after an intentional change. Requires uv and
# libsodium.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
venv="${VENV:-$here/keripy/.venv}"

if [ ! -x "$venv/bin/python" ]; then
    uv venv --quiet --python 3.14 "$venv"
fi
uv pip install --quiet --python "$venv/bin/python" -r "$here/keripy/requirements.txt"

"$venv/bin/python" -I -W ignore "$here/keripy/check.py" "$here/keriox" \
    "$here/keripy/cross_check.txt" "$@"
