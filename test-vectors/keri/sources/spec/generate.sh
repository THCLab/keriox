#!/usr/bin/env bash
# Copy the examples of the KERI specification into test-vectors/keri/v2/spec
# (every example message in the specification is a KERI 2.0 body).
# Usage: generate.sh [checkout of trustoverip/kswg-keri-specification]
#        (default ../kswg-keri-specification, relative to the keriox checkout)
# Needs only python3 (standard library).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
spec="${1:-$root/../kswg-keri-specification}"
if [ ! -f "$spec/spec/spec-body.md" ]; then
    echo "usage: $0 <kswg-keri-specification checkout>" >&2
    echo "no spec/spec-body.md in $spec" >&2
    exit 1
fi
python3 -I "$here/extract.py" "$spec" "$here/../../v2/spec"
