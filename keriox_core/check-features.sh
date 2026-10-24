#!/usr/bin/env bash
# Checks that keri-core builds with each of its features on its own, the way
# dependents that enable only what they need build it. --all-features in CI
# cannot catch a feature that relies on code gated behind another one.
#
#   keriox_core/check-features.sh
set -euo pipefail

cd "$(dirname "$0")"
features=$(cargo metadata --no-deps --format-version 1 |
    python3 -c 'import json, sys
pkg = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "keri-core")
# optional dependencies show up as implicit features; only declared ones count
optional = {d.get("rename") or d["name"] for d in pkg["dependencies"] if d["optional"]}
print(" ".join(f for f in sorted(pkg["features"]) if f != "default" and f not in optional))')

cargo check -p keri-core --no-default-features
for feature in $features; do
    echo "== keri-core --no-default-features --features $feature"
    cargo check -p keri-core --no-default-features --features "$feature"
done
