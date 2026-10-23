#!/usr/bin/env bash
# Checks that this keriox and the keriox deployed clients are built from
# work together over HTTP, whichever side is upgraded first:
#
#   1. clients of the deployed revision against witnesses and a watcher of
#      this keriox;
#   2. clients of this keriox against witnesses and a watcher of the
#      deployed revision;
#   3. witnesses and a watcher of the deployed revision upgraded in place:
#      this keriox, started on their databases, serves the stored key event
#      logs byte for byte as they did, and old clients keep working.
#
# The clients are the scenarios of keriox_tests (multisig, delegation,
# watcher queries, witness rotation), made to use the nodes this script
# starts instead of starting their own: the deployed revision through
# external-nodes.patch, this keriox through KERIOX_TEST_NODES. The nodes
# listen on the ports in COMPAT_PORTS (first witness, second witness,
# watcher), which must be free.
#
#   compat/check.sh            # OLD_REV overrides the deployed revision
set -euo pipefail

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
# the revision of keriox's development branch deployed clients (cyfron)
# are locked to, and the cesrox and said releases it was built with
old_rev="${OLD_REV:-6f70bb2ba5ebeb2bc8707a003d4637bcbd1176cd}"
work="${WORK:-$root/target/compat}"
read -r wit1_port wit2_port watcher_port <<<"${COMPAT_PORTS:-3332 3333 3336}"
wit1_seed=ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc
wit2_seed=ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAd
watcher_seed=Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8
# where the client scenarios of this keriox find the nodes
export KERIOX_TEST_NODES="$wit1_seed@http://127.0.0.1:$wit1_port \
$wit2_seed@http://127.0.0.1:$wit2_port $watcher_seed@http://127.0.0.1:$watcher_port"
scenarios=(
    query_updates
    indirect_mode_signing
    multisig
    single_delegator_single_delegatee
    multi_delegator_single_delegatee
    multisig_delegator_multisig_delegatee
    test_witness_rotation
)

prepare() { # <dir> [patch]: build the nodes and the client scenarios in <dir>
    (
        cd "$1"
        if [ "${2:-}" = patch ]; then
            patch --quiet -p1 <"$root/compat/external-nodes.patch"
            # the scenarios' node ports (also in expected oobis) become ours
            grep -rlE '127.0.0.1:323[236]' keriox_tests | xargs -r sed -i \
                -e "s/127.0.0.1:3232/127.0.0.1:$wit1_port/g" \
                -e "s/127.0.0.1:3233/127.0.0.1:$wit2_port/g" \
                -e "s/127.0.0.1:3236/127.0.0.1:$watcher_port/g"
        fi
        export CARGO_TARGET_DIR="$1/target"
        cargo build --quiet -p witness -p watcher
        cargo test --quiet -p keri-tests --no-run
    )
}

echo "preparing the deployed revision ${old_rev:0:8}"
rm -rf "$work"
mkdir -p "$work/old" "$work/new" "$work/run"
git -C "$root" archive "$old_rev" | tar -x -C "$work/old"
# it was built against a local cesrox checkout, before cesrox 2.0 was
# published
python3 - "$work/old/Cargo.toml" <<'EOF'
import re, sys
path = sys.argv[1]
text = open(path).read()
open(path, "w").write(re.sub(r"\[patch\.crates-io\]\n(?:[^\[\n].*\n|\n)*", "", text))
EOF
(
    cd "$work/old"
    cargo generate-lockfile --quiet
    cargo update --quiet -p cesrox --precise 2.0.0-beta.8
    cargo update --quiet -p said --precise 0.5.3-beta.2
)
prepare "$work/old" patch

echo "preparing this keriox"
git -C "$root" ls-files -co --exclude-standard -z |
    (cd "$root" && tar --null -T - -c) | tar -x -C "$work/new"
[ -f "$root/Cargo.lock" ] && cp "$root/Cargo.lock" "$work/new/"
prepare "$work/new"

run="$work/run"
for node in "wit1:$wit1_port:$wit1_seed" "wit2:$wit2_port:$wit2_seed"; do
    IFS=: read -r name port seed <<<"$node"
    cat >"$run/$name.yml" <<EOF
db_path: "$run/$name-db"
http_port: $port
public_url: "http://127.0.0.1:$port/"
seed: "$seed"
EOF
done
cat >"$run/watcher.yml" <<EOF
db_path: "$run/watcher-db"
tel_storage_path: "$run/watcher-tel"
public_url: "http://127.0.0.1:$watcher_port/"
seed: "$watcher_seed"
http_port: $watcher_port
initial_oobis: []
EOF

pids=()
start() { # <tree> <label>: start the nodes built in <tree>
    for name in wit1 wit2; do
        "$work/$1/target/debug/witness" -c "$run/$name.yml" >"$run/$2-$name.log" 2>&1 &
        pids+=($!)
    done
    "$work/$1/target/debug/watcher" -c "$run/watcher.yml" >"$run/$2-watcher.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 60); do
        up=0
        for port in "$wit1_port" "$wit2_port" "$watcher_port"; do
            curl -sf -o /dev/null "http://127.0.0.1:$port/introduce" && up=$((up + 1))
        done
        [ "$up" = 3 ] && return
        sleep 1
    done
    echo "nodes of $1 did not start, see $run/$2-*.log" >&2
    exit 1
}
stop() {
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
    pids=()
}
trap stop EXIT
fresh_databases() {
    rm -rf "$run"/*-db "$run/watcher-tel"
    mkdir -p "$run/wit1-db" "$run/wit2-db" "$run/watcher-db" "$run/watcher-tel"
}

failed=0
clients() { # <tree> <label> <scenario>...: run scenarios of <tree>'s client
    local tree=$1 label=$2
    shift 2
    for test in "$@"; do
        if (cd "$work/$tree" && CARGO_TARGET_DIR="$work/$tree/target" timeout 300 \
            cargo test --quiet -p keri-tests --test "$test" -- --test-threads=1) \
            >"$run/$label-$test.log" 2>&1; then
            echo "  ok    $test"
        else
            echo "  FAIL  $test (see $run/$label-$test.log)"
            failed=$((failed + 1))
        fi
    done
}

served() { # the key event logs the witnesses serve for every identifier they saw
    { grep -ho 'E[A-Za-z0-9_-]\{43\}' "$run"/upgrade-old-wit*.log || true; } | sort -u |
        while read -r id; do
            for port in "$wit1_port" "$wit2_port"; do
                eid=$(curl -sf "http://127.0.0.1:$port/introduce" |
                    sed 's/.*"eid":"\([^"]*\)".*/\1/')
                printf '%s %s ' "$id" "$port"
                # without the witness's own location reply, which is signed
                # anew at every start
                curl -sf "http://127.0.0.1:$port/oobi/$id/witness/$eid" |
                    python3 -c 'import re, sys
print("".join(m for m in re.split(r"(?=\{\"v\":)", sys.stdin.read()) if "\"t\":\"rpy\"" not in m))'
            done
        done
}

echo "1. deployed clients, nodes of this keriox"
fresh_databases
start new old-clients
clients old old-clients "${scenarios[@]}"
stop

echo "2. clients of this keriox, deployed nodes"
fresh_databases
start old new-clients
clients new new-clients "${scenarios[@]}"
stop

echo "3. deployed nodes upgraded in place"
fresh_databases
start old upgrade-old
clients old upgrade-before multisig single_delegator_single_delegatee test_witness_rotation
served >"$run/served-before"
stop
start new upgrade-new
served >"$run/served-after"
events=$(grep -o '{"v":' "$run/served-before" | wc -l)
if [ "$events" -gt 0 ] && cmp -s "$run/served-before" "$run/served-after"; then
    echo "  ok    $events stored events and their attachments served as before"
else
    echo "  FAIL  stored key event logs served differently ($events events before)"
    diff "$run/served-before" "$run/served-after" | head -c 2000
    failed=$((failed + 1))
fi
clients old upgrade-after multisig query_updates
stop

if [ "$failed" -gt 0 ]; then
    echo "$failed check(s) failed"
    exit 1
fi
echo "all checks passed"
