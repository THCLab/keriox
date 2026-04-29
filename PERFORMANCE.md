# Performance — witness/watcher communication

This document covers how to measure and reason about the network-bound parts
of keriox: OOBI resolution, controller→witness publishing, and the
watcher-mediated AID-verification flow that a client triggers when it asks
a watcher to look up an unknown identifier.

## What is instrumented

Every hop on the AID-verification critical path emits:

1. A `tracing` span with timing fields (host, status, elapsed_ms, bytes).
   Set `RUST_LOG=info` (or `debug`/`trace`) to see them.
2. A Prometheus histogram. Currently exposed under `/metrics` on the
   watcher and witness HTTP servers.

Notable metric names:

| name | labels | what it measures |
|---|---|---|
| `keri_watcher_handler_seconds` | `endpoint` | wall time inside a watcher HTTP handler |
| `keri_watcher_oobi_resolve_seconds` | `kind=loc_scheme\|end_role` | OOBI resolution stages |
| `keri_watcher_kel_fetch_seconds` | `outcome` | top-level KEL fetch (forward_query_from) |
| `keri_watcher_witness_query_seconds` | `witness_id`, `kind=ksn\|logs\|tel` | per-witness query latency |
| `keri_watcher_witness_query_failures_total` | `witness_id`, `kind` | failure counter per witness |
| `keri_witness_handler_seconds` | `endpoint` | witness HTTP handler latency |
| `keri_witness_query_processing_seconds` | — | parse + verify + reply on a /query call |

Histograms use bucket boundaries tuned for the observed latency range
(1 ms → 60 s).

## HTTP client

`keriox_core::transport::default::DefaultTransport`,
`watcher::transport::HttpTelTransport`, and
`keri_controller::communication::HTTPTelTransport` share a process-wide
`reqwest::Client` with keep-alive, HTTP/2 negotiation, and a 32-connection
idle pool per host. Building a fresh `Client` per call (the previous
behavior) forces a TCP+TLS handshake every time, which under WAN/TLS adds
50–200 ms per call and is the root cause of the multi-second OOBI
resolution latencies observed in production.

To revert to the per-call behavior at runtime (no recompile, intended for
A/B perf measurements), set the environment variable:

```
KERIOX_DISABLE_HTTP_POOL=1
```

This applies to all three transport implementations.

## The perf harness

`keriox_tests/src/bin/perf_watcher.rs` boots N witnesses and a watcher
in-process, creates M signing identifiers (each anchored to K witnesses),
and drives the watcher's `/resolve` endpoint to make it fetch each
signer's KEL via one of that signer's witnesses. This mirrors the network
path a client triggers when verifying an unknown AID:

```
client → watcher /resolve(EndRole)
         watcher → witness /oobi/{cid}/{role}/{eid}   (KEL fetch)
```

It then renders the Prometheus histograms via a recorder installed in
`main()` and writes the full scrape to a file.

### Run it

```sh
cargo build --release -p keri-tests --bin perf_watcher
./target/release/perf_watcher
```

Tunables (env vars):

| var | default | meaning |
|---|---|---|
| `PERF_WITNESSES` | 5 | total witnesses |
| `PERF_IDENTIFIERS` | 20 | identifiers to create |
| `PERF_WITS_PER_ID` | 3 | witnesses anchored per identifier |
| `PERF_PARALLEL_VERIFY` | 1 | concurrent verifier flows |
| `PERF_BASE_PORT` | 4000 | first witness port (watcher = base + 900) |
| `PERF_METRICS_DUMP` | `/tmp/perf_watcher_metrics.txt` | full Prometheus scrape file |
| `PERF_MODE` | `resolve` | `resolve` drives watcher `/resolve` over HTTP; `fetch_kel` drives `Watcher::fetch_kel` in-process and exercises `forward_query_from` (the multi-witness fan-out path) |
| `PERF_SLOW_WITNESS_DELAY_MS` | 0 | when > 0 and there are ≥ 2 witnesses, witness 0's `/query` handler sleeps this many ms. Combined with `PERF_MODE=fetch_kel`, this validates that the priority-ordered fan-out cancels pending slow requests once a fast witness has answered. |
| `KERIOX_DISABLE_HTTP_POOL` | unset | flip to disable connection pooling for A/B |

### Example A/B (loopback, plain HTTP)

100 identifiers, 10 witnesses, 5 wits/id, 10 parallel verifier flows. Numbers
averaged over two runs.

| metric | per-call client (before) | shared client + pool (after) | delta |
|---|---|---|---|
| identifier setup (100 ids) | 3.27 s | 2.50 s | −24 % |
| verifier flow avg | 8.5 ms | 7.0 ms | −18 % |
| verifier flow p95 | 20 ms | 10 ms | −50 % |
| verifier flow p99 | 21.5 ms | 19 ms | −12 % |
| watcher `resolve_oobi` handler avg | 1.45 ms | 1.13 ms | −22 % |
| watcher `loc_scheme` resolve avg | 0.81 ms | 0.41 ms | −49 % |
| witness `/query` handler avg | 0.19 ms | 0.16 ms | −18 % |

Loopback is the floor. In WAN with TLS, each cold connection costs an
additional 50–200 ms for the handshake — per-call client pays that every
time, shared client pays it once per (host, idle-window). The 30-second
tails reported in production are consistent with several cold TLS
handshakes accumulating in the same flow, which connection pooling
eliminates.

### Reading the output

```
=== verifier flow latency over 100/100 identifiers (failed=0) ===
total wall time : 0.11s
avg             : 7 ms     p50: 7 ms     p95: 10 ms     p99: 17 ms
```

Plus selected Prometheus lines like:

```
keri_watcher_oobi_resolve_seconds_sum{kind="loc_scheme"} 0.20898153
keri_watcher_oobi_resolve_seconds_count{kind="loc_scheme"} 500
```

Divide `_sum / _count` for the per-call mean. The full scrape (with
buckets, all labels) goes to `/tmp/perf_watcher_metrics.txt` for manual
inspection or feeding into Grafana.

### Slow-witness validation (step 3)

The `forward_query_from` change in step 3 is supposed to ensure that one
slow witness no longer dominates a verification flow. To prove it
empirically:

```sh
# All-fast baseline (5 witnesses, 4 per signer, fetch_kel mode)
PERF_MODE=fetch_kel PERF_WITNESSES=5 PERF_IDENTIFIERS=20 \
  PERF_WITS_PER_ID=4 ./target/release/perf_watcher

# Same workload, but witness 0 sleeps 2 s on every /query
PERF_MODE=fetch_kel PERF_WITNESSES=5 PERF_IDENTIFIERS=20 \
  PERF_WITS_PER_ID=4 PERF_SLOW_WITNESS_DELAY_MS=2000 \
  ./target/release/perf_watcher
```

Expected: the fetch_kel verifier flow latency stays the same in both
runs (≈ 1 ms on loopback). If the slow witness dominated the flow it
would be ≈ 2000 ms.

Identifier setup *does* slow down in the slow-witness run because the
controller's `query_mailbox` waits on all witnesses; that is unrelated
to the watcher fan-out path and not what step 3 targets.

### Caveats

- The `resolve` mode exercises `/resolve` only and does not trigger
  `forward_query_from`. Use `PERF_MODE=fetch_kel` to measure the
  multi-witness fan-out path.
- All metrics flow through one process-wide global recorder, installed
  in the perf binary's `main()`. Watcher and witness in-process
  `install()` calls then return `None` and their `/metrics` endpoints
  render empty in this configuration. In production, each binary owns
  its own recorder and exposes its own `/metrics`.
