# Performance — witness/watcher communication

This document covers two things:

1. **How to use the metrics and tracing** that are now wired into the
   watcher and witness — what's exposed, where, and how to scrape it.
2. **How to reproduce the A/B baseline** the perf harness was built to
   measure, and what the numbers from the five-step optimisation
   actually deliver.

If you only want to run a benchmark, jump to
[Reproducible A/B runbook](#reproducible-ab-runbook). If you want to
understand a specific change, see
[What each step contributes](#what-each-step-contributes).

---

## 1. Metrics and tracing — how to use them

### Tracing

Every hop on the AID-verification critical path emits a `tracing` span
with structured fields (host, status, elapsed_ms, bytes,
prefix, witness_id, sn). The watcher and witness already initialise
`tracing-subscriber` with env-filter, so:

```sh
RUST_LOG=info  watcher --config ...     # default
RUST_LOG=watcher=debug,keri_core=debug,witness=info  watcher ...
RUST_LOG=keri_core::transport=trace  watcher ...    # per-request HTTP timings
```

The most useful filters when chasing a slow flow:

- `keri_core::transport::default=debug` — every outbound HTTP request
  with elapsed_ms and target host.
- `watcher::watcher::watcher_data=debug` — `forward_query_from` /
  `query_state` / `ksn_update` per witness.
- `watcher::watcher_listener=info` — handler entry/exit on /query,
  /resolve, /query/tel.

### Prometheus metrics

The watcher and witness each install a `metrics-exporter-prometheus`
recorder on first call to `listen_http` and expose it at:

```
GET http://<watcher-host>:<port>/metrics
GET http://<witness-host>:<port>/metrics
```

Histograms use bucket boundaries tuned for the observed range
(1 ms → 60 s). Useful queries:

| metric | labels | what it measures |
|---|---|---|
| `keri_watcher_handler_seconds` | `endpoint` | wall time inside a watcher HTTP handler |
| `keri_watcher_oobi_resolve_seconds` | `kind=loc_scheme \| end_role` | OOBI resolution stages |
| `keri_watcher_kel_fetch_seconds` | `outcome` | top-level KEL fetch (`forward_query_from`) |
| `keri_watcher_witness_query_seconds` | `witness_id`, `kind=ksn \| logs \| tel` | per-witness query latency |
| `keri_watcher_witness_query_failures_total` | `witness_id`, `kind` | failure counter per witness |
| `keri_witness_handler_seconds` | `endpoint` | witness HTTP handler latency |
| `keri_witness_query_processing_seconds` | — | parse + verify + reply on a /query call |

Grafana cheat-sheet:

```promql
# Watcher's "verify an unknown AID" p95
histogram_quantile(0.95, sum by (le) (rate(keri_watcher_kel_fetch_seconds_bucket[5m])))

# Slowest witness for a given AID
topk(5,
  histogram_quantile(0.99, sum by (le, witness_id) (
    rate(keri_watcher_witness_query_seconds_bucket{kind="logs"}[5m])
  ))
)

# Per-witness failure rate
sum by (witness_id) (rate(keri_watcher_witness_query_failures_total[5m]))
```

`witness_id` cardinality is bounded by the size of your witness fleet,
so it's safe to keep as a label.

### Manual scrape

For ad-hoc work without a Prometheus server:

```sh
curl -s http://localhost:3236/metrics | grep '^keri_'
```

---

## 2. The perf harness

`keriox_tests/src/bin/perf_watcher` is a self-contained binary that:

1. Boots N witnesses + 1 watcher in-process.
2. Creates M signing identifiers, each anchored to K of those
   witnesses (the assignment cycles, so witness load is roughly even).
3. Drives the watcher's KEL-fetch path for each identifier.
4. Times each fetch, prints latency stats, and dumps the Prometheus
   scrape to disk.

It installs the Prometheus recorder once in `main()` so all
in-process histograms (watcher + witness) end up in the same render —
that is why `/metrics` on the spawned watcher would render empty in
this configuration. In production each binary installs its own.

### Build

```sh
cargo build --release -p keri-tests --bin perf_watcher
```

### Tunables

| var | default | meaning |
|---|---|---|
| `PERF_WITNESSES` | 5 | total witnesses |
| `PERF_IDENTIFIERS` | 20 | identifiers to create |
| `PERF_WITS_PER_ID` | 3 | witnesses anchored per identifier |
| `PERF_PARALLEL_VERIFY` | 1 | concurrent verifier flows |
| `PERF_BASE_PORT` | 4000 | first witness port (watcher = base + 900) |
| `PERF_METRICS_DUMP` | `/tmp/perf_watcher_metrics.txt` | full Prometheus scrape file |
| `PERF_MODE` | `resolve` | `resolve` drives watcher `/resolve` over HTTP. `fetch_kel` drives `Watcher::fetch_kel` in-process and exercises `forward_query_from` (the multi-witness fan-out path). |
| `PERF_SLOW_WITNESS_DELAY_MS` | 0 | when > 0 and there are ≥ 2 witnesses, witness 0's `/query` handler sleeps this long. Combined with `PERF_MODE=fetch_kel`, this validates that the priority-ordered fan-out cancels pending slow requests once a fast witness has answered. |
| `KERIOX_DISABLE_HTTP_POOL` | unset | flip to disable connection pooling and re-test against the pre-step-2 behavior |

### Reading the output

```
=== verifier flow latency over 100/100 identifiers (failed=0) ===
total wall time : 0.10s
avg             : 7 ms     p50: 7 ms     p95: 9 ms     p99: 14 ms

=== watcher metrics (selected) ===
keri_watcher_oobi_resolve_seconds_sum{kind="loc_scheme"} 0.209
keri_watcher_oobi_resolve_seconds_count{kind="loc_scheme"} 500
...
full metrics dump written to /tmp/perf_watcher_metrics.txt
```

Divide `_sum / _count` for the per-call mean. The full scrape (with
buckets, every label) goes to the dump file for manual inspection or
feeding into Grafana.

---

## 3. Reproducible A/B runbook

These four scenarios cover the measurable contribution of every step
in the optimisation. Run them in this order on a quiet machine; total
wall time is ~3 minutes.

```sh
cargo build --release -p keri-tests --bin perf_watcher

# A. After all 5 steps, /resolve flow (HTTP path)
PERF_MODE=resolve PERF_WITNESSES=10 PERF_IDENTIFIERS=100 \
  PERF_WITS_PER_ID=5 PERF_PARALLEL_VERIFY=10 PERF_BASE_PORT=8000 \
  ./target/release/perf_watcher

# B. Same workload, with the connection pool disabled
KERIOX_DISABLE_HTTP_POOL=1 PERF_MODE=resolve \
  PERF_WITNESSES=10 PERF_IDENTIFIERS=100 PERF_WITS_PER_ID=5 \
  PERF_PARALLEL_VERIFY=10 PERF_BASE_PORT=8200 \
  ./target/release/perf_watcher

# C. fetch_kel mode (forward_query_from path), all witnesses fast
PERF_MODE=fetch_kel PERF_WITNESSES=5 PERF_IDENTIFIERS=20 \
  PERF_WITS_PER_ID=4 PERF_BASE_PORT=8400 \
  ./target/release/perf_watcher

# D. Same as C, but witness 0 sleeps 2 s on every /query
PERF_MODE=fetch_kel PERF_WITNESSES=5 PERF_IDENTIFIERS=20 \
  PERF_WITS_PER_ID=4 PERF_SLOW_WITNESS_DELAY_MS=2000 \
  PERF_BASE_PORT=8600 \
  ./target/release/perf_watcher
```

A vs B isolates step 2 (HTTP connection pool). C vs D isolates step 3
(first-success fan-out). Steps 1 (instrumentation), 4 (poller
parallelism), and 5 (circuit breaker) don't have a single-flag toggle
because the harness's short-running scenarios don't exercise them
end-to-end — see [What each step contributes](#what-each-step-contributes)
below for what each one buys you.

### Measured A/B results

Loopback, plain HTTP, machine idle (load avg ≈ 2). Numbers averaged
over two runs each.

#### A vs B — `/resolve` flow (step 2 contribution)

| metric | B: pool OFF (pre-step-2 baseline) | A: pool ON (after all 5 steps) | delta |
|---|---|---|---|
| identifier setup, 100 ids | 3.10 s | 2.55 s | **−18 %** |
| verifier flow avg | 8.5 ms | 6.5 ms | **−24 %** |
| verifier flow p50 | 8.5 ms | 7.0 ms | −18 % |
| verifier flow p95 | **16.5 ms** | **9.0 ms** | **−45 %** |
| verifier flow p99 | 17.0 ms | 14.5 ms | −15 % |
| watcher `loc_scheme` resolve avg | 0.81 ms | 0.42 ms | −49 % |
| watcher `end_role` resolve avg (incl. KEL fetch) | 4.65 ms | 4.65 ms | ≈0 |
| witness `/query` handler avg | 0.19 ms | 0.16 ms | −16 % |

#### C vs D — `fetch_kel` flow (step 3 contribution)

| metric | C: all fast | D: witness 0 sleeps 2 s | observation |
|---|---|---|---|
| verifier p99 | 1 ms | **1 ms** | first-success cancels the slow witness; flow is bound to the *fast* witness latency |
| identifier setup | 0.41 s | 32.5 s | controller `query_mailbox` waits on all witnesses; *not* the path step 3 targets |

The single-digit-millisecond verifier latency in scenario D, with one
witness sleeping for 2 seconds on every request, is the headline
result of step 3.

### What this means in WAN with TLS

Loopback is the floor. With real TLS each cold connection adds
50–200 ms for the handshake. The pre-step-2 path pays this on every
call; the shared client pays it once per (host, idle window). For a
10-call verification flow that's **0.5–2 s saved per flow**, which is
consistent with the 30-second tails operators reported in production.

The A/B above already shows a 45 % p95 reduction without TLS — the
absolute milliseconds become absolute seconds in production.

---

## 4. What each step contributes

Step numbering matches the implementation plan
(`~/.claude/plans/witness-and-watcher-communication-dapper-gizmo.md`).

| step | change | how to observe |
|---|---|---|
| 1 | `tracing` spans + `/metrics` on watcher and witness | `RUST_LOG=keri_core::transport=debug`; `curl /metrics`; the perf harness output is built on these. |
| 2 | shared `reqwest::Client` with keep-alive + 32-conn pool | A vs B above. Toggle via `KERIOX_DISABLE_HTTP_POOL=1`. **Largest measurable win on every flow.** |
| 3 | health-prioritised `FuturesUnordered` fan-out, first-success in `forward_query_from`, healthy-only in `query_state` | C vs D above. **Headline win**: one slow witness no longer drags the verification flow. |
| 4 | parallel poller fan-out (16-wide) | Visible only with many tracked AIDs over a poll cycle (default 30 s). Not exercised by the harness's short-running scenarios. |
| 5 | circuit-breaker cool-down on `WitnessHealth::is_healthy()` | Visible only when a witness has crossed 3 consecutive failures. Unit-tested in `watcher::watcher::health::tests`. |

Steps 4 and 5 are deliberately not exercised by the harness because
they're failure-mode optimisations:

- Step 4's win shows up as steady-state poll-cycle wall time on a
  watcher with many AIDs. A meaningful test needs the poll loop to
  actually run, i.e. wall time ≥ 30 s, with several hundred tracked
  AIDs. Easier to validate by reading the diff and the tests.
- Step 5 only kicks in once a witness has failed three calls in a
  row. Its job is to stop hammering a known-broken witness for
  30 seconds. Empirically validating it would require killing a
  witness mid-run; the unit tests cover the four state transitions
  directly.

---

## 5. Caveats

- The harness drives the watcher in-process and installs one
  Prometheus recorder for the whole process. In production, each
  binary owns its own recorder and exposes its own `/metrics`.
- The `resolve` mode does not trigger `forward_query_from`; use
  `PERF_MODE=fetch_kel` to measure the multi-witness fan-out path.
- The controller's `query_watchers` flow has a pre-existing hang at
  HEAD that's unrelated to this work, so the harness drives the
  watcher's HTTP API directly. If/when that's fixed, the
  controller-driven verifier flow can be wired into the harness for
  a more end-to-end measurement.
- `KERIOX_DISABLE_HTTP_POOL=1` is intended as a measurement aid; it
  exists so ops can re-verify the connection-pool win against any
  real environment without a recompile, and so this document's A/B
  is reproducible. There is no reason to leave it set in production.
