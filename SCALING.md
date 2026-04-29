# Scaling proposal — witness, watcher, controller

This is a working document capturing where the system currently scales,
where it doesn't, and what to invest in next. It builds on the
performance work documented in `PERFORMANCE.md` (steps 1–5).

## Context

Two scaling pressures matter operationally:

1. **A watcher observing many witnesses** — does the watcher slow down
   as its tracked-AID set or its connected-witness fleet grows?
2. **A witness for many users** — hundreds of thousands or millions of
   AIDs trusting a single witness operator.

The HTTP-level work in steps 2–5 (shared client, first-success
fan-out, parallel poller, circuit breaker) addresses the first
pressure. The second is mostly a storage and write-throughput problem
that the existing changes don't touch.

## Architectural fact: multi-witness is W-way replication

Every AID in KERI lists its witnesses in its KEL. A controller with
tally `t-of-W` is durably stored on `W` independent operators'
machines, each producing its own receipts. This is **protocol-native
replication** with no infrastructure cost, and it shapes every
trade-off below.

Implication: most of the things you'd reach for Postgres replication
to solve in a single-witness deployment are already solved at the
protocol layer in a multi-witness deployment. The remaining genuine
Postgres argument is single-operator scale and compliance, not data
safety.

## Where Postgres helps vs doesn't (in *this* codebase)

| concern | redb today | Postgres today | comment |
|---|---|---|---|
| Watcher tracking many witnesses | fine — HTTP-bound, already addressed | irrelevant — it's not a storage problem | step 3 fan-out scales *better* with more witnesses per AID |
| Watcher tracking many AIDs (≥ 1 M) | bounded by single-host capacity | shared state across replicas, in theory | not implemented for watcher; would require setup_with_postgres + removing block_on |
| Witness for ≤ ~hundreds of K users | fine | overkill | redb single-writer handles 100s of writes/sec, KEL events are rare |
| Witness for millions of users, sustained writes | redb single-writer becomes ceiling | could parallelise per-AID writes | not implemented for witness; mailbox is permanently redb (`keriox_core/src/database/mailbox.rs`) |
| One operator's HA / PITR / regulated backup | not provided | yes, the strongest case | needs Postgres witness + block_on removal first |
| Cross-witness data redundancy | already provided by protocol | duplicate of what the protocol gives | only adds value for the single-operator failure modes |

## Important correction from the earlier brief

Witnesses are **not** prefix-shardable behind a load balancer. The
witness identity is part of the AID's KEL — controllers pick specific
witness AIDs at inception. To scale witness capacity in one operator
you grow the *pool* over time (more witness AIDs from that operator),
and each new AID picks from the larger pool. Existing AIDs stay tied
to their original witnesses unless they rotate.

This means horizontal scaling for a witness operator looks like:
> "I run N witness AIDs. Controllers picking from my pool naturally
> distribute load. Each AID lands on `K` of my N pods. My per-pod
> load is roughly `total_AIDs × K / N`."

Not:
> "I put a load balancer in front of my witness and shard by AID
> prefix." (← wrong; receipts wouldn't validate.)

## Proposed work items, in priority order

### 1. Controller-side first-tally fan-out (mirrors step 3, on writes)

**Status**: identified during perf testing, not implemented.
**Why**: `broadcast.rs:216–227` and `identifier/mechanics/query_mailbox.rs`
use `join_all` and wait for the slowest witness. The perf harness
showed this clearly: with 4 witnesses, 1 slow at 2 s, identifier
setup blew up from 0.4 s to 32.5 s for 100 ids.
**What**: same `FuturesUnordered` + first-N-success pattern as step
3, where N = the AID's tally. Fan out to all, return when `tally`
receipts have come back, leave the rest pending.
**Risk**: low. Tally is the protocol's correctness threshold; waiting
beyond it is overhead. Witnesses that haven't responded yet still get
their receipt eventually because the request was launched.
**Effort**: ~1 day. Touches two files; the perf harness already
exercises the path via `notify_witnesses` and `query_mailbox`.

### 2. Witness pod sharding pattern, documented as a deployment guide

**Status**: not in code; this is operational guidance.
**Why**: the right scaling answer for a witness operator is "run N
witness AIDs and let controllers distribute." That's not obvious from
the code, and there's no doc for it.
**What**: a section in `DEVELOPER.md` or a new `OPERATIONS.md`
covering: how to spin up additional witness AIDs, how to advertise
them to controllers, expected per-pod load math, when to consider
Postgres instead.
**Risk**: zero (docs only).
**Effort**: ~half a day.

### 3. Witness for millions: shard-by-witness-AID first, only then Postgres

**Status**: redb works up to ~50 GB / ~1 K writes/sec on commodity
hardware; beyond that you need a different strategy.
**Decision tree**:
1. Does growing the witness *pool* (more witness AIDs per operator)
   resolve the load? Usually yes for write rate. Pursue this first.
2. Does any single-pod still exceed redb's comfort zone (file size,
   contention)? If no, stop here.
3. If yes: build the Postgres witness path. This is real work — see
   item 4.

### 4. Postgres witness implementation (only if 1–3 don't suffice)

**Status**: scaffolding exists in `keriox_core` and `teliox`; no
`setup_with_postgres` constructor on the witness; mailbox stays redb.
**Required work**:
- Build `WitnessListener::setup_with_postgres` mirroring the
  redb constructor. `Witness::new` (`components/witness/src/witness.rs:155`)
  takes `RedbDatabase` directly in places — needs decoupling.
- Decide what to do about the mailbox. Either port to Postgres
  (large change — new tables, new cleanup logic) or accept that even
  a Postgres witness writes a per-pod mailbox file and is therefore
  not stateless.
- Remove `async_std::task::block_on(...)` wrappers across
  `keriox_core/src/database/postgres/`. Currently every Postgres
  query parks the async runtime; without this, "concurrent writes
  via Postgres" doesn't materialise. Migrate to sqlx with
  `runtime-tokio`.
- Fill in the `todo!()` and `panic!()` sites:
  - `keriox_core/src/database/postgres/mod.rs:385` (receipt range queries)
  - `keriox_core/src/database/postgres/oobi_storage.rs:122` (KSN reply route)
  - `keriox_core/src/database/postgres/ksn_log.rs:30` (panic on type mismatch)
  - `support/teliox/src/database/postgres.rs:461` (panic on schema setup)
- Add concurrency tests — multiple processes writing to the same
  Postgres database is the *one* thing Postgres is for, and there are
  zero tests for it today.

**Effort**: 2–3 weeks for someone familiar with the codebase.
**Risk**: moderate. Touches load-bearing storage paths; needs
careful migration of existing redb deployments if rolled out.

### 5. Watcher state sharing across replicas (Postgres watcher path)

**Status**: not implemented; pure follow-on once 4 lands.
**Why**: a watcher with millions of tracked AIDs benefits from
sharing KEL state across replicas instead of each replica re-fetching
from witnesses independently.
**What**: same shape as the witness Postgres path — Postgres
constructor on `WatcherListener`, decouple the redb-typed fields, no
`block_on`.
**Effort**: probably another week on top of 4, since the storage
layer is shared.
**Decision criterion**: only worth doing if a single watcher pod is
running out of memory or its KEL store is hitting redb's size limits.
Until then, sharding tracked AIDs across watcher pods (each with its
own redb) is simpler.

### 6. (Stretch) Push-based witness → watcher subscription

**Status**: not in protocol scope here, but worth noting.
**Why**: today watchers poll witnesses on a 30 s adaptive cadence.
For a watcher tracking 1 M AIDs, even with adaptive intervals that's
a lot of "nothing-changed" round trips. A push model — watchers
subscribe, witnesses send when something changes — would scale
qualitatively better.
**Effort**: significant; touches protocol and both components.
**Decision criterion**: only relevant at very high tracked-AID counts.

## Open questions to revisit

- Should `WitnessHealthTracker::COOL_DOWN` and `FAILURE_THRESHOLD`
  (currently constants in `health.rs`) become per-deployment config?
  Probably yes once we have a deployment with diverse witness
  reliability.
- The perf harness drives `/resolve` and in-process `fetch_kel`
  because the controller's `add_watcher` flow has a pre-existing hang
  at HEAD. Untangling that lets the harness measure the controller →
  watcher → witness → KEL round trip end-to-end, which is the real
  user-facing latency.
- WAN-with-TLS measurement of all of the above. Loopback shows the
  *floor*; the wins from steps 2–3 grow significantly under TLS.

## TL;DR for prioritisation

1. **Cheap, big bang for the buck**: item 1 (controller first-tally
   fan-out). Same pattern as step 3, fixes the slow-witness problem
   on writes.
2. **Documentation**: item 2 (witness sharding pattern). Half a day,
   prevents the wrong scaling decision.
3. **Medium project, only if you actually need it**: item 4 (Postgres
   witness). 2–3 weeks. Don't reach for this until items 1–3 don't
   suffice. The protocol's multi-witness model already gives you most
   of what Postgres replication would.
4. **Hold**: items 5 and 6. Watch for the conditions that would
   justify them; don't pre-build.
