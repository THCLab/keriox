# KERI protocol test vectors

Language-neutral vectors for the [KERI specification]: signed key event logs
a validator must accept, and messages it must reject, written as CESR
streams. They test what a validator does with the messages (which events it
accepts, which replies it applies), not the encoding alone; the CESR vectors
for that are in `../v2/`.

The specification is the target. Where keripy, the reference
implementation, does something else, the vector says what the specification
requires and records what keripy does.

[KERI specification]: https://trustoverip.github.io/kswg-keri-specification/

## Sources

| Source | Produced by | Pinned at |
|---|---|---|
| `keripy` | `sources/keripy/generate.sh`, with keripy's own event builders (bodies keripy refuses to build are made by editing a valid body, then recomputing its size and SAID and signing it again) | `sources/keripy/requirements.txt`; specification commit in the manifests |
| `spec` | `sources/spec/generate.sh`, which copies the examples printed in the specification and checks them against the specification's own rules | specification commit in `v2/spec/manifest.json` |

```sh
test-vectors/keri/sources/keripy/generate.sh          # needs uv and libsodium
test-vectors/keri/sources/spec/generate.sh <checkout> # needs python3; the default
                                                      # checkout is ../kswg-keri-specification
```

Generation is deterministic: every key comes from a fixed label and every
date-time is fixed, so running a generator twice gives identical files.
`sources/keripy/gaps.json` lists the gaps between keriox and the
specification that the negative vectors cover.

## Layout

```
v1/keripy/                 KERI 1.0 bodies
  manifest.json            source, revisions, vector counts, vectors per gap,
                           and the vectors where keripy differs from the specification
  kels/positive.json       key event logs every validator must accept
  negative/negative.json   what a validator must reject, or must still accept
  negative/edge.json       the vectors of negative.json where keripy does
                           something other than the specification
v2/keripy/                 KERI 2.0 bodies, same layout
v2/spec/                   the specification's examples (all KERI 2.0 bodies)
  manifest.json            source, revision, vector counts, inconsistent examples
  examples.json            messages, seals, thresholds, next key lists, encodings
```

## File format

Every file is `{"schema": "<kind>/1", "generator": {...}, "vectors": [...]}`.
Vector ids are unique within a file and stable across regenerations. Field
maps keep their field order.

Every vector has the messages as one stream, `stream`, with CESR 2.0
attachment codes. Vectors with KERI 1.0 bodies also have `stream_cesr1`, the
same messages with CESR 1.0 attachment codes (what keripy writes for KERI
1.0). Both forms must give the same result.

### `keri-kel/1` (kels/positive.json)

Processing `stream` from empty state and running the escrows must leave
exactly `kels`: per identifier prefix, the accepted `events` (`sn`, `t`,
`d`) in order, the final sequence number `sn` and the final key `state`
(`s`, `d`, `kt`, `k`, `nt`, `n`, `bt`, `b`). `stored`, where present, is the
number of signatures and receipts keripy kept per event.

### `keri-negative/1` (negative/*.json)

- `target`: what the vector is about. `kel` is a key event stream for a
  validator; `reply`, `exchange`, `query` and `message` are routed messages;
  `witness` is a stream sent to the witness named in `witness`; `ksn` is
  the key state a validator reports afterwards.
- `expected`: the specification's outcome for the messages whose SAIDs are
  in `targets`: `reject` or `accept`. Most vectors expect `reject`. Vectors
  for gaps where keriox wrongly refuses something expect `accept`.
- `kels`: the events each identifier must have afterwards. Other
  expectations, where present, are `witnesses` (the witness list after the
  stream), `duplicity.evidence` (SAIDs that are evidence of duplicity),
  `key_state` or `key_state_notice` (key state fields), `ends` (end-role
  records `cid`, `role`, `eid`, `allowed`; `allowed: null` means no record),
  `locs` (location records `eid`, `scheme`, `url`; `url: null` means no
  record), and `witness_receipts`.
- `reason`, `spec_section`, and for gaps `gap`, `gap_kind` and `spec_quote`.
- `spec_ambiguous` and `ambiguity`: the specification is unclear or
  contradicts itself here. The expected outcome is the most defensible
  reading and `ambiguity` says which one it is.
- `keripy`: what keripy at the pinned revision does. `outcome` is `accepts`
  or `rejects` for the targets, and `agrees_with_spec` is false when that
  outcome or any of the other expectations differ. Then come what keripy
  accepted (`kels`, `locs`, ...), an optional `note`, and `review_expected`,
  the keripy behaviour the review predicted. For `message` and `query`
  vectors the outcome is whether keripy loads the body (field set, version
  string, SAID), because keripy does not process those messages from a
  stream.

### `keri-spec-example/1` (spec/examples.json)

One vector per example printed in the specification. `type` is `message`,
`seal`, `threshold`, `key-list`, `uuid-list` or `encoding`; `section`,
`section_path`, `file` and `line` say where it is printed. A message has its
field map as `sad`, the printed serialization as `raw` (`kind` JSON or
CESR) and, for native CESR examples, the annex's `label_order`; a seal has
`sad`; the other types have `value` (and `qb64`/`b64` for encodings). A
next key list names the message it reveals the next keys of in `next_of`.
`checks` holds what the generator checked (version and size, SAID, field
order, links between examples), `consistent` whether every check held, and
`errata` what did not. The file header's `declared` block holds the field
orders, seal orders and configuration traits read from the specification
text.

### Witness vectors

A `witness` vector is delivered to the witness whose prefix is in
`witness`; `witness_seed` is that witness's Ed25519 private key seed
(qb64), so a runner can start that exact witness. `witness_receipts: []`
means the witness must not receipt the target events.

## Known differences between keripy and the specification

`keripy_disagrees_with_spec` in each manifest lists them; the same vectors
are in `negative/edge.json`. At the pinned revision:

- a rotation listing one exposed next key twice meets an integer prior next
  threshold (`gap/kel-rot-dup-key-prior-next-bypass/integer`);
- a weighted next threshold with more weights than next key digests is
  accepted (`classic/weighted-next-threshold-length`);
- a source seal couple with `s=0` is refused, so a delegation anchored in the
  delegator's inception is found only by searching the KEL
  (`gap/deleg-anchor-in-inception-refused`);
- `RB` without registrar backer seals is accepted (`gap/kel-config-did-rb-nrb`);
- a different event with only an invalid signature, at an accepted location,
  is kept in the likely-duplicitous escrow (`gap/kel-duplicity-*`,
  `gap/wit-duplicity-unverified/unverified`);
- a receipt couple whose signature is coded as ECDSA secp256k1 is verified as
  Ed25519 when the bytes are a valid Ed25519 signature
  (`gap/rm-couple-sig-type-panic/valid-ed25519-bytes`);
- a key state notice whose sn has no event yet is not checked against the KEL
  (`gap/rm-ksn-sn-decimal/decimal`);
- witness list edge cases where keripy is stricter than the specification
  text: `ba` naming a current witness, `br` naming a non-witness, `br`/`ba`
  overlap, `bt=0` with witnesses (`gap/wit-*`).

## Running the vectors against keriox

`keriox_tests/tests/keri_vectors.rs` runs every vector file under `v1/` and
`v2/` (except `edge.json`, whose vectors are copies of vectors in
`negative.json`):

```sh
cargo test -p keri-tests --test keri_vectors
cargo test -p keri-tests --test keri_vectors -- --nocapture   # per-file counts
```

What it checks:

- `keri-kel/1`: `stream` is processed by a `BasicProcessor` with the default
  escrow bus. Each identifier in `kels` must have exactly the listed events
  (sn and SAID, in order) and the listed key state (`s`, `d`, `kt`, `k`,
  `nt`, `n`, `bt`, `b`). `stream_cesr1` is run the same way as a second
  vector, `<id>/cesr1`.
- `keri-negative/1`: the same validator, with an `OobiManager` for replies.
  Key events go to the processor, replies to `process_reply`, exchanges to
  `process_signed_exn`, queries to `process_signed_query`. Each identifier
  must then have exactly the events in `kels`. A target counts as accepted
  when its event is in a KEL, when its reply is stored, or when the
  exchange or query is processed without error, and it must match
  `expected`. `witnesses`, `duplicity.evidence` (the duplicitous-event
  escrow), `key_state`, `key_state_notice`, `locs` and `ends` are compared
  when present. `witness` vectors are delivered to a keriox witness
  started from `witness_seed`. `message` vectors only check that keriox
  reads the body and verifies its SAID. Only `stream` is run for these
  vectors; `stream_cesr1` is covered by the KEL vectors.
- `keri-spec-example/1`: a message must be read by keriox (JSON bodies
  directly, native CESR bodies through the stream parser). For a
  consistent example its SAID must also verify. An example whose errata
  say its content is malformed (a key in `n`, a url without a scheme) must
  instead be refused. Errata about field order alone do not count, because
  they come from the specification contradicting itself about `i` in
  routed messages, and the examples follow keripy. A seal must read as a
  keriox seal and be written back with the same fields, and a seal printed
  with a malformed value must be refused. A threshold must read and be
  written back the same. A next key list must satisfy the `nt`/`n`
  commitment of the message named in `next_of`. Encodings and the UUID
  list are not checked (6 vectors), because keriox has no API that reads a
  native field encoding or a salt on its own.

The vectors keriox does not pass today are listed in
`keriox_tests/tests/keri_vectors_expected_failures.txt`. Each line is
`<file>/<vector id> TAB <cause> TAB <reason>`. The test fails when a vector
that is not listed fails, and also when a listed vector passes, so the list
can only shrink. After an intentional change, bless the list:

```sh
KERI_VECTORS_BLESS=1 cargo test -p keri-tests --test keri_vectors
```

Blessing keeps the cause and reason of vectors that are already listed. It
writes a new failure with cause `unclassified` and its error message, which
then has to be classified by hand.

### Outcome at this revision

| File | Run | Pass | Expected failures |
|---|---:|---:|---:|
| `v1/keripy/kels/positive` (15 vectors, each also as `/cesr1`) | 30 | 15 | 15 |
| `v1/keripy/negative/negative` | 84 | 67 | 17 |
| `v2/keripy/kels/positive` | 15 | 15 | 0 |
| `v2/keripy/negative/negative` | 11 | 6 | 5 |
| `v2/spec/examples` (52 vectors, 6 not checked) | 46 | 14 | 32 |
| total | 186 | 117 | 69 |

### Expected failures by cause

| Cause | Vectors | What keriox does | Specification section |
|---|---:|---|---|
| `cesr1` | 15 | It does not parse KERI 1.0 streams with CESR 1.0 attachment codes (`-A`, `-V`, ...). It reads only CESR 2.0 counters, so it cannot read keripy's KERI 1.0 output. | Version string field (a protocol version names its CESR genus version) |
| `native-cesr` | 12 | It does not support native CESR message bodies (Annex A examples). | Annex A, Native CESR Encodings of KERI Messages |
| `deleg` | 1 | Only the first couple of a source seal group is tried; the specification does not say what several couples mean. | Cooperative Delegation; Seals |
| `seal-types` | 10 | It has no source, latest establishment, registrar backer or typed seal. Its untagged seal type reads them as digest seals and drops their other fields, so an event seal with a malformed `i` is also read as a digest seal. | Seals; Seal Count Codes |
| `routed-v2` | 8 | It does not read KERI 2.0 `qry`/`rpy` as the specification prints them (with `i`, `/oobi` routes). The specification contradicts itself here: its declared field order has no `i`, but every example and keripy have one. | Query Message Body; Reply Message Body; OOBI sections |
| `key-event-rules` | 4 | Accepted although the specification forbids them:<br>- `kt=0`;<br>- `nt=0` with a rotation to unrelated keys;<br>- an unsatisfiable `nt`;<br>- a non-transferable prefix with `n`. | Rotation using pre-rotation; Key and key digest threshold fields; KERI's secure bindings |
| `pro-bar-xip` | 6 | There are no `pro`, `bar` or `xip` message types. | Routed Messages |
| `reply-bada` | 2 | The roles `registrar` and `mailbox` are not known. | BADA Policy; RUN off the CRUD; OOBI KERI Endpoint Authorization |
| `nested-threshold` | 5 | It does not read nested weighted thresholds (`{"1/2": [...]}`). | Fractionally weighted threshold |
| `config` | 1 | It does not enforce `RB` (registrar backers need registrar backer seals). | Configuration traits field |
| `key-state` | 2 | Key state notices in keripy's shape are not read; the specification defines no key state notice format. | Backer remove / add lists; Reply Message Body |
| `witness-role` | 1 | A witness accepts remote events: there is no notion of a local channel (a SHOULD-level rule). | Validator Roles and Event Locality |
| `exn-fields` | 2 | The specification's `exn` fields `[v,t,d,i,ri,x,p,dt,r,q,a]` are not read. | Exchange Message Body |

Some passes need care when reading them:

- A message keriox cannot read counts as rejected. `rm-ksn-sn-decimal/decimal`
  (a key state notice in keripy's shape) and the keripy-shaped `exn` vectors
  pass for that reason, not because keriox applies the check the vector is
  about.
- `endpoint-location-with-scheme-by-eid-update-rpy-json` (a url without a
  scheme, which must be refused) passes for the same reason: keriox does
  not read KERI 2.0 replies with `i`.
