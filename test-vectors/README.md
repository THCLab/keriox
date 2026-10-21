# CESR V2 interoperability vectors

`v2/` is a snapshot of the language-neutral test vectors kept in
[cesrox](https://github.com/THCLab/cesrox) under `test-vectors/v2`: vectors
written by keripy, by cesrox and said, and examples from the CESR
specification. `UPSTREAM` names the cesrox commit they were copied from and
`harness.rs` is cesrox's runner, copied with them.

`keriox_tests/tests/vectors.rs` runs them against keriox. cesrox already
checks the encoding itself, so these checks cover what keriox adds:

- its own key, digest, signature and seed types read every primitive and
  write it back, and indexed signatures keep their indexes;
- signature groups convert into keriox signatures and back;
- streams turn into messages, which a processor with the usual escrows
  accepts into the KEL under their own SAIDs, and keriox's encoding of
  them reads as the same messages;
- processing a key event log leaves exactly the events keripy accepted for
  each identifier, so an event keripy rejects (a borrowed SAID, a wrong
  prior digest, uncommitted keys, too few or foreign signatures, indexes
  out of range, a sequence gap, an unanchored delegation) is rejected too;
- streams in the format of cesrox before 2.0 read as their V2 form;
- the SAIDs of KERI messages and the digests keriox derives match;
- input the source rejects is rejected.

## Refreshing

```sh
test-vectors/sync.sh [path/to/cesrox]   # default ../cesrox; must be clean
cargo test -p keri-tests --test vectors
```

Review the diff of `v2/`, then rewrite the expected failures if the change
is intended:

```sh
CESR_VECTORS_BLESS=1 cargo test -p keri-tests --test vectors
```

## Expected failures

`keriox_tests/tests/vectors_expected_failures.txt` lists the vectors keriox
does not pass. The test fails when another vector fails and also when a
listed one starts to pass, so the list only shrinks. Its entries fall into
these groups:

| Vectors | Why |
|---|---|
| `*/CBOR/*`, `serder/KERI/*/CBOR` | said 2.0.0-rc.2 writes structs with flattened fields as indefinite-length CBOR maps, keripy as definite-length ones, so keriox cannot reproduce the bytes. Fixed in said after rc.2. |
| `keripy/indexer/ECDSA_256r1_*` | cesrox uses other codes for indexed P-256 signatures than keripy. |
| `keripy/indexer/Ed448_*/262143*` | keriox stores signature indexes as 16-bit numbers. |
| `keripy/kel/2/*` with a rotation, `keripy/stream/qry/json/lsgs` | keriox models KERI 1.0 bodies: a KERI 2.0 rotation carries configuration traits in `c` and a KERI 2.0 query the sender in `i`. Inceptions, interactions, delegated inceptions and receipts read in both versions. |
| `keripy/stream/icp/CESR/3sig` | Native CESR message bodies are not supported. |
| `keripy/neg/version/v2-unknown-proto` | said accepts any upper-case protocol code in a version string. |
| `keripy/stream/icp/json/framed`, `genusify` | Framing vectors with one of the two required signatures: keriox correctly keeps the event in the partially signed escrow. |
| `cesrox/stream/icp/JSON/big-attachments` | 190 signatures for three keys, to exercise big counters: correctly rejected. |
| `cesrox/stream/native/generic-map`, `spec/stream/example/trans-indexed-sig-groups` | Not KERI messages (a generic map, attachments without a message): correctly rejected. |
