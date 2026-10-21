#!/usr/bin/env python3
"""
Reads the vectors of another source with keripy, so that vectors written by
one implementation are confirmed by a second one before others rely on them.

Usage (see check.sh, which sets up the same venv as generate.sh):
    <venv>/bin/python -I check.py <v2/<source> dir> <expected file> [--bless]

Every vector is checked the way its kind allows:
  group, stream, migrate (V2 side)
      walked primitive by primitive with keripy's Counter, Indexer and
      Matter, in the text and binary domain; every count must cover its
      content exactly and both domains must hold the same primitives.
      Message bodies are loaded as Serders, which checks their SAIDs and
      version strings, and indexed controller signatures that follow a
      body are verified against the keys listed with the vector.
  saidify
      the SAID computed by keripy into the vector's labels.
  versionstring
      parsed with deversify.
  negative
      keripy must reject the input.
  kel
      the stream processed by keripy, escrows included, must leave exactly
      the events the vector lists for each identifier.

The outcomes are compared with the expected file, which lists every vector
keripy does not confirm and why, like the expected-failure lists of the
crates: a new disagreement and a listed one that went away both fail.
"""
import argparse
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from keri.kering import Vrsn_2_0, deversify, smell, sniff, Colds
from keri.core import coring
from keri.core.coring import Matter, Diger, Saider, Verfer
from keri.core.indexing import Indexer
from keri.core.counting import Counter
from keri.core.serdering import SerderKERI, SerderACDC

# groups whose items are indexed signatures
INDEXED = {"ControllerIdxSigs", "WitnessIdxSigs",
           "BigControllerIdxSigs", "BigWitnessIdxSigs"}
# groups whose content is itself a stream of groups and primitives
NESTING = {"GenericGroup", "BigGenericGroup", "AttachmentGroup", "BigAttachmentGroup",
           "BodyWithAttachmentGroup", "BigBodyWithAttachmentGroup",
           "GenericMapGroup", "BigGenericMapGroup", "GenericListGroup",
           "BigGenericListGroup", "MapBodyGroup", "BigMapBodyGroup",
           "FixBodyGroup", "BigFixBodyGroup"}
NON_NATIVE = {"NonNativeBodyGroup", "BigNonNativeBodyGroup"}


class Walk:
    """Primitives of a stream: (kind, qb64, qb2) per token."""

    def __init__(self, verkeys=None):
        self.tokens = []
        self.verkeys = verkeys or []
        self.body = None
        self.verified = 0

    def stream(self, ims: bytes):
        i = 0
        while i < len(ims):
            cold = sniff(ims[i:])
            if cold == Colds.msg:
                i += self.message(ims[i:])
            elif cold in (Colds.txt, Colds.bny):
                # groups right after a body, not wrapped in an attachment
                # group, are its attachments too
                i += self.counted(ims[i:], cold == Colds.txt, top=True,
                                  sigs_of_body=self.body is not None)
            else:
                raise ValueError(f"unexpected cold start {cold} at {i}")

    def message(self, ims: bytes) -> int:
        sm = smell(ims)
        raw = bytes(ims[:sm.size])
        if len(raw) != sm.size:
            raise ValueError("body shorter than its version string says")
        klas = SerderACDC if sm.proto == "ACDC" else SerderKERI
        klas(raw=raw)  # checks the SAID and the version string
        self.body = raw
        self.tokens.append(("body", raw, raw))
        return sm.size

    def primitive(self, klas, ims: bytes, txt: bool):
        p = klas(qb64b=ims) if txt else klas(qb2=ims)
        self.tokens.append((klas.__name__, p.qb64, p.qb2))
        return p, len(p.qb64) if txt else len(p.qb2)

    def counted(self, ims: bytes, txt: bool, top=False, sigs_of_body=False) -> int:
        """Reads a counted group or a lone primitive; returns its length."""
        if (ims[:1] == b"-") if txt else (ims[0] >> 2 == 0o76):
            ctr = Counter(qb64b=ims, version=Vrsn_2_0) if txt else \
                Counter(qb2=ims, version=Vrsn_2_0)
            head = len(ctr.qb64) if txt else len(ctr.qb2)
            self.tokens.append(("Counter", ctr.qb64, ctr.qb2))
            if ctr.name.endswith("GenusVersion"):
                return head
            size = ctr.count * (4 if txt else 3)
            content = ims[head:head + size]
            if len(content) != size:
                raise ValueError(f"{ctr.name} counts {ctr.count} quadlets, stream ends first")
            j = 0
            while j < size:
                rest = content[j:]
                if ctr.name in INDEXED:
                    sig, n = self.primitive(Indexer, rest, txt)
                    if sigs_of_body and self.verkeys and self.body is not None:
                        key = Verfer(qb64=self.verkeys[sig.index])
                        if not key.verify(sig.raw, self.body):
                            raise ValueError(f"signature {sig.index} does not verify")
                        self.verified += 1
                elif ctr.name in NON_NATIVE:
                    m, n = self.primitive(Matter, rest, txt)
                    # the enclosed body is what the attachments that follow sign
                    if self.message(m.raw) != len(m.raw):
                        raise ValueError("enclosed body has trailing bytes")
                else:
                    attachments = ctr.name in ("AttachmentGroup", "BigAttachmentGroup")
                    n = self.counted(rest, txt, sigs_of_body=attachments and top)
                if n <= 0:
                    raise ValueError("no progress")
                j += n
            if j != size:
                raise ValueError(f"{ctr.name} content overruns its count")
            return head + size
        _, n = self.primitive(Matter, ims, txt)
        return n

    def text(self) -> bytes:
        return b"".join(t[1] if t[0] == "body" else t[1].encode() if isinstance(t[1], str)
                        else t[1] for t in self.tokens)

    def binary(self) -> bytes:
        return b"".join(t[2] for t in self.tokens)


def check_group(v):
    text, binary = Walk(), Walk()
    text.stream(v["qb64"].encode())
    binary.stream(bytes.fromhex(v["qb2_hex"]))
    if text.binary() != bytes.fromhex(v["qb2_hex"]):
        raise ValueError("binary form differs from the text form")
    if binary.text().decode() != v["qb64"]:
        raise ValueError("text form differs from the binary form")


def check_stream(v):
    stream = v["stream"].encode() if v.get("stream") else bytes.fromhex(v["stream_hex"])
    walk = Walk(v.get("sigs_verkeys"))
    walk.stream(stream)
    # signatures over native bodies are not checked
    if v.get("sigs_verkeys") and walk.body is not None and walk.verified == 0:
        raise ValueError("no signature verified")


def check_migrate(v):
    Walk().stream(bytes.fromhex(v["v2_hex"]))


def check_saidify(v):
    kind, labels = v["kind"], v.get("labels") or [v["label"]]
    if "sad_in_json" not in v:
        # a complete message: keripy checks its SAID when it loads it
        serder = SerderKERI(raw=bytes.fromhex(v["raw_hex"]))
        if serder.said != v["said"]:
            raise ValueError(f"SAID {serder.said}")
        return
    sad = json.loads(v["sad_in_json"])
    if len(labels) == 1:
        saider, out = Saider.saidify(sad=sad, code=v["code"], kind=kind, label=labels[0])
        said = saider.qb64
    else:
        # a message that is its own identifier: keripy computes both fields
        # when it builds the message
        out = SerderKERI(sad=sad, makify=True, kind=kind).sad
        said = out[labels[0]]
    if said != v["said"]:
        raise ValueError(f"SAID {said}")
    if "sad_out_hex" in v and coring.dumps(out, kind=kind).hex() != v["sad_out_hex"]:
        raise ValueError("serialization differs")


def check_version(v):
    deversify(v["vs"])


def accepted(v) -> bool:
    target, inp = v["target"], v["input"]
    try:
        if target == "matter":
            m = Matter(qb64=inp)
            return len(m.qb64) == len(inp)
        if target == "indexer":
            Indexer(qb64=inp)
        elif target == "counter":
            c = Counter(qb64=inp, version=Vrsn_2_0)
            return len(c.qb64) == len(inp)
        elif target == "version":
            deversify(inp)
        elif target == "stream":
            Walk().stream(inp.encode())
        elif target == "said":
            SerderKERI(raw=inp.encode())
        else:
            raise SystemExit(f"unknown negative target {target}")
    except SystemExit:
        raise
    except Exception:
        return False
    return True


def check_negative(v):
    if accepted(v):
        raise ValueError("keripy accepts it")


def check_kel(v):
    from keri.app import habbing
    from keri.core import eventing, parsing
    with habbing.openHby(name="kelcheck", temp=True) as hby:
        kvy = eventing.Kevery(db=hby.db, lax=False, local=False)
        parsing.Parser(kvy=kvy, version=Vrsn_2_0).parse(ims=bytearray(v["stream"].encode()))
        for _ in range(3):
            kvy.processEscrows()
        for pre, events in v["kels"].items():
            got = [{"sn": e.sn, "said": e.said} for e in hby.db.getEvtPreIter(pre)]
            if got != events:
                raise ValueError(f"{pre}: keripy accepted {[e['sn'] for e in got]}, "
                                 f"vector lists {[e['sn'] for e in events]}")


CHECKS = {
    "group/1": check_group,
    "stream/1": check_stream,
    "migrate/1": check_migrate,
    "saidify/1": check_saidify,
    "versionstring/1": check_version,
    "negative/1": check_negative,
    "kel/1": check_kel,
}


def run(source_dir):
    results = {}
    for root, _, files in sorted(os.walk(source_dir)):
        for name in sorted(files):
            if name == "manifest.json" or not name.endswith(".json"):
                continue
            with open(os.path.join(root, name)) as f:
                data = json.load(f)
            check = CHECKS.get(data["schema"])
            for v in data["vectors"]:
                if check is None:
                    results[v["id"]] = f"not checked: no check for {data['schema']}"
                    continue
                try:
                    check(v)
                except Exception as ex:
                    msg = str(ex).splitlines()[0] if str(ex) else ""
                    results[v["id"]] = f"{type(ex).__name__}: {msg}"[:160]
                else:
                    results[v["id"]] = None
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("source_dir")
    ap.add_argument("expected")
    ap.add_argument("--bless", action="store_true",
                    help="rewrite the expected file from the current outcomes")
    args = ap.parse_args()
    results = run(args.source_dir)
    failing = {k: v for k, v in sorted(results.items()) if v is not None}
    source = os.path.basename(os.path.normpath(args.source_dir))
    print(f"{source}: {len(results) - len(failing)} of {len(results)} vectors confirmed by keripy")

    if args.bless:
        with open(args.expected, "w") as f:
            f.write(f"# Vectors of the {source} source that keripy does not confirm.\n"
                    "# Format: <vector id> TAB <why>. Rewrite with check.sh --bless.\n")
            for k, why in failing.items():
                f.write(f"{k}\t{why}\n")
        return

    expected = {}
    if os.path.exists(args.expected):
        with open(args.expected) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    k, _, why = line.rstrip("\n").partition("\t")
                    expected[k] = why
    report = [f"not confirmed: {k}: {why}" for k, why in failing.items() if k not in expected]
    report += [f"now confirmed, remove from list: {k}" for k in expected if k not in failing]
    if report:
        print("\n".join(report))
        sys.exit(1)


if __name__ == "__main__":
    main()
