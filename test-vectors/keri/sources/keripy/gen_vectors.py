#!/usr/bin/env python3
"""
KERI protocol test vectors generated with keripy.

Usage (see generate.sh, which pins keripy and sets up the venv):
    <venv>/bin/python -I gen_vectors.py <out_dir> --keripy-rev <git rev>

Writes   <out_dir>/v1/keripy/{kels/positive.json, negative/negative.json,
                              negative/edge.json, manifest.json}
         <out_dir>/v2/keripy/{...same layout, KERI 2.0 bodies...}

Every file is a JSON object:
    {"schema": "<kind>/1", "generator": {...}, "vectors": [ {...}, ... ]}

Every vector carries its messages twice: `stream` with CESR 2.0 attachment
codes and `stream_cesr1` with CESR 1.0 attachment codes (what KERI 1.0
deployments of keripy write). Both are replayed through keripy and must
give the same result.

The KERI specification is the target. Where keripy and the specification
disagree, `expected` and `kels` follow the specification and `keripy`
records what keripy actually does. Such vectors are also written to
negative/edge.json.

Vectors are deterministic: every key is derived from a fixed label, every
date-time is fixed, so reruns produce byte-identical output for the same
keripy revision.
"""
import argparse
import copy
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import logging
logging.disable(logging.CRITICAL)

from keri import kering
from keri.kering import Vrsn_1_0, Vrsn_2_0, Kinds, Protocols, versify
from keri.core import eventing, parsing, routing, signing, coring
from keri.core.coring import MtrDex, Diger, Number, Prefixer
from keri.core.indexing import Siger, IdrDex
from keri.core.signing import Cigar
from keri.core.structing import SealEvent, SealSource
from keri.app import habbing
from keri.help import helping

GEN_VERSION = "1.0.0"
SPEC = {"repository": "https://github.com/trustoverip/kswg-keri-specification",
        "commit": "fbdd4a6155e48248873cccd5cf6f79b6b631a021"}

V1, V2 = Vrsn_1_0, Vrsn_2_0
STAMP = "2020-08-21T17:52:11.000000+00:00"   # fixed date-times
STAMPS = ["2020-08-21T17:52:%02d.000000+00:00" % s for s in range(60)]


def det_bytes(label: str, n: int) -> bytes:
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha512(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]


_SIGNERS = {}


def S(name, trans=True):
    """The signer named `name` (transferable key code D, or B when not)."""
    key = (name, trans)
    if key not in _SIGNERS:
        _SIGNERS[key] = signing.Signer(raw=det_bytes(f"keri-vectors/{name}", 32),
                                       transferable=trans)
    return _SIGNERS[key]


def W(name):
    """A witness: non-transferable signer."""
    return S(name, trans=False)


def keys(ss):
    return [s.verfer.qb64 for s in ss]


def dig(s):
    return Diger(ser=s.verfer.qb64b).qb64


def digs(ss):
    return [dig(s) for s in ss]


def junk_sig(label):
    return det_bytes(f"keri-vectors/junk/{label}", 64)


# --------------------------------------------------------------------------
# bodies
# --------------------------------------------------------------------------

def dumps(sad):
    return json.dumps(sad, separators=(",", ":"), ensure_ascii=False).encode()


def saidify(sad, pvrsn, labels=("d",), proto=Protocols.keri):
    """`sad` (field order kept) with its version string sized and the fields
    in `labels` set to the Blake3-256 SAID of the result. Builds bodies
    keripy refuses to build."""
    sad = dict(sad)
    gv = V2 if pvrsn.major >= 2 else None
    for label in labels:
        sad[label] = "#" * 44
    sad["v"] = versify(proto=proto, pvrsn=pvrsn, kind=Kinds.json, size=0, gvrsn=gv)
    size = len(dumps(sad))
    sad["v"] = versify(proto=proto, pvrsn=pvrsn, kind=Kinds.json, size=size, gvrsn=gv)
    said = Diger(ser=dumps(sad), code=MtrDex.Blake3_256).qb64
    for label in labels:
        sad[label] = said
    return Body(dumps(sad))


class Body:
    """A message body that keripy may refuse to load."""

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.sad = json.loads(self.raw)

    @property
    def said(self):
        return self.sad["d"]

    @property
    def pre(self):
        return self.sad["i"]

    @property
    def keys(self):
        return self.sad["k"]

    @property
    def ndigs(self):
        return self.sad["n"]


def remake(serder, pvrsn, labels=None, **changes):
    """A body like `serder` with `changes` applied (None deletes a field;
    new fields go before `after` when given as (value, after_label))."""
    sad = copy.deepcopy(serder.sad)
    for k, v in changes.items():
        if v is None:
            sad.pop(k, None)
        else:
            sad[k] = v
    if labels is None:
        labels = ("d", "i") if sad.get("t") in ("icp", "dip") and sad["i"] == sad["d"] else ("d",)
    return saidify(sad, pvrsn, labels)


# --------------------------------------------------------------------------
# messages: a body with attachments, rendered with CESR 1.0 or 2.0 codes
# --------------------------------------------------------------------------

def _standin(pvrsn):
    return eventing.interact(pre=S("standin").verfer.qb64, dig=S("standin").verfer.qb64,
                             sn=1, pvrsn=pvrsn, kind=Kinds.json)


class Msg:
    def __init__(self, body, fix=None, atc_raw=None, **atc):
        """`body` is a SerderKERI or Body; `atc` are messagize arguments;
        `fix(text) -> text` edits the rendered attachments (for attachments
        messagize refuses to write); `atc_raw(gv) -> bytes` writes them
        instead of messagize."""
        self.body = body
        self.atc = atc
        self.fix = fix
        self.atc_raw = atc_raw

    def attachments(self, gv):
        return self.render(gv)[len(self.body.raw):]

    def render(self, gv):
        raw = bytes(self.body.raw)
        if self.atc_raw is not None:
            return raw + self.atc_raw(gv)
        if not self.atc:
            return raw
        standin = _standin(V1)
        att = bytes(eventing.messagize(standin, gvrsn=gv, **self.atc))[len(standin.raw):]
        if self.fix:
            att = self.fix(att.decode()).encode()
        return raw + att


def stream(msgs, gv):
    return b"".join(m.render(gv) for m in msgs)


def sign(body, signers, *, k=None, prior=None, raw=None, indexes=None):
    """Indexed signatures of `signers` over `body`. With `k` each index is
    the signer's position in `k`; with `prior` (the prior next digests) the
    other index is its position there (current-only signature when absent)."""
    raw = bytes(raw if raw is not None else body.raw)
    out = []
    for n, s in enumerate(signers):
        if indexes is not None:
            idx = indexes[n]
        elif k is not None:
            idx = k.index(s.verfer.qb64)
        else:
            idx = n
        if prior is not None:
            d = dig(s)
            if d in prior:
                out.append(s.sign(ser=raw, index=idx, ondex=prior.index(d)))
            else:
                out.append(s.sign(ser=raw, index=idx, only=True))
        else:
            out.append(s.sign(ser=raw, index=idx))
    return out


def junk_siger(index, label, ondex=None):
    if ondex is None:
        return Siger(raw=junk_sig(label), code=IdrDex.Ed25519_Sig, index=index)
    return Siger(raw=junk_sig(label), code=IdrDex.Ed25519_Big_Sig, index=index, ondex=ondex)


def wsign(body, witnesses, wits):
    """Indexed witness signatures, each at the witness's position in `wits`."""
    return [w.sign(ser=bytes(body.raw), index=wits.index(w.verfer.qb64))
            for w in witnesses]


def rct(body, witnesses, pvrsn):
    """A receipt of `body` with a non-transferable receipt couple per witness."""
    r = eventing.receipt(pre=body.pre, sn=int(body.sad["s"], 16), said=body.said,
                         pvrsn=pvrsn, kind=Kinds.json)
    return Msg(r, cigars=[w.sign(ser=bytes(body.raw)) for w in witnesses])


def vrc(body, validator_icp, validator_signers, pvrsn):
    """A transferable receipt of `body` by the validator incepted with
    `validator_icp`."""
    r = eventing.receipt(pre=body.pre, sn=int(body.sad["s"], 16), said=body.said,
                         pvrsn=pvrsn, kind=Kinds.json)
    sigers = sign(body, validator_signers)
    tsg = (Prefixer(qb64=validator_icp.pre), Number(num=0),
           Diger(qb64=validator_icp.said), sigers)
    return Msg(r, tsgs=[tsg])


# --------------------------------------------------------------------------
# keripy replay
# --------------------------------------------------------------------------

def replay(msgs, prefixes, gv, extra=None):
    """What keripy accepts from the messages: the key events per identifier
    in sn order and the resulting key state, after its escrows have run.
    `extra(hby, kvy, rvy)` adds further observations."""
    with habbing.openHby(name="kerivec", temp=True) as hby:
        rtr = routing.Router()
        rvy = routing.Revery(db=hby.db, rtr=rtr, lax=False)
        kvy = eventing.Kevery(db=hby.db, lax=False, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        from keri.peer import exchanging
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        parser = parsing.Parser(kvy=kvy, rvy=rvy, exc=exc,
                                version=V2 if gv.major >= 2 else V1)
        for m in msgs:   # one message at a time so that one bad message
            try:         # does not stop the rest of the stream
                parser.parse(ims=bytearray(m.render(gv)))
            except Exception:
                pass
            for _ in range(2):
                kvy.processEscrows()
                rvy.processEscrowReply()
        for _ in range(3):
            kvy.processEscrows()
            rvy.processEscrowReply()
        out = {"kels": {}}
        for pre in prefixes:
            events = [{"sn": s.sn, "t": s.ilk, "d": s.said}
                      for s in hby.db.getEvtPreIter(pre)]
            kever = kvy.kevers.get(pre)
            state = None
            if kever is not None:
                state = {"s": kever.sner.numh, "d": kever.serder.said,
                         "kt": kever.tholder.sith, "k": [v.qb64 for v in kever.verfers],
                         "nt": kever.ntholder.sith if kever.ntholder else "0",
                         "n": [d.qb64 for d in kever.ndigers],
                         "bt": kever.toader.numh, "b": list(kever.wits)}
            out["kels"][pre] = {"events": events, "state": state}
        if extra:
            out.update(extra(hby, kvy, rvy))
        return out


def is_v2(msgs):
    return any(m.body.sad.get("v", "").startswith(("KERIC", "ACDCC")) for m in msgs)


def replay_both(msgs, prefixes, extra=None, name=""):
    a = replay(msgs, prefixes, V2, extra)
    if is_v2(msgs):
        return a   # KERI 2.0 bodies: CESR 2.0 attachments only
    b = replay(msgs, prefixes, V1, extra)
    if a != b:
        sys.exit(f"{name}: keripy gives different results for CESR 1.0 and 2.0 "
                 f"attachments:\n{json.dumps(a)}\n{json.dumps(b)}")
    return a


def events_of(*bodies):
    return [{"sn": int(b.sad["s"], 16), "t": b.sad["t"], "d": b.said} for b in bodies]


def streams(msgs):
    out = {"stream": stream(msgs, V2).decode()}
    if not is_v2(msgs):
        out["stream_cesr1"] = stream(msgs, V1).decode()
    return out


def receipt_counts(pairs):
    """Observation: per (prefix, event SAID) the number of controller
    signatures, witness signatures, non-transferable receipt couples and
    transferable receipts keripy stored."""
    def extra(hby, kvy, rvy):
        db = hby.db
        out = {}
        for pre, said in pairs:
            keys = (pre, said)
            out[said] = {"sigs": len(db.sigs.get(keys=keys)),
                         "wigs": len(db.wigs.get(keys=keys)),
                         "rcts": len(db.rcts.get(keys=keys)),
                         "vrcs": len(list(db.vrcs.getTopItemIter(keys=keys)))}
        return {"stored": out}
    return extra


# --------------------------------------------------------------------------
# positive key event logs
# --------------------------------------------------------------------------

def ev(pv, fn, *a, **kwa):
    return fn(*a, pvrsn=pv, kind=Kinds.json, **kwa)


def gen_positive(pv):
    """Key event logs every validator must accept."""
    vecs = []
    pvname = f"{pv.major}.{pv.minor}"

    def add(vid, description, msgs, expect, spec_section, receipts=None):
        prefixes = list(expect)
        got = replay_both(msgs, prefixes, receipt_counts(receipts) if receipts else None,
                          name=vid)
        for pre, bodies in expect.items():
            want = events_of(*bodies)
            if got["kels"][pre]["events"] != want:
                sys.exit(f"{vid}: keripy accepted {got['kels'][pre]['events']} "
                         f"for {pre}, intended {want}")
        kels = {}
        for pre in prefixes:
            st = got["kels"][pre]["state"]
            kels[pre] = {"events": got["kels"][pre]["events"],
                         "sn": None if st is None else int(st["s"], 16),
                         "state": st}
        v = {"id": f"kel/{vid}", "description": description, "pvrsn": pvname,
             "spec_section": spec_section}
        v.update(streams(msgs))
        v["kels"] = kels
        if receipts:
            v["stored"] = got["stored"]
        vecs.append(v)

    # -- inception ----------------------------------------------------------
    # non-transferable basic prefix: the prefix is the key, no next keys
    nt = S("nontrans", trans=False)
    icp = ev(pv, eventing.incept, keys=[nt.verfer.qb64], code=MtrDex.Ed25519N)
    ixn = ev(pv, eventing.interact, pre=icp.pre, dig=icp.said, sn=1)
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=[nt.verfer.qb64], dig=icp.said, sn=1,
             isith="1", ndigs=[], nsith="0")
    add("icp/nontransferable",
        "inception of a non-transferable basic prefix (Ed25519N code, n=[]); an "
        "interaction and a rotation after it are dropped",
        [Msg(icp, sigers=sign(icp, [nt])), Msg(ixn, sigers=sign(ixn, [nt])),
         Msg(rot, sigers=sign(rot, [nt]))],
        {icp.pre: [icp]}, "Inception Event Message Body; Basic prefix derivation")

    # transferable basic prefix: the prefix is the single key
    a = [S(f"basic/{i}") for i in range(3)]
    icp = ev(pv, eventing.incept, keys=keys(a[:1]), isith="1", ndigs=digs(a[1:2]), nsith="1",
             code=MtrDex.Ed25519)
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(a[1:2]), dig=icp.said, sn=1,
             isith="1", ndigs=digs(a[2:3]), nsith="1")
    add("icp/basic-transferable",
        "inception of a transferable basic prefix (Ed25519 code, the prefix is the key) "
        "and a rotation to the pre-rotated key",
        [Msg(icp, sigers=sign(icp, a[:1])),
         Msg(rot, sigers=sign(rot, a[1:2], k=rot.keys, prior=icp.ndigs))],
        {icp.pre: [icp, rot]}, "Inception Event Message Body; Rotation using pre-rotation")

    # self-addressing single key
    s = [S(f"single/{i}") for i in range(4)]
    icp = ev(pv, eventing.incept, keys=keys(s[:1]), isith="1", ndigs=digs(s[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    ixn = ev(pv, eventing.interact, pre=icp.pre, dig=icp.said, sn=1,
             data=[{"d": Diger(ser=b"anchored").qb64}])
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(s[1:2]), dig=ixn.said, sn=2,
             isith="1", ndigs=digs(s[2:3]), nsith="1")
    rot2 = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(s[2:3]), dig=rot.said, sn=3,
              isith="1", ndigs=digs(s[3:4]), nsith="1")
    ixn2 = ev(pv, eventing.interact, pre=icp.pre, dig=rot2.said, sn=4,
              data=[SealEvent(i=icp.pre, s="3", d=rot2.said)._asdict()])
    single = [Msg(icp, sigers=sign(icp, s[:1])), Msg(ixn, sigers=sign(ixn, s[:1])),
              Msg(rot, sigers=sign(rot, s[1:2], k=rot.keys, prior=icp.ndigs)),
              Msg(rot2, sigers=sign(rot2, s[2:3], k=rot2.keys, prior=rot.ndigs)),
              Msg(ixn2, sigers=sign(ixn2, s[2:3]))]
    add("icp/self-addressing",
        "self-addressing inception with one key, interaction anchoring a digest seal, "
        "two rotations, interaction anchoring an event seal",
        single, {icp.pre: [icp, ixn, rot, rot2, ixn2]},
        "Inception Event Message Body; Interaction Event Message Body; Seals")
    add("order/reversed",
        "the same log delivered last event first: escrowed out of order until the "
        "inception arrives", list(reversed(single)), {icp.pre: [icp, ixn, rot, rot2, ixn2]},
        "Out-of-order events")

    # multisig
    m = [S(f"multi/{i}") for i in range(9)]
    icp = ev(pv, eventing.incept, keys=keys(m[:3]), isith="2", ndigs=digs(m[3:6]), nsith="2")
    ixn = ev(pv, eventing.interact, pre=icp.pre, dig=icp.said, sn=1)
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(m[3:6]), dig=ixn.said, sn=2,
             isith="2", ndigs=digs(m[6:9]), nsith="2")
    add("icp/multisig",
        "self-addressing inception with 3 keys and threshold 2 signed by all three, an "
        "interaction signed by keys 1 and 2, a rotation signed by next keys 0 and 2",
        [Msg(icp, sigers=sign(icp, m[:3])), Msg(ixn, sigers=sign(ixn, m[1:3], k=icp.keys)),
         Msg(rot, sigers=sign(rot, [m[3], m[5]], k=rot.keys, prior=icp.ndigs))],
        {icp.pre: [icp, ixn, rot]}, "Indexed Signatures; Rotation using pre-rotation")

    # -- rotations ------------------------------------------------------------
    p = [S(f"partial/{i}") for i in range(7)]
    icp = ev(pv, eventing.incept, keys=keys(p[:3]), isith="2", ndigs=digs(p[3:6]), nsith="2")
    # partial rotation: expose next keys 3 and 5; key 4 stays unexposed and
    # is committed again in the new next list
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys([p[3], p[5]]), dig=icp.said, sn=1,
             isith="2", ndigs=digs([p[6], p[4]]), nsith="1")
    rot2 = ev(pv, eventing.rotate, pre=icp.pre, keys=keys([p[4]]), dig=rot.said, sn=2,
              isith="1", ndigs=digs([p[0]]), nsith="1")
    add("rot/partial",
        "partial rotation: 2 of 3 pre-rotated keys exposed, the third committed again "
        "and exposed in the next rotation from position 1 of the prior next list",
        [Msg(icp, sigers=sign(icp, p[:3])),
         Msg(rot, sigers=sign(rot, [p[3], p[5]], k=rot.keys, prior=icp.ndigs)),
         Msg(rot2, sigers=sign(rot2, [p[4]], k=rot2.keys, prior=rot.ndigs))],
        {icp.pre: [icp, rot, rot2]}, "Partial pre-rotation; Rotation using pre-rotation")

    # augmented rotation: a new key that was not pre-rotated joins
    g = [S(f"augment/{i}") for i in range(4)]
    icp = ev(pv, eventing.incept, keys=keys(g[:1]), isith="1", ndigs=digs(g[1:2]), nsith="1")
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(g[1:3]), dig=icp.said, sn=1,
             isith="2", ndigs=digs(g[3:4]), nsith="1")
    add("rot/augmented",
        "augmented rotation: the new key list adds a key that was not pre-rotated; it "
        "signs with a current-only signature, the exposed key with both indexes",
        [Msg(icp, sigers=sign(icp, g[:1])),
         Msg(rot, sigers=sign(rot, g[1:3], k=rot.keys, prior=icp.ndigs))],
        {icp.pre: [icp, rot]}, "Rotation using pre-rotation; Partial pre-rotation")

    # reserve rotation: the specification's worked example
    A = [S(f"reserve/A{i}") for i in range(32)]
    h, q, z = "1/2", "1/4", "0"
    table = [  # (current keys, current sith, next keys, next sith, signers)
        ([0, 1, 2, 3, 4], [h, h, h, q, q], [5, 6, 7, 8, 9], [h, h, h, q, q], [0, 1, 2, 3, 4]),
        ([5, 6, 7], [h, h, h], [10, 11, 12, 8, 9], [h, h, h, q, q], [5, 6, 7]),
        ([10, 8, 9], [h, h, h], [13, 14, 15, 16, 17], [h, h, h, q, q], [10, 8, 9]),
        ([13, 14, 15], [h, h, h], [18, 19, 20, 16, 17], [h, h, h, q, q], [13, 14, 15]),
        ([18, 20, 21], [h, h, h], [22, 23, 24, 16, 17], [h, h, h, q, q], [18, 20, 21]),
        ([22, 25, 26, 16, 17], [h, h, h, z, z], [27, 28, 29, 30, 31], [h, h, h, q, q],
         [22, 25, 26, 16, 17]),
    ]
    add("rot/reserve-spec-example",
        "the specification's reserve rotation example: reserve keys A8/A9 and A16/A17 "
        "held unexposed across rotations, then pulled out of reserve; A16/A17 get "
        "current weight 0",
        *table_kel(pv, A, table), "Reserve rotation")

    C = [S(f"custodial/A{i}") for i in range(18)]
    table = [
        ([0, 1, 2], [h, h, h], [3, 4, 5], [h, h, h], [0, 1, 2]),
        ([3, 4, 5, 6, 7, 8], [z, z, z, h, h, h], [9, 10, 11], [h, h, h], [3, 4, 6, 7]),
        ([9, 10, 11, 12, 13, 14], [z, z, z, h, h, h], [15, 16, 17], [h, h, h],
         [10, 11, 13, 14]),
    ]
    add("rot/custodial-spec-example",
        "the specification's custodial rotation example: the owner's pre-rotated keys "
        "get current weight 0, two of them sign for the prior next threshold and two "
        "custodial keys for the current one",
        *table_kel(pv, C, table), "Custodial Rotation")

    # -- witnesses ------------------------------------------------------------
    w1, w2, w3 = W("w1"), W("w2"), W("w3")
    c = [S(f"witnessed/{i}") for i in range(3)]
    wits = keys([w1, w2])
    icp = ev(pv, eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=wits, toad=2)
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
             isith="1", ndigs=digs(c[2:3]), nsith="1", toad=2, wits=wits,
             cuts=[w1.verfer.qb64], adds=[w3.verfer.qb64])
    wits2 = [w2.verfer.qb64, w3.verfer.qb64]
    ixn = ev(pv, eventing.interact, pre=icp.pre, dig=rot.said, sn=2)
    add("wit/indexed-cuts-adds",
        "witnessed inception (b=[W1,W2], bt=2) with indexed witness signatures; a "
        "rotation cutting W1 and adding W3 (new list [W2,W3]) and an interaction, each "
        "with the signatures of the new witness list",
        [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1, w2], wits)),
         Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
             wigers=wsign(rot, [w2, w3], wits2)),
         Msg(ixn, sigers=sign(ixn, c[1:2]), wigers=wsign(ixn, [w2, w3], wits2))],
        {icp.pre: [icp, rot, ixn]}, "Backer remove list; Backer add list; Indexed signatures")

    add("wit/receipts",
        "witnessed inception (b=[W1,W2], bt=2) without attached witness signatures, "
        "followed by a receipt (rct with a non-transferable receipt couple) from each "
        "witness",
        [Msg(icp, sigers=sign(icp, c[:1])), rct(icp, [w1], pv), rct(icp, [w2], pv)],
        {icp.pre: [icp]}, "Receipt Message Body; Witness receipts",
        receipts=[(icp.pre, icp.said)])

    # transferable receipt by a validator with its own KEL
    v = [S(f"validator/{i}") for i in range(2)]
    vicp = ev(pv, eventing.incept, keys=keys(v[:1]), isith="1", ndigs=digs(v[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    o = [S(f"receipted/{i}") for i in range(2)]
    oicp = ev(pv, eventing.incept, keys=keys(o[:1]), isith="1", ndigs=digs(o[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    add("rct/transferable",
        "a transferable receipt: a validator with its own KEL receipts an inception "
        "with a transferable indexed signature group referencing its establishment event",
        [Msg(vicp, sigers=sign(vicp, v[:1])), Msg(oicp, sigers=sign(oicp, o[:1])),
         vrc(oicp, vicp, v[:1], pv)],
        {vicp.pre: [vicp], oicp.pre: [oicp]}, "Receipt Message Body",
        receipts=[(oicp.pre, oicp.said)])

    # -- delegation -----------------------------------------------------------
    dr = [S(f"delegator/{i}") for i in range(3)]
    de = [S(f"delegate/{i}") for i in range(3)]
    dor = ev(pv, eventing.incept, keys=keys(dr[:1]), isith="1", ndigs=digs(dr[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    dip = ev(pv, eventing.delcept, keys=keys(de[:1]), delpre=dor.pre, isith="1",
             ndigs=digs(de[1:2]), nsith="1")
    dixn = ev(pv, eventing.interact, pre=dor.pre, dig=dor.said, sn=1,
              data=[SealEvent(i=dip.pre, s="0", d=dip.said)._asdict()])
    drt = ev(pv, eventing.deltate, pre=dip.pre, keys=keys(de[1:2]), dig=dip.said, sn=1,
             isith="1", ndigs=digs(de[2:3]), nsith="1")
    drot = ev(pv, eventing.rotate, pre=dor.pre, keys=keys(dr[1:2]), dig=dixn.said, sn=2,
              isith="1", ndigs=digs(dr[2:3]), nsith="1",
              data=[SealEvent(i=drt.pre, s="1", d=drt.said)._asdict()])
    deleg = [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
             Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="1", d=dixn.said)]),
             Msg(drot, sigers=sign(drot, dr[1:2], k=drot.keys, prior=dor.ndigs)),
             Msg(drt, sigers=sign(drt, de[1:2], k=drt.keys, prior=dip.ndigs),
                 bonds=[SealSource(s="2", d=drot.said)])]
    add("deleg/dip-drt",
        "delegated inception anchored by a delegator interaction, delegated rotation "
        "anchored by a delegator rotation; each delegated event carries a source seal "
        "couple pointing at the anchoring event",
        deleg, {dor.pre: [dor, dixn, drot], dip.pre: [dip, drt]},
        "Cooperative Delegation; Delegated Inception Event Message Body; "
        "Delegated Rotation Event Message Body")
    add("deleg/dip-before-anchor",
        "the delegated events arrive before the delegator's anchoring events: escrowed "
        "until the anchors arrive",
        [deleg[0], deleg[2], deleg[4], deleg[1], deleg[3]],
        {dor.pre: [dor, dixn, drot], dip.pre: [dip, drt]}, "Cooperative Delegation")

    # -- abandonment ----------------------------------------------------------
    b = [S(f"abandon/{i}") for i in range(3)]
    icp = ev(pv, eventing.incept, keys=keys(b[:1]), isith="1", ndigs=digs(b[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    rot = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(b[1:2]), dig=icp.said, sn=1,
             isith="1", ndigs=[], nsith="0")
    ixn = ev(pv, eventing.interact, pre=icp.pre, dig=rot.said, sn=2)
    rot2 = ev(pv, eventing.rotate, pre=icp.pre, keys=keys(b[2:3]), dig=rot.said, sn=2,
              isith="1", ndigs=digs(b[:1]), nsith="1")
    add("abandon/rot-to-empty-next",
        "abandonment: a rotation to n=[] and nt=0; a later interaction signed by the "
        "current key and a later rotation are dropped",
        [Msg(icp, sigers=sign(icp, b[:1])),
         Msg(rot, sigers=sign(rot, b[1:2], k=rot.keys, prior=icp.ndigs)),
         Msg(ixn, sigers=sign(ixn, b[1:2])), Msg(rot2, sigers=sign(rot2, b[2:3]))],
        {icp.pre: [icp, rot]}, "Rotation Event Message Body; Next key digest list")

    return {"kels/positive.json": ("keri-kel/1", vecs)}


def table_kel(pv, A, table):
    """A KEL following a table of (current, sith, next, nsith, signers)."""
    msgs, bodies = [], []
    prev = None
    for sn, (cur, sith, nxt, nsith, signers) in enumerate(table):
        ks = keys([A[i] for i in cur])
        nd = digs([A[i] for i in nxt])
        if prev is None:
            body = ev(pv, eventing.incept, keys=ks, isith=sith, ndigs=nd, nsith=nsith)
            sigers = sign(body, [A[i] for i in signers], k=ks)
        else:
            body = ev(pv, eventing.rotate, pre=prev.pre, keys=ks, dig=prev.said, sn=sn,
                      isith=sith, ndigs=nd, nsith=nsith)
            sigers = sign(body, [A[i] for i in signers], k=ks, prior=prev.ndigs)
        msgs.append(Msg(body, sigers=sigers))
        bodies.append(body)
        prev = body
    return msgs, {bodies[0].pre: bodies}


# --------------------------------------------------------------------------
# negative vectors: what a validator must reject (or, for gaps whose
# specification outcome is acceptance, must still accept)
# --------------------------------------------------------------------------

def keripy_loads(raw):
    """Whether keripy's SerderKERI loads (and verifies) the body."""
    from keri.core.serdering import SerderKERI
    try:
        SerderKERI(raw=bytes(raw))
        return True
    except Exception:
        return False


def routed_state(rpys=(), exns=(), ends=(), locs=()):
    """Observation of routed messages: which replies and exchanges keripy
    accepted, and the endpoint records they left."""
    def extra(hby, kvy, rvy):
        db = hby.db
        out = {}
        if rpys:
            out["replies"] = {s: db.rpys.get(keys=(s,)) is not None for s in rpys}
        if exns:
            out["exchanges"] = {s: db.exns.get(keys=(s,)) is not None for s in exns}
        if ends:
            out["ends"] = []
            for cid, role, eid in ends:
                rec = db.ends.get(keys=(cid, role, eid))
                out["ends"].append({"cid": cid, "role": role, "eid": eid,
                                    "allowed": None if rec is None else bool(rec.allowed)})
        if locs:
            out["locs"] = []
            for eid, scheme in locs:
                rec = db.locs.get(keys=(eid, scheme))
                out["locs"].append({"eid": eid, "scheme": scheme,
                                    "url": None if rec is None else rec.url})
        return out
    return extra


def combine(*extras):
    extras = [e for e in extras if e]
    if not extras:
        return None

    def extra(hby, kvy, rvy):
        out = {}
        for e in extras:
            out.update(e(hby, kvy, rvy))
        return out
    return extra


def duplicity_state(pre):
    def extra(hby, kvy, rvy):
        db = hby.db
        return {"likely_duplicitous": [{"sn": sn, "d": bytes(d).decode() if not isinstance(d, str) else d}
                                       for _, sn, d in db.ldes.getAllItemIter(keys=pre)]}
    return extra


class NegGen:
    def __init__(self, pv, gaps):
        self.pv = pv
        self.pvname = f"{pv.major}.{pv.minor}"
        self.gaps = gaps
        self.vecs = []

    def ev(self, fn, *a, **kwa):
        return fn(*a, pvrsn=self.pv, kind=Kinds.json, **kwa)

    def add(self, vid, description, msgs, expect, *, targets, expected, reason,
            spec_section=None, gap=None, ambiguity=None, target="kel", extra=None,
            spec_expect=None, keripy_note=None, check=None, review=None):
        """`expect` maps each prefix to the bodies a validator must have
        accepted after processing `msgs`; `targets` are the SAIDs whose
        acceptance the vector is about; `expected` is "accept" or "reject"
        for them. `spec_expect` adds further expectations (replies, endpoint
        records); `check(got)` turns keripy's observation into its outcome
        when the targets are not key events."""
        g = self.gaps.get(gap) if gap else None
        if g and spec_section is None:
            spec_section = g["spec_section"]
        prefixes = list(expect)
        got = replay_both(msgs, prefixes, extra, name=vid)
        if check is not None:
            kp = check(got)
        elif targets:
            accepted = {e["d"] for k in got["kels"].values() for e in k["events"]}
            hits = [t in accepted for t in targets]
            kp = "accepts" if all(hits) else ("rejects" if not any(hits) else "partial")
        else:  # nothing new may be accepted
            same = all(got["kels"][p]["events"] == events_of(*b) for p, b in expect.items())
            kp = "rejects" if same else "accepts"
        want = "accepts" if expected == "accept" else "rejects"
        agrees = kp == want and all(got["kels"][p]["events"] == events_of(*b)
                                    for p, b in expect.items())
        spec_expect = spec_expect or {}
        if "duplicity" in spec_expect:
            seen = [e["d"] for e in got.get("likely_duplicitous", [])]
            agrees = agrees and seen == spec_expect["duplicity"]["evidence"]
        if "witnesses" in spec_expect:
            for p, wl in spec_expect["witnesses"].items():
                st = got["kels"][p]["state"]
                agrees = agrees and st is not None and st["b"] == wl
        for key in ("locs", "ends"):
            if key in spec_expect:
                agrees = agrees and got.get(key) == spec_expect[key]
        if "key_state" in spec_expect and "ksn" in got:
            ks, want_ks = got["ksn"] or {}, spec_expect["key_state"]
            agrees = agrees and all(ks.get(f) == want_ks[f] for f in ("s", "d", "et", "b", "ee"))
        v = {"id": vid, "description": description, "pvrsn": self.pvname,
             "target": target}
        if gap:
            v["gap"] = gap
            v["gap_kind"] = g["kind"]
        v.update(streams(msgs))
        v["expected"] = expected
        v["targets"] = list(targets)
        v["kels"] = {p: {"events": events_of(*b)} for p, b in expect.items()}
        if spec_expect:
            v.update(spec_expect)
        v["reason"] = reason
        v["spec_section"] = spec_section
        if g:
            v["spec_quote"] = g["spec_quote"]
        if ambiguity:
            v["spec_ambiguous"] = True
            v["ambiguity"] = ambiguity
        kpv = {"outcome": kp, "agrees_with_spec": agrees,
               "kels": {p: got["kels"][p]["events"] for p in prefixes}}
        if "witnesses" in spec_expect:
            kpv["witnesses"] = {p: (got["kels"][p]["state"] or {}).get("b")
                                for p in spec_expect["witnesses"]}
        for key in ("replies", "exchanges", "ends", "locs", "stored", "likely_duplicitous",
                    "ksn", "knas"):
            if key in got:
                kpv[key] = got[key]
        if keripy_note:
            kpv["note"] = keripy_note
        if review is None and g and g.get("keripy_expected") in ("accept", "reject"):
            review = g["keripy_expected"] + "s"
        if review:
            kpv["review_expected"] = review
        v["keripy"] = kpv
        self.vecs.append(v)
        return v


def try_build(build, fallback):
    """keripy's builder when it builds the event, else `fallback()`."""
    try:
        return build()
    except Exception:
        return fallback()


def neg_classic(g):
    """The classic rejections and the rules already enforced by keriox."""
    ev = g.ev
    c = [S(f"classic/{i}") for i in range(6)]
    icp = ev(eventing.incept, keys=keys(c[:2]), isith="2", ndigs=digs(c[2:4]), nsith="2",
             code=MtrDex.Blake3_256)
    pre = icp.pre
    rot = ev(eventing.rotate, pre=pre, keys=keys(c[2:4]), dig=icp.said, sn=1, isith="2",
             ndigs=digs(c[4:6]), nsith="2")
    ixn = ev(eventing.interact, pre=pre, dig=rot.said, sn=2, data=[{"d": Diger(ser=b"x").qb64}])
    m_icp = Msg(icp, sigers=sign(icp, c[:2]))
    m_rot = Msg(rot, sigers=sign(rot, c[2:4], k=rot.keys, prior=icp.ndigs))

    other = ev(eventing.interact, pre=pre, dig=rot.said, sn=2, data=[])
    forged = Body(bytes(other.raw).replace(other.said.encode(), ixn.said.encode(), 1))
    g.add("classic/borrowed-said", "an interaction whose d is the SAID of another event, "
          "signed over its own bytes", [m_icp, m_rot, Msg(forged, sigers=sign(forged, c[2:4]))],
          {pre: [icp, rot]}, targets=[ixn.said], expected="reject",
          reason="d is not the SAID of the event", spec_section="SAID field; Key event messages")

    wrong = ev(eventing.interact, pre=pre, dig=icp.said, sn=2, data=[])
    g.add("classic/wrong-prior", "an interaction whose p is the SAID of the inception, "
          "not of the rotation before it",
          [m_icp, m_rot, Msg(wrong, sigers=sign(wrong, c[2:4]))], {pre: [icp, rot]},
          targets=[wrong.said], expected="reject",
          reason="p must be the SAID of the prior event", spec_section="Prior event SAID field")

    unc = ev(eventing.rotate, pre=pre, keys=keys(c[4:6]), dig=icp.said, sn=1, isith="2",
             ndigs=digs(c[:2]), nsith="2")
    g.add("classic/uncommitted-next-keys", "a rotation to keys whose digests the inception "
          "did not commit to, signed by them",
          [m_icp, Msg(unc, sigers=sign(unc, c[4:6], k=unc.keys))], {pre: [icp]},
          targets=[unc.said], expected="reject",
          reason="the new keys are not the pre-rotated next keys",
          spec_section="Rotation using pre-rotation")

    g.add("classic/too-few-signatures", "a rotation with 1 of the 2 signatures its "
          "thresholds require", [m_icp, Msg(rot, sigers=sign(rot, c[2:3], k=rot.keys,
                                                             prior=icp.ndigs))],
          {pre: [icp]}, targets=[rot.said], expected="reject",
          reason="neither the current nor the prior next threshold is met",
          spec_section="Indexed Signatures")

    gap = ev(eventing.interact, pre=pre, dig=icp.said, sn=2, data=[])
    g.add("classic/sequence-gap", "an interaction with s=2 directly after the inception",
          [m_icp, Msg(gap, sigers=sign(gap, c[:2]))], {pre: [icp]}, targets=[gap.said],
          expected="reject", reason="sequence numbers must increase by one",
          spec_section="Sequence number field")

    g.add("classic/unsigned", "the inception and a rotation without any attached signature",
          [Msg(icp), m_icp, Msg(rot)], {pre: [icp]}, targets=[rot.said], expected="reject",
          reason="a key event without at least one verifiable controller signature must be "
          "dropped", spec_section="Indexed Signatures")

    # delegation never anchored
    dr = [S(f"classic/delegator/{i}") for i in range(2)]
    dor = ev(eventing.incept, keys=keys(dr[:1]), isith="1", ndigs=digs(dr[1:]), nsith="1",
             code=MtrDex.Blake3_256)
    de = [S(f"classic/delegate/{i}") for i in range(2)]
    dip = ev(eventing.delcept, keys=keys(de[:1]), delpre=dor.pre, isith="1",
             ndigs=digs(de[1:]), nsith="1")
    g.add("classic/unanchored-delegation", "a delegated inception whose source seal points "
          "at the delegator's inception, which anchors nothing",
          [Msg(dor, sigers=sign(dor, dr[:1])),
           Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="0", d=dor.said)])],
          {dor.pre: [dor], dip.pre: []}, targets=[dip.said], expected="reject",
          reason="the delegator's KEL has no seal of the delegated event",
          spec_section="Cooperative Delegation")

    # abandonment, non-transferable
    b = [S(f"classic/abandon/{i}") for i in range(3)]
    aicp = ev(eventing.incept, keys=keys(b[:1]), isith="1", ndigs=digs(b[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    arot = ev(eventing.rotate, pre=aicp.pre, keys=keys(b[1:2]), dig=aicp.said, sn=1,
              isith="1", ndigs=[], nsith="0")
    aixn = ev(eventing.interact, pre=aicp.pre, dig=arot.said, sn=2)
    arot2 = ev(eventing.rotate, pre=aicp.pre, keys=keys(b[2:3]), dig=arot.said, sn=2,
               isith="1", ndigs=digs(b[:1]), nsith="1")
    am = [Msg(aicp, sigers=sign(aicp, b[:1])),
          Msg(arot, sigers=sign(arot, b[1:2], k=arot.keys, prior=aicp.ndigs))]
    g.add("classic/after-abandonment/ixn", "an interaction after a rotation to n=[], "
          "signed by the current key", am + [Msg(aixn, sigers=sign(aixn, b[1:2]))],
          {aicp.pre: [aicp, arot]}, targets=[aixn.said], expected="reject",
          reason="an identifier whose next key list is empty is abandoned; no further "
          "event is accepted", spec_section="Next key digest list")
    g.add("classic/after-abandonment/rot", "a rotation after a rotation to n=[], signed "
          "by the current key and by an unrelated key",
          am + [Msg(arot2, sigers=sign(arot2, b[1:3], indexes=[0, 0]))],
          {aicp.pre: [aicp, arot]}, targets=[arot2.said], expected="reject",
          reason="an identifier whose next key list is empty is abandoned; no further "
          "event is accepted", spec_section="Next key digest list")
    nt = S("classic/nontrans", trans=False)
    nicp = ev(eventing.incept, keys=[nt.verfer.qb64], code=MtrDex.Ed25519N)
    nixn = ev(eventing.interact, pre=nicp.pre, dig=nicp.said, sn=1)
    g.add("classic/after-nontransferable-inception", "an interaction after the inception "
          "of a non-transferable prefix",
          [Msg(nicp, sigers=sign(nicp, [nt])), Msg(nixn, sigers=sign(nixn, [nt]))],
          {nicp.pre: [nicp]}, targets=[nixn.said], expected="reject",
          reason="a non-transferable identifier has no events after its inception",
          spec_section="Inception Event Message Body; Basic prefix derivation")

    # empty k, threshold larger than k, weighted threshold length mismatch
    e = [S(f"classic/keys/{i}") for i in range(4)]
    base = ev(eventing.incept, keys=keys(e[:2]), isith="1", ndigs=digs(e[2:4]), nsith="1",
              code=MtrDex.Blake3_256)
    empty = remake(base, g.pv, k=[], kt="0")
    g.add("classic/empty-current-keys", "an inception with k=[] and kt=0, with a "
          "signature at index 0 by an unrelated key",
          [Msg(empty, sigers=sign(empty, e[:1]))], {empty.pre: []}, targets=[empty.said],
          expected="reject", reason="the current key list must not be empty",
          spec_section="Current keys list field")
    big = remake(base, g.pv, kt="3")
    g.add("classic/threshold-exceeds-keys", "an inception with kt=3 and two keys, signed "
          "by both", [Msg(big, sigers=sign(big, e[:2]))], {big.pre: []}, targets=[big.said],
          expected="reject", reason="an integer threshold larger than the key list can "
          "never be met", spec_section="Key and key digest threshold fields")
    wl = remake(base, g.pv, kt=["1/2", "1/2", "1/2"])
    g.add("classic/weighted-threshold-length", "an inception with three weights for two "
          "keys, signed by both", [Msg(wl, sigers=sign(wl, e[:2]))], {wl.pre: []},
          targets=[wl.said], expected="reject",
          reason="a weighted threshold has exactly one weight per key",
          spec_section="Fractionally weighted threshold")
    wn = remake(base, g.pv, nt=["1/2", "1/2", "1/2"])
    g.add("classic/weighted-next-threshold-length", "an inception with three next weights "
          "for two next key digests", [Msg(wn, sigers=sign(wn, e[:2]))], {wn.pre: []},
          targets=[wn.said], expected="reject",
          reason="a weighted threshold has exactly one weight per key digest (\"Three "
          "weights mean there MUST be exactly three corresponding key pairs\")",
          spec_section="Fractionally weighted threshold")


def neg_key_events(g):
    ev, pv = g.ev, g.pv

    # -- kel-rot-dup-key-prior-next-bypass -------------------------------------
    for variant, nsith, sith in (("integer", "2", "1"),
                                 ("weighted", ["1/2", "1/2"], ["1/2", "1/2"])):
        k = [S(f"dupkey/{variant}/{i}") for i in range(4)]
        icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:3]), nsith=nsith,
                 code=MtrDex.Blake3_256)
        rot = try_build(
            lambda: ev(eventing.rotate, pre=icp.pre, keys=keys([k[1], k[1]]), dig=icp.said,
                       sn=1, isith=sith, ndigs=digs(k[3:4]), nsith="1"),
            lambda: remake(ev(eventing.rotate, pre=icp.pre, keys=keys([k[1], k[2]]),
                              dig=icp.said, sn=1, isith=sith, ndigs=digs(k[3:4]), nsith="1"),
                           pv, k=keys([k[1], k[1]])))
        sigers = [k[1].sign(ser=bytes(rot.raw), index=0, ondex=0),
                  k[1].sign(ser=bytes(rot.raw), index=1, ondex=0)]
        g.add(f"gap/kel-rot-dup-key-prior-next-bypass/{variant}",
              f"inception with nt={json.dumps(nsith)} and two next key digests; a rotation "
              f"with k=[K1,K1] and kt={json.dumps(sith)}, signed twice by K1 (index 0 and "
              f"index 1, both with prior-next index 0). Only one pre-rotated key is exposed",
              [Msg(icp, sigers=sign(icp, k[:1])), Msg(rot, sigers=sigers)], {icp.pre: [icp]},
              targets=[rot.said], expected="reject", gap="kel-rot-dup-key-prior-next-bypass",
              review="accepts" if variant == "integer" else "rejects",
              reason="one exposed pre-rotated key counted twice does not satisfy a prior next "
              "threshold of two keys; a key list must not repeat a key")

    # -- kel-threshold-zero -----------------------------------------------------
    k = [S(f"zero/{i}") for i in range(3)]
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="0",
                   code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]),
                          nsith="1", code=MtrDex.Blake3_256), pv, nt="0"))
    x = S("zero/unrelated")
    rot = ev(eventing.rotate, pre=icp.pre, keys=keys([x]), dig=icp.said, sn=1, isith="1",
             ndigs=digs(k[2:3]), nsith="1")
    amb = ("The specification allows any non-negative integer threshold, and read "
           "literally an empty set of signatures meets 0. It also requires a rotation to be "
           "signed by keys of the newly exposed pre-rotated set, which implies at least one. "
           "The expected outcome follows keripy (a 0 threshold is never met) and the intent "
           "of pre-rotation.")
    g.add("gap/kel-threshold-zero/next", "inception with nt=0 and n=[H(K1)]; a rotation to "
          "an unrelated key Kx, signed only by Kx with a current-only signature",
          [Msg(icp, sigers=sign(icp, k[:1])), Msg(rot, sigers=sign(rot, [x], k=rot.keys,
                                                                    prior=icp.ndigs))],
          {icp.pre: [icp]}, targets=[rot.said], expected="reject", gap="kel-threshold-zero",
          ambiguity=amb, reason="no pre-rotated key is exposed, so rotation authority is "
          "not established")
    zicp = try_build(
        lambda: ev(eventing.incept, keys=keys(k[:1]), isith="0", ndigs=digs(k[1:2]), nsith="1",
                   code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]),
                          nsith="1", code=MtrDex.Blake3_256), pv, kt="0"))
    g.add("gap/kel-threshold-zero/current", "inception with kt=0 and one key, signed by it",
          [Msg(zicp, sigers=sign(zicp, k[:1]))], {zicp.pre: []}, targets=[zicp.said],
          expected="reject", gap="kel-threshold-zero", ambiguity=amb,
          reason="a current threshold of 0 gives no signing authority; keripy never "
          "accepts such an inception")

    # -- kel-config-eo-not-enforced ---------------------------------------------
    k = [S(f"eo/{i}") for i in range(2)]
    icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
             cnfg=["EO"], code=MtrDex.Blake3_256)
    ixn = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=[])
    rot = ev(eventing.rotate, pre=icp.pre, keys=keys(k[1:2]), dig=icp.said, sn=1, isith="1",
             ndigs=digs(k[:1]), nsith="1")
    g.add("gap/kel-config-eo-not-enforced", "inception with c=[\"EO\"]; an interaction at "
          "s=1 signed by the current key is dropped, a rotation at s=1 is accepted",
          [Msg(icp, sigers=sign(icp, k[:1])), Msg(ixn, sigers=sign(ixn, k[:1])),
           Msg(rot, sigers=sign(rot, k[1:2], k=rot.keys, prior=icp.ndigs))],
          {icp.pre: [icp, rot]}, targets=[ixn.said], expected="reject",
          gap="kel-config-eo-not-enforced",
          reason="an establishment-only identifier has no interaction events")

    # -- kel-type-tag-body-mismatch ---------------------------------------------
    k = [S(f"tag/{i}") for i in range(2)]
    icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    ixn = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=[])
    rotixn = remake(ixn, pv, t="rot")
    g.add("gap/kel-type-tag-body-mismatch/rot-with-ixn-body",
          "after an inception, a body {v,t:\"rot\",d,i,s,p,a} (the fields of an interaction "
          "tagged rot) with its SAID computed over the body as sent, signed by the current key",
          [Msg(icp, sigers=sign(icp, k[:1])), Msg(rotixn, sigers=sign(rotixn, k[:1]))],
          {icp.pre: [icp]}, targets=[rotixn.said], expected="reject",
          gap="kel-type-tag-body-mismatch",
          reason="a rot body must have exactly the rotation fields")
    d = [S(f"tag/dip/{i}") for i in range(2)]
    base = ev(eventing.incept, keys=keys(d[:1]), isith="1", ndigs=digs(d[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    # d/i computed over the body with t=icp (how a validator that derives the
    # body from its shape computes it), then the tag changed to dip
    dip_icp = Body(bytes(base.raw).replace(b'"t":"icp"', b'"t":"dip"', 1))
    dip_raw = remake(base, pv, t="dip")
    for variant, body, how in (("said-over-icp-dummy", dip_icp,
                                "d and i are the SAID of the same body tagged icp"),
                               ("said-over-body", dip_raw,
                                "d and i are the SAID of the body as sent")):
        g.add(f"gap/kel-type-tag-body-mismatch/dip-without-di/{variant}",
              f"a self-addressing body tagged dip without a di field ({how}), signed by "
              f"k[0], with no source seal",
              [Msg(body, sigers=sign(body, d[:1]))], {body.pre: []}, targets=[body.said],
              expected="reject", gap="kel-type-tag-body-mismatch",
              reason="a dip body must carry di; without it it is neither a valid dip nor "
              "an icp")

    # -- kel-invalid-sig-poisons-event ------------------------------------------
    k = [S(f"poison/{i}") for i in range(4)]
    icp = ev(eventing.incept, keys=keys(k[:2]), isith="1", ndigs=digs(k[2:4]), nsith="1",
             code=MtrDex.Blake3_256)
    g.add("gap/kel-invalid-sig-poisons-event", "inception with kt=1 and two keys; a valid "
          "signature by K0 at index 0 and 64 random bytes as an Ed25519 signature at index 1",
          [Msg(icp, sigers=sign(icp, k[:1]) + [junk_siger(1, "poison")])], {icp.pre: [icp]},
          targets=[icp.said], expected="accept", gap="kel-invalid-sig-poisons-event",
          reason="the verified signatures meet the threshold; a signature that does not "
          "verify is ignored")

    # -- kel-escrow-unverified-sigs ---------------------------------------------
    k = [S(f"escrow/{i}") for i in range(4)]
    icp = ev(eventing.incept, keys=keys(k[:2]), isith="2", ndigs=digs(k[2:4]), nsith="2",
             code=MtrDex.Blake3_256)
    g.add("gap/kel-escrow-unverified-sigs", "inception with kt=2 sent three times: with one "
          "random signature at index 0 (to be dropped, not escrowed), with only K0's "
          "signature at index 0 (escrowed as partially signed), with only K1's signature at "
          "index 1 (completes it)",
          [Msg(icp, sigers=[junk_siger(0, "escrow")]), Msg(icp, sigers=sign(icp, k[:1])),
           Msg(icp, sigers=sign(icp, k[1:2], indexes=[1]))], {icp.pre: [icp]},
          targets=[icp.said], expected="accept", gap="kel-escrow-unverified-sigs",
          reason="a message without a verifiable signature is dropped, so it cannot block "
          "the signatures that arrive later")

    # -- kel-duplicity-identical-and-unverified -----------------------------------
    k = [S(f"dup/{i}") for i in range(6)]
    icp = ev(eventing.incept, keys=keys(k[:2]), isith="1", ndigs=digs(k[2:4]), nsith="1",
             code=MtrDex.Blake3_256)
    rot = ev(eventing.rotate, pre=icp.pre, keys=keys(k[2:4]), dig=icp.said, sn=1, isith="1",
             ndigs=digs(k[4:6]), nsith="1")
    alt = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=[])
    msgs = [Msg(icp, sigers=sign(icp, k[:1])),
            Msg(rot, sigers=sign(rot, k[2:3], k=rot.keys, prior=icp.ndigs)),
            Msg(rot, sigers=sign(rot, k[3:4], k=rot.keys, prior=icp.ndigs)),
            Msg(alt, sigers=[junk_siger(0, "dup")])]
    g.add("gap/kel-duplicity-identical-and-unverified", "inception and rotation (kt=1 of 2) "
          "signed by K2; the identical rotation again with K3's signature; then a different "
          "interaction at s=1 with only a random signature",
          msgs, {icp.pre: [icp, rot]}, targets=[alt.said], expected="reject",
          gap="kel-duplicity-identical-and-unverified",
          spec_expect={"duplicity": {"evidence": [], "note": "neither the re-sent rotation "
                                     "(same SAID) nor the unverified interaction is a "
                                     "verified different version of an event at s=1, so "
                                     "neither is evidence of duplicity. Keeping K3's late "
                                     "signature on the accepted rotation is keripy "
                                     "behaviour; the specification does not require it."}},
          extra=combine(receipt_counts([(icp.pre, rot.said)]), duplicity_state(icp.pre)),
          reason="a duplicitous event is a verified but different version of an event at the "
          "same location; an identical event is not duplicitous and an unverified one is "
          "dropped")

    # -- kel-nested-weighted-threshold ------------------------------------------
    k = [S(f"nested/{i}") for i in range(10)]
    sith = [[{"1/2": ["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}],
            ["1/2", {"1/2": ["1", "1"]}]]
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(k[:9]), isith=sith, ndigs=digs(k[9:10]),
                   nsith="1", code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(k[:9]), isith="1", ndigs=digs(k[9:10]),
                          nsith="1", code=MtrDex.Blake3_256), pv, kt=sith))
    signers = [k[i] for i in (0, 3, 5, 6, 8)]
    g.add("gap/kel-nested-weighted-threshold", "inception with 9 keys and the "
          "specification's nested weighted threshold, signed by keys 0, 3, 5, 6 and 8",
          [Msg(icp, sigers=sign(icp, signers, k=keys(k[:9])))], {icp.pre: [icp]},
          targets=[icp.said], expected="accept", gap="kel-nested-weighted-threshold",
          reason="keys 0, 3, 5, 6 and 8 satisfy both clauses of the nested threshold")

    # -- kel-seal-types-missing / seal-types-missing ------------------------------
    k = [S(f"seals/{i}") for i in range(2)]
    icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    seals = {
        "source": {"s": "e", "d": "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-"},
        "latest-establishment": {"i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"},
        "registrar-backer": {"bi": "BDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
                             "d": "EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe"},
        "typed": {"t": "YCSMTCAA", "d": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5"},
    }
    ixn = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=list(seals.values()))
    g.add("gap/kel-seal-types-missing", "an interaction anchoring a source seal {s,d}, a "
          "latest establishment seal {i}, a registrar backer seal {bi,d} and a typed seal "
          "{t,d}", [Msg(icp, sigers=sign(icp, k[:1])), Msg(ixn, sigers=sign(ixn, k[:1]))],
          {icp.pre: [icp, ixn]}, targets=[ixn.said], expected="accept",
          gap="kel-seal-types-missing",
          reason="every seal type of the specification may appear in a key event's a list")
    for name, seal in seals.items():
        ixn = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=[seal])
        g.add(f"gap/seal-types-missing/{name}", f"an interaction anchoring one {name} seal "
              f"{json.dumps(seal)}",
              [Msg(icp, sigers=sign(icp, k[:1])), Msg(ixn, sigers=sign(ixn, k[:1]))],
              {icp.pre: [icp, ixn]}, targets=[ixn.said], expected="accept",
              gap="seal-types-missing", reason=f"the {name} seal is a seal type of the "
              "specification")

    # -- kel-nontrans-prefix-with-next ------------------------------------------
    nt = S("nontrans-next", trans=False)
    k1 = S("nontrans-next/1")
    icp = try_build(
        lambda: ev(eventing.incept, keys=[nt.verfer.qb64], isith="1", ndigs=digs([k1]),
                   nsith="1", code=MtrDex.Ed25519N),
        lambda: remake(ev(eventing.incept, keys=[S("nontrans-next", True).verfer.qb64],
                          isith="1", ndigs=digs([k1]), nsith="1", code=MtrDex.Ed25519),
                       pv, labels=("d",), i=nt.verfer.qb64, k=[nt.verfer.qb64]))
    rot = try_build(
        lambda: ev(eventing.rotate, pre=icp.pre, keys=keys([k1]), dig=icp.said, sn=1,
                   isith="1", ndigs=digs([nt]), nsith="1"),
        lambda: remake(ev(eventing.rotate, pre=S("nontrans-next", True).verfer.qb64,
                          keys=keys([k1]), dig=icp.said, sn=1, isith="1", ndigs=digs([nt]),
                          nsith="1"), pv, i=icp.pre))
    g.add("gap/kel-nontrans-prefix-with-next", "inception with i=k[0] a non-transferable "
          "(B) key and n=[H(K1)]; then a rotation to K1",
          [Msg(icp, sigers=sign(icp, [nt])),
           Msg(rot, sigers=sign(rot, [k1], k=rot.keys, prior=[dig(k1)]))],
          {icp.pre: []}, targets=[icp.said, rot.said], expected="reject",
          gap="kel-nontrans-prefix-with-next",
          ambiguity="The specification says only informatively that the derivation code "
          "indicates a non-transferable identifier; it has no explicit MUST that rejects "
          "the inception. At the least the rotation must be rejected.",
          reason="a non-transferable derivation code cannot have next keys")

    # -- kel-weighted-threshold-validity ----------------------------------------
    k = [S(f"weights/{i}") for i in range(4)]
    unreduced = try_build(
        lambda: ev(eventing.incept, keys=keys(k[:2]), isith=["2/4", "2/4"], ndigs=digs(k[2:4]),
                   nsith="1", code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(k[:2]), isith=["1/2", "1/2"],
                          ndigs=digs(k[2:4]), nsith="1", code=MtrDex.Blake3_256),
                       pv, kt=["2/4", "2/4"]))
    g.add("gap/kel-weighted-threshold-validity/unreduced-fraction",
          "inception with kt=[\"2/4\",\"2/4\"], signed by both keys",
          [Msg(unreduced, sigers=sign(unreduced, k[:2]))], {unreduced.pre: [unreduced]},
          targets=[unreduced.said], expected="accept", gap="kel-weighted-threshold-validity",
          reason="\"2/4\" is a ratio of non-negative integers; the threshold is written as "
          "sent")
    unsat = try_build(
        lambda: ev(eventing.incept, keys=keys(k[:2]), isith="1", ndigs=digs(k[2:4]),
                   nsith=["1/3", "1/3"], code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(k[:2]), isith="1", ndigs=digs(k[2:4]),
                          nsith=["1/2", "1/2"], code=MtrDex.Blake3_256),
                       pv, nt=["1/3", "1/3"]))
    g.add("gap/kel-weighted-threshold-validity/unsatisfiable-next",
          "inception with nt=[\"1/3\",\"1/3\"] (the weights of all next keys sum to 2/3), "
          "signed by the current key", [Msg(unsat, sigers=sign(unsat, k[:1]))],
          {unsat.pre: []}, targets=[unsat.said], expected="reject",
          gap="kel-weighted-threshold-validity", review="rejects",
          ambiguity="The specification only implies that a threshold must be satisfiable "
          "(the clause weights must be able to reach 1); it does not say that an "
          "unsatisfiable next threshold invalidates the event. The expected outcome follows "
          "keripy.",
          reason="no set of next keys can ever satisfy the next threshold, so the "
          "identifier could never rotate")

    # -- kel-config-did-rb-nrb --------------------------------------------------
    k = [S(f"rb/{i}") for i in range(2)]
    w1 = W("rb/w1")
    icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
             cnfg=["RB"], wits=[w1.verfer.qb64], toad=1, code=MtrDex.Blake3_256)
    g.add("gap/kel-config-did-rb-nrb", "inception with c=[\"RB\"], b=[B1], bt=1 and a=[] "
          "(no registrar backer seal for B1), signed and receipted by B1",
          [Msg(icp, sigers=sign(icp, k[:1]), wigers=wsign(icp, [w1], [w1.verfer.qb64]))],
          {icp.pre: []}, targets=[icp.said], expected="reject", gap="kel-config-did-rb-nrb",
          reason="with RB the establishment event must include a registrar backer seal for "
          "each backer")


def neg_delegation(g):
    ev, pv = g.ev, g.pv

    def delegator(name, **kwa):
        dr = [S(f"{name}/delegator/{i}") for i in range(3)]
        dor = ev(eventing.incept, keys=keys(dr[:1]), isith="1", ndigs=digs(dr[1:2]), nsith="1",
                 code=MtrDex.Blake3_256, **kwa)
        return dr, dor

    def delegate(name, delpre):
        de = [S(f"{name}/delegate/{i}") for i in range(3)]
        dip = ev(eventing.delcept, keys=keys(de[:1]), delpre=delpre, isith="1",
                 ndigs=digs(de[1:2]), nsith="1")
        return de, dip

    def seal(body):
        return SealEvent(i=body.pre, s=body.sad["s"], d=body.said)._asdict()

    # -- DND --------------------------------------------------------------------
    dr, dor = delegator("dnd", cnfg=["DND"])
    de, dip = delegate("dnd", dor.pre)
    dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1, data=[seal(dip)])
    g.add("gap/kel-config-dnd-not-enforced", "delegator inception with c=[\"DND\"], a "
          "delegator interaction anchoring the seal of a delegated inception, and the "
          "delegated inception with a source seal couple pointing at it",
          [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
           Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="1", d=dixn.said)])],
          {dor.pre: [dor, dixn], dip.pre: []}, targets=[dip.said], expected="reject",
          gap="kel-config-dnd-not-enforced",
          reason="a delegated event whose delegator has the DND trait is dropped")
    drot = ev(eventing.rotate, pre=dor.pre, keys=keys(dr[1:2]), dig=dor.said, sn=1,
              isith="1", ndigs=digs(dr[2:3]), nsith="1", data=[seal(dip)])
    g.add("gap/deleg-dnd-not-enforced", "delegator inception with c=[\"DND\"], a delegator "
          "rotation anchoring the seal of a delegated inception, and the delegated inception "
          "with a source seal couple pointing at the rotation",
          [Msg(dor, sigers=sign(dor, dr[:1])),
           Msg(drot, sigers=sign(drot, dr[1:2], k=drot.keys, prior=dor.ndigs)),
           Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="1", d=drot.said)])],
          {dor.pre: [dor, drot], dip.pre: []}, targets=[dip.said], expected="reject",
          gap="deleg-dnd-not-enforced",
          reason="a delegated event whose delegator has the DND trait is dropped")

    # -- one anchor, two delegations ---------------------------------------------
    dr, dor = delegator("two")
    da, dipa = delegate("two/a", dor.pre)
    db_, dipb = delegate("two/b", dor.pre)
    dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1, data=[seal(dipa), seal(dipb)])
    g.add("gap/deleg-escrow-one-per-anchor", "two delegated inceptions with source seal "
          "couples (s=1) arrive before the delegator interaction at s=1 that anchors both",
          [Msg(dor, sigers=sign(dor, dr[:1])),
           Msg(dipa, sigers=sign(dipa, da[:1]), bonds=[SealSource(s="1", d=dixn.said)]),
           Msg(dipb, sigers=sign(dipb, db_[:1]), bonds=[SealSource(s="1", d=dixn.said)]),
           Msg(dixn, sigers=sign(dixn, dr[:1]))],
          {dor.pre: [dor, dixn], dipa.pre: [dipa], dipb.pre: [dipb]},
          targets=[dipa.said, dipb.said], expected="accept", gap="deleg-escrow-one-per-anchor",
          reason="one delegating event may anchor several delegations, each of which is "
          "then accepted")

    # -- seal i and s must match ---------------------------------------------------
    dr, dor = delegator("sealmatch")
    de, dip = delegate("sealmatch", dor.pre)
    other = S("sealmatch/other").verfer.qb64
    for variant, sl, how in (
            ("wrong-i-and-s", {"i": other, "s": "7", "d": dip.said}, "another AID and s=7"),
            ("wrong-i", {"i": other, "s": "0", "d": dip.said}, "another AID, s=0"),
            ("wrong-s", {"i": dip.pre, "s": "1", "d": dip.said}, "the delegate's AID, s=1")):
        dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1, data=[sl])
        g.add(f"gap/deleg-seal-is-ignored/{variant}", f"the delegator's interaction anchors "
              f"a seal with the delegated inception's SAID as d but {how}",
              [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
               Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="1", d=dixn.said)])],
              {dor.pre: [dor, dixn], dip.pre: []}, targets=[dip.said], expected="reject",
              gap="deleg-seal-is-ignored",
              reason="the delegating seal is an event seal of the delegated event: its i, s "
              "and d must all match")

    # -- no source seal attached ------------------------------------------------
    dr, dor = delegator("nosource")
    de, dip = delegate("nosource", dor.pre)
    dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1, data=[seal(dip)])
    g.add("gap/deleg-no-kel-search", "the delegator's inception and the interaction "
          "anchoring the delegated inception, then the delegated inception without a "
          "source seal attachment",
          [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
           Msg(dip, sigers=sign(dip, de[:1]))],
          {dor.pre: [dor, dixn], dip.pre: [dip]}, targets=[dip.said], expected="accept",
          gap="deleg-no-kel-search",
          reason="a validator must be given or find the delegating seal in the delegator's "
          "KEL")

    # -- dip without di (basic prefix) ---------------------------------------------
    k = [S(f"nodi/{i}") for i in range(2)]
    base = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
              code=MtrDex.Ed25519)
    nodi_icp = Body(bytes(base.raw).replace(b'"t":"icp"', b'"t":"dip"', 1))
    nodi_raw = remake(base, pv, labels=("d",), t="dip")
    for variant, body, how in (("said-over-icp-dummy", nodi_icp,
                                "d is the SAID of the same body tagged icp"),
                               ("said-over-body", nodi_raw, "d is the SAID of the body as sent")):
        g.add(f"gap/dip-without-di-accepted/{variant}", f"a body tagged dip with a "
              f"transferable basic prefix i=k[0] and no di field ({how}), signed, no source "
              f"seal", [Msg(body, sigers=sign(body, k[:1]))], {body.pre: []},
              targets=[body.said], expected="reject", gap="dip-without-di-accepted",
              reason="a dip body must carry di")

    # -- anchor in the delegator's inception ---------------------------------------
    dr = [S(f"icpanchor/delegator/{i}") for i in range(2)]
    delpre = dr[0].verfer.qb64
    de, dip = delegate("icpanchor", delpre)
    dor = ev(eventing.incept, keys=[delpre], isith="1", ndigs=digs(dr[1:2]), nsith="1",
             code=MtrDex.Ed25519, data=[seal(dip)])
    assert dor.pre == delpre
    g.add("gap/deleg-anchor-in-inception-refused", "a delegator with a transferable basic "
          "prefix whose inception anchors the seal of a delegated inception; the delegated "
          "inception's source seal couple points at that inception (s=0)",
          [Msg(dor, sigers=sign(dor, dr[:1])),
           Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="0", d=dor.said)])],
          {dor.pre: [dor], dip.pre: [dip]}, targets=[dip.said], expected="accept",
          gap="deleg-anchor-in-inception-refused",
          keripy_note="keripy refuses a source seal couple with s=0: validateDelegation "
          "validates the couple's sequence number with inceptive=False "
          "(src/keri/core/eventing.py:3279), so an anchor in the delegator's inception is "
          "found only by its KEL search, when no source seal is attached (see the "
          "no-source-seal variant)",
          reason="any event of the delegator that carries the event seal can be the "
          "delegating event")

    g.add("gap/deleg-anchor-in-inception-refused/no-source-seal", "the same delegator "
          "inception anchoring the delegated inception, which carries no source seal "
          "attachment, so the validator has to find the seal in the delegator's KEL",
          [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dip, sigers=sign(dip, de[:1]))],
          {dor.pre: [dor], dip.pre: [dip]}, targets=[dip.said], expected="accept",
          gap="deleg-anchor-in-inception-refused",
          reason="any event of the delegator that carries the event seal can be the "
          "delegating event")

    # -- several source seal couples ----------------------------------------------
    dr, dor = delegator("couples")
    de, dip = delegate("couples", dor.pre)
    dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1, data=[seal(dip)])
    wrong = Diger(ser=b"not the anchoring event").qb64
    g.add("gap/source-seal-multiple-couples", "a delegated inception with one source seal "
          "group holding two couples: (s=1, a wrong SAID) then (s=1, the anchoring "
          "interaction's SAID)",
          [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
           Msg(dip, sigers=sign(dip, de[:1]),
               bonds=[SealSource(s="1", d=wrong), SealSource(s="1", d=dixn.said)])],
          {dor.pre: [dor, dixn], dip.pre: [dip]}, targets=[dip.said], expected="accept",
          gap="source-seal-multiple-couples",
          ambiguity="The specification allows several seals in one count code group and "
          "lets a validator find the delegating seal itself, but does not say which couple "
          "of a group is the reference. keripy uses the last one.",
          reason="one of the couples points at the anchoring event")


def neg_witnessing(g):
    ev, pv = g.ev, g.pv
    w1, w2, w3, w9 = W("wit/w1"), W("wit/w2"), W("wit/w3"), W("wit/w9")
    W1, W2, W3, W9 = (w.verfer.qb64 for w in (w1, w2, w3, w9))

    def ctl(name, n=3):
        return [S(f"wit/{name}/{i}") for i in range(n)]

    # -- duplicate backers -------------------------------------------------------
    c = ctl("bdup")
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                   wits=[W1, W1], toad=1, code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]),
                          nsith="1", wits=[W1, W2], toad=1, code=MtrDex.Blake3_256),
                       pv, b=[W1, W1]))
    g.add("gap/wit-b-duplicates", "inception with b=[W1,W1] and bt=1, controller-signed, "
          "with W1's receipt attached as a witness signature at index 0",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=[w1.sign(ser=bytes(icp.raw), index=0)])],
          {icp.pre: []}, targets=[icp.said], expected="reject", gap="wit-b-duplicates",
          reason="an AID must not appear more than once in a backer list")

    # -- bt != 0 with an empty list ------------------------------------------------
    c = ctl("bt-empty")
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                   wits=[], toad=1, code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]),
                          nsith="1", code=MtrDex.Blake3_256), pv, bt="1"))
    g.add("gap/wit-bt-nonzero-empty-b/inception", "inception with b=[] and bt=1, "
          "controller-signed", [Msg(icp, sigers=sign(icp, c[:1]))], {icp.pre: []},
          targets=[icp.said], expected="reject", gap="wit-bt-nonzero-empty-b",
          reason="with an empty backer list bt must be 0; the event is invalid (dropped, "
          "not escrowed)")
    c = ctl("bt-empty-rot")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1], toad=1, code=MtrDex.Blake3_256)
    rot = try_build(
        lambda: ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
                   isith="1", ndigs=digs(c[2:3]), nsith="1", wits=[W1], cuts=[W1], adds=[],
                   toad=1),
        lambda: remake(ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
                          isith="1", ndigs=digs(c[2:3]), nsith="1", wits=[W1], cuts=[W1],
                          adds=[], toad=0), pv, bt="1"))
    g.add("gap/wit-bt-nonzero-empty-b/rotation", "inception with b=[W1], bt=1 (witnessed); "
          "a rotation with br=[W1], ba=[] and bt=1, controller-signed",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1])),
           Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs))],
          {icp.pre: [icp]}, targets=[rot.said], expected="reject", gap="wit-bt-nonzero-empty-b",
          reason="the rotation leaves an empty backer list, so bt must be 0")

    # -- bt larger than the backer list ------------------------------------------
    c = ctl("bt-big")
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                   wits=[W1, W2], toad=3, code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]),
                          nsith="1", wits=[W1, W2], toad=2, code=MtrDex.Blake3_256),
                       pv, bt="3"))
    g.add("gap/wit-bt-exceeds-b", "inception with b=[W1,W2] and bt=3, controller-signed, "
          "with the witness signatures of W1 and W2",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1, w2], [W1, W2]))],
          {icp.pre: []}, targets=[icp.said], expected="reject", gap="wit-bt-exceeds-b",
          ambiguity="The specification says bt is the number of backers in the backer list "
          "that must support the event, so bt > len(b) can never be met; it does not say "
          "explicitly that such an event is invalid rather than escrowed.",
          reason="the backer threshold exceeds the number of backers")

    # -- weighted bt -----------------------------------------------------------
    c = ctl("bt-weighted")
    base = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
              wits=[W1, W2], toad=2, code=MtrDex.Blake3_256)
    icp = remake(base, pv, bt=["1/2", "1/2"])
    g.add("gap/wit-bt-weighted", "inception with b=[W1,W2] and bt=[\"1/2\",\"1/2\"], "
          "controller-signed, with the witness signatures of W1 and W2",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1, w2], [W1, W2]))],
          {icp.pre: []}, targets=[icp.said], expected="reject", gap="wit-bt-weighted",
          reason="bt is a hex-encoded non-negative integer")

    # -- transferable witness AID -------------------------------------------------
    c = ctl("wit-trans")
    tw = S("wit/transferable-witness")    # D code
    TW = tw.verfer.qb64
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                   wits=[TW], toad=1, code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]),
                          nsith="1", wits=[W1], toad=1, code=MtrDex.Blake3_256), pv, b=[TW]))
    ntw = S("wit/transferable-witness", trans=False)  # same key, B code
    r = eventing.receipt(pre=icp.pre, sn=0, said=icp.said, pvrsn=pv, kind=Kinds.json)
    cig = ntw.sign(ser=bytes(icp.raw))
    receipt = Msg(r, cigars=[cig], fix=lambda t: t.replace(ntw.verfer.qb64, TW, 1))
    g.add("gap/wit-transferable-witness-aid", "inception with b=[D...] (a transferable "
          "Ed25519 code) and bt=1, controller-signed, followed by a receipt whose "
          "non-transferable receipt couple carries that D key with a valid signature",
          [Msg(icp, sigers=sign(icp, c[:1])), receipt], {icp.pre: []}, targets=[icp.said],
          expected="reject", gap="wit-transferable-witness-aid",
          reason="witness AIDs must be non-transferable public keys")

    # -- ba naming a current witness ---------------------------------------------
    c = ctl("ba-existing")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1, W2], toad=1, code=MtrDex.Blake3_256)
    rot = try_build(
        lambda: ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
                   isith="1", ndigs=digs(c[2:3]), nsith="1", wits=[W1, W2], cuts=[],
                   adds=[W1], toad=1),
        lambda: remake(ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
                          isith="1", ndigs=digs(c[2:3]), nsith="1", wits=[W1, W2], cuts=[],
                          adds=[W3], toad=1), pv, ba=[W1]))
    g.add("gap/wit-ba-existing-duplicates", "inception with b=[W1,W2], bt=1 (witnessed); a "
          "rotation with br=[], ba=[W1], bt=1, controller-signed and signed by W1 at index 0",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1, W2])),
           Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
               wigers=wsign(rot, [w1], [W1, W2]))],
          {icp.pre: [icp, rot]}, targets=[rot.said], expected="accept",
          gap="wit-ba-existing-duplicates",
          spec_expect={"witnesses": {icp.pre: [W1, W2]}},
          ambiguity="The specification says to skip AIDs of ba that are already witnesses, "
          "keripy refuses the event and keriox appends W1 again: three behaviours, so "
          "interop needs a decision. The expected outcome follows the specification text.",
          reason="ba entries already in the backer list are skipped; the witness list stays "
          "[W1,W2]")

    # -- duplicates inside br or ba ---------------------------------------------
    for variant, cuts, adds, after, signers in (("ba", [], [W3, W3], [W1, W2, W3], [w2]),
                                                ("br", [W1, W1], [], [W2], [w2])):
        c = ctl(f"brba-dup-{variant}")
        icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                 wits=[W1, W2], toad=1, code=MtrDex.Blake3_256)
        good = ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1,
                  isith="1", ndigs=digs(c[2:3]), nsith="1", wits=[W1, W2],
                  cuts=sorted(set(cuts)), adds=sorted(set(adds)), toad=1)
        rot = remake(good, pv, br=cuts, ba=adds)
        g.add(f"gap/wit-br-ba-internal-duplicates/{variant}",
              f"inception with b=[W1,W2], bt=1 (witnessed); a rotation with br={cuts and '[W1,W1]' or '[]'}, "
              f"ba={adds and '[W3,W3]' or '[]'}, bt=1, controller-signed and witnessed by W2",
              [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1, W2])),
               Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
                   wigers=wsign(rot, signers, after))],
              {icp.pre: [icp]}, targets=[rot.said], expected="reject",
              gap="wit-br-ba-internal-duplicates",
              reason=f"an AID must not appear more than once in {variant}")

    # -- br not a member; br and ba overlap --------------------------------------
    c = ctl("br-nonmember")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1, W2], toad=1, code=MtrDex.Blake3_256)
    good = ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1, isith="1",
              ndigs=digs(c[2:3]), nsith="1", wits=[W1, W2], cuts=[], adds=[], toad=1)
    rot = remake(good, pv, br=[W9])
    g.add("gap/wit-br-not-member-and-br-ba-overlap/br-not-member",
          "inception with b=[W1,W2], bt=1 (witnessed); a rotation with br=[W9] (not a "
          "witness), ba=[], bt=1, controller-signed and witnessed by W1",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1, W2])),
           Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
               wigers=wsign(rot, [w1], [W1, W2]))],
          {icp.pre: [icp, rot]}, targets=[rot.said], expected="accept",
          gap="wit-br-not-member-and-br-ba-overlap",
          spec_expect={"witnesses": {icp.pre: [W1, W2]}},
          ambiguity="The specification does not say what happens when br names an AID that "
          "is not a witness. Removing it is a no-op under the literal reading; keripy refuses "
          "the event.",
          reason="removing an AID that is not in the list leaves the list unchanged")
    c = ctl("br-ba-overlap")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1, W2], toad=1, code=MtrDex.Blake3_256)
    good = ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1, isith="1",
              ndigs=digs(c[2:3]), nsith="1", wits=[W1, W2], cuts=[], adds=[], toad=1)
    rot = remake(good, pv, br=[W1], ba=[W1])
    ixn = ev(eventing.interact, pre=icp.pre, dig=rot.said, sn=2)
    g.add("gap/wit-br-not-member-and-br-ba-overlap/br-ba-overlap",
          "inception with b=[W1,W2], bt=1 (witnessed); a rotation with br=[W1], ba=[W1], "
          "bt=1, controller-signed and witnessed by W2 at index 0; an interaction witnessed "
          "by W1 at index 1 (W1's position after remove-then-append, [W2,W1])",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1, W2])),
           Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
               wigers=wsign(rot, [w2], [W2, W1])),
           Msg(ixn, sigers=sign(ixn, c[1:2]), wigers=wsign(ixn, [w1], [W2, W1]))],
          {icp.pre: [icp, rot, ixn]}, targets=[rot.said, ixn.said], expected="accept",
          gap="wit-br-not-member-and-br-ba-overlap",
          spec_expect={"witnesses": {icp.pre: [W2, W1]}},
          ambiguity="\"except for any AIDs that already appear in the current Backer list\" "
          "can mean the list before the event (W1 is skipped, giving [W2]) or the list after "
          "removal (giving [W2,W1]); keripy refuses any overlap. Witness-indexed signatures "
          "resolve to different keys under each reading. The expected outcome follows the "
          "literal remove-then-append reading.",
          reason="br is applied before ba, so W1 is removed and appended again")

    # -- bt=0 with witnesses ------------------------------------------------------
    c = ctl("bt-zero")
    icp = try_build(
        lambda: ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
                   wits=[W1, W2], toad=0, code=MtrDex.Blake3_256),
        lambda: remake(ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]),
                          nsith="1", wits=[W1, W2], toad=1, code=MtrDex.Blake3_256),
                       pv, bt="0"))
    g.add("gap/wit-bt-zero-nonempty-b", "inception with b=[W1,W2] and bt=0, "
          "controller-signed, no witness signatures",
          [Msg(icp, sigers=sign(icp, c[:1]))], {icp.pre: [icp]}, targets=[icp.said],
          expected="accept", gap="wit-bt-zero-nonempty-b",
          ambiguity="The specification allows any non-negative integer bt and a threshold "
          "of 0 is met by no receipts; keripy requires 1 <= bt <= len(b) whenever b is not "
          "empty.",
          reason="bt=0 needs no witness support")

    # -- a non-designated witness ---------------------------------------------------
    c = ctl("foreign")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1, W2], toad=2, code=MtrDex.Blake3_256)
    g.add("gap/wit-witness-receipts-any-aid", "inception with b=[W1,W2], bt=2 and no "
          "witness signatures, sent to witness W3, which the event does not designate. W3 "
          "(like any validator that is not one of its witnesses) must not accept, store or "
          "receipt it",
          [Msg(icp, sigers=sign(icp, c[:1]))], {icp.pre: []}, targets=[icp.said],
          expected="reject", gap="wit-witness-receipts-any-aid", target="witness",
          spec_expect={"witness": W3, "witness_seed": w3.qb64, "witness_receipts": []},
          keripy_note="replayed as a validator: the event waits in the partially witnessed "
          "escrow. A keripy witness skips the receipt check only for events whose witness "
          "list contains its own prefix (locallyWitnessed, eventing.py:2212-2229)",
          reason="a witness signs only events whose witness list designates it, and does not "
          "accept an event without its witness threshold otherwise")

    # -- one bad witness signature --------------------------------------------------
    c = ctl("wig-bad")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1, W2, W3], toad=2, code=MtrDex.Blake3_256)
    wl = [W1, W2, W3]
    g.add("gap/wit-receipt-all-or-nothing/bad-signature", "inception with b=[W1,W2,W3], "
          "bt=2, controller-signed, one witness signature group with valid signatures at "
          "indexes 0 and 1 and random bytes at index 2",
          [Msg(icp, sigers=sign(icp, c[:1]),
               wigers=wsign(icp, [w1, w2], wl) + [junk_siger(2, "wig-bad")])],
          {icp.pre: [icp]}, targets=[icp.said], expected="accept",
          gap="wit-receipt-all-or-nothing",
          reason="the verified witness signatures meet bt; the bad one is ignored")
    g.add("gap/wit-receipt-all-or-nothing/out-of-range", "the same inception with valid "
          "witness signatures at indexes 0 and 1 and W3's valid signature at index 5",
          [Msg(icp, sigers=sign(icp, c[:1]),
               wigers=wsign(icp, [w1, w2], wl) + [w3.sign(ser=bytes(icp.raw), index=5)])],
          {icp.pre: [icp]}, targets=[icp.said], expected="accept",
          gap="wit-receipt-all-or-nothing",
          reason="the verified witness signatures meet bt; the out-of-range one is ignored")

    # -- duplicity at a used location -------------------------------------------
    c = ctl("dupl", 4)
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1], toad=1, code=MtrDex.Blake3_256)
    ixn = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1, data=[])
    alt = ev(eventing.interact, pre=icp.pre, dig=icp.said, sn=1,
             data=[{"d": Diger(ser=b"other").qb64}])
    base = [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1])),
            Msg(ixn, sigers=sign(ixn, c[:1]), wigers=wsign(ixn, [w1], [W1]))]
    note = ("neither the KEL nor its key state may change. Only (c) is evidence of "
            "duplicity: {}")
    for variant, extra_msg, evidence in (
            ("identical", Msg(ixn, sigers=sign(ixn, c[:1]), wigers=wsign(ixn, [w1], [W1])), []),
            ("unverified", Msg(alt, sigers=[junk_siger(0, "dupl")]), []),
            ("verified", Msg(alt, sigers=sign(alt, c[:1]), wigers=wsign(alt, [w1], [W1])),
             [alt.said])):
        g.add(f"gap/wit-duplicity-unverified/{variant}",
              {"identical": "an accepted inception and interaction (both witnessed); the "
                            "same interaction again",
               "unverified": "an accepted inception and interaction; a different interaction "
                             "at s=1 with a random controller signature",
               "verified": "an accepted inception and interaction; a different interaction "
                           "at s=1, properly signed and witnessed"}[variant],
              base + [extra_msg], {icp.pre: [icp, ixn]},
              targets=[] if variant == "identical" else [alt.said], expected="reject",
              gap="wit-duplicity-unverified",
              spec_expect={"duplicity": {"evidence": evidence}},
              extra=duplicity_state(icp.pre),
              reason={"identical": "an identical event is not duplicitous",
                      "unverified": "an event without a verified signature is dropped; it is "
                                    "not evidence of duplicity",
                      "verified": "a verified different event at an accepted location is "
                                  "evidence of duplicity but does not change the KEL"}[variant])

    # -- local vs remote ------------------------------------------------------------
    c = ctl("remote")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1], toad=1, code=MtrDex.Blake3_256)
    g.add("gap/wit-witness-local-remote", "a controller-signed inception naming W1 as its "
          "only witness, delivered to W1 by a third party over W1's public unauthenticated "
          "endpoint instead of over a protected channel from the controller",
          [Msg(icp, sigers=sign(icp, c[:1]))], {icp.pre: []}, targets=[icp.said],
          expected="reject", gap="wit-witness-local-remote", target="witness",
          spec_expect={"witness": W1, "witness_seed": w1.qb64, "channel": "remote",
                       "witness_receipts": []},
          ambiguity="SHOULD-level rule; what counts as a local (protected) channel is "
          "implementation-defined, so a stream alone cannot express this vector. A runner "
          "has to deliver it as a remote event.",
          keripy_note="replayed as a validator (escrowed for lack of the receipt). A keripy "
          "witness puts remote events of KELs it witnesses into the misfit escrow "
          "(eventing.py:2794-2805)",
          reason="a witness should not sign or accept a remote event")

    # -- key state ee after a rotation ------------------------------------------------
    c = ctl("ksn-ee")
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1], toad=1, code=MtrDex.Blake3_256)
    rot = ev(eventing.rotate, pre=icp.pre, keys=keys(c[1:2]), dig=icp.said, sn=1, isith="1",
             ndigs=digs(c[2:3]), nsith="1", wits=[W1], cuts=[W1], adds=[W2], toad=1)

    def ksn_state(pre):
        def extra(hby, kvy, rvy):
            kever = kvy.kevers.get(pre)
            if kever is None:
                return {"ksn": None}
            ksr = kever.state()
            from dataclasses import asdict
            return {"ksn": {"s": ksr.s, "d": ksr.d, "et": ksr.et, "b": ksr.b,
                            "ee": asdict(ksr.ee)}}
        return extra
    g.add("gap/wit-ksn-ee-swapped", "inception with b=[W1], bt=1 and a rotation with "
          "br=[W1], ba=[W2], bt=1, both witnessed; the key state of the identifier",
          [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1])),
           Msg(rot, sigers=sign(rot, c[1:2], k=rot.keys, prior=icp.ndigs),
               wigers=wsign(rot, [w2], [W2]))],
          {icp.pre: [icp, rot]}, targets=[rot.said], expected="accept",
          gap="wit-ksn-ee-swapped", target="ksn",
          spec_expect={"key_state": {"i": icp.pre, "s": "1", "d": rot.said, "et": "rot",
                                     "b": [W2],
                                     "ee": {"s": "1", "d": rot.said, "br": [W1], "ba": [W2]}}},
          extra=ksn_state(icp.pre),
          ambiguity="The specification does not define the key state notice or its ee "
          "block; the expected values follow keripy's KeyStateRecord and the meaning of "
          "br/ba.",
          reason="ee describes the latest establishment event: its sn and SAID and the "
          "witnesses it removed (br) and added (ba)")


def neg_routed(g):
    from keri.core.counting import Counter, Codens
    from keri.core.coring import Pather
    from dataclasses import asdict
    ev, pv = g.ev, g.pv

    def rpy(route, data, stamp, pre=None):
        kwa = {"pre": pre} if pre else {}
        return ev(eventing.reply, route=route, data=data, stamp=stamp, **kwa)

    def nontrans_signed(body, signer):
        return Msg(body, cigars=[signer.sign(ser=bytes(body.raw))])

    def trans_signed(body, est, signers):
        tsg = (Prefixer(qb64=est.pre), Number(num=int(est.sad["s"], 16)),
               Diger(qb64=est.said), sign(body, signers))
        return Msg(body, tsgs=[tsg])

    def check_loc(eid, scheme, accepted_url):
        def check(got):
            url = got["locs"][0]["url"]
            return "accepts" if url == accepted_url else "rejects"
        return check

    # -- ksn -------------------------------------------------------------------
    w1 = W("routed/w1")
    W1 = w1.verfer.qb64
    c = [S(f"routed/ksn/{i}") for i in range(2)]
    icp = ev(eventing.incept, keys=keys(c[:1]), isith="1", ndigs=digs(c[1:2]), nsith="1",
             wits=[W1], toad=1, code=MtrDex.Blake3_256)
    kel = [Msg(icp, sigers=sign(icp, c[:1]), wigers=wsign(icp, [w1], [W1]))]
    prev = icp
    for sn in range(1, 11):
        ixn = ev(eventing.interact, pre=icp.pre, dig=prev.said, sn=sn)
        kel.append(Msg(ixn, sigers=sign(ixn, c[:1]), wigers=wsign(ixn, [w1], [W1])))
        prev = ixn
    events = [m.body for m in kel]

    def keystate(msgs, pre):
        """keripy's key state notice of `pre` after `msgs`, with a fixed dt."""
        with habbing.openHby(name="kerivec-ksn", temp=True) as hby:
            kvy = eventing.Kevery(db=hby.db, lax=False, local=False)
            parsing.Parser(kvy=kvy, version=V2).parse(ims=bytearray(stream(msgs, V2)))
            ksr = asdict(kvy.kevers[pre].state())
        ksr["dt"] = STAMPS[30]
        return ksr

    def check_ksn(pre, aid, ksr):
        def check(got):
            seen = got.get("knas", {}).get(f"{pre}/{aid}")
            return "accepts" if seen == {"d": ksr["d"], "s": ksr["s"]} else "rejects"
        return check

    ksn = keystate(kel, icp.pre)
    good = rpy(f"/ksn/{W1}", ksn, STAMPS[31])
    g.add("gap/rm-ksn-sn-decimal/hex", "a KEL of 11 events (sn 0 to a, witnessed by W1) "
          "and W1's key state notice reply for it with a.s=\"a\" (hex), keripy's "
          "KeyStateRecord shape, signed with W1's non-transferable couple",
          kel + [nontrans_signed(good, w1)], {icp.pre: events}, targets=[good.said],
          expected="accept", gap="rm-ksn-sn-decimal", target="reply",
          extra=ksn_obs([(icp.pre, W1)]), check=check_ksn(icp.pre, W1, ksn),
          spec_expect={"key_state_notice": {"i": icp.pre, "s": "a", "d": events[10].said}},
          reason="sequence numbers are hex; the notice names the sn-10 event")
    bad = dict(ksn)
    bad["s"] = "10"
    badr = rpy(f"/ksn/{W1}", bad, STAMPS[31])
    g.add("gap/rm-ksn-sn-decimal/decimal", "the same key state notice with a.s=\"10\" "
          "(sn 10 written in decimal, which reads as hex 0x10 = 16) and d the SAID of the "
          "sn-10 event", kel + [nontrans_signed(badr, w1)], {icp.pre: events},
          targets=[badr.said], expected="reject", gap="rm-ksn-sn-decimal", target="reply",
          keripy_note="keripy accepts it: processReplyKeyStateNotice compares d with the KEL "
          "only when it has an event at the notice's sn (src/keri/core/eventing.py:5317-5326), "
          "and there is none at 0x10",
          extra=ksn_obs([(icp.pre, W1)]), check=check_ksn(icp.pre, W1, bad),
          reason="there is no event at sn 0x10; the notice is inconsistent with the KEL")
    small = keystate(kel[:1], icp.pre)
    smallr = rpy(f"/ksn/{W1}", small, STAMPS[31])
    g.add("gap/rm-ksn-format-undefined", "a witnessed inception and the witness's key "
          "state notice reply in keripy's shape ({vn:[1,0], i, s, p, d, f, dt, et, kt, k, "
          "nt, n, bt, b, c, ee, di}), signed with the witness's couple",
          kel[:1] + [nontrans_signed(smallr, w1)], {icp.pre: events[:1]},
          targets=[smallr.said], expected="accept", gap="rm-ksn-format-undefined",
          target="reply", extra=ksn_obs([(icp.pre, W1)]),
          check=check_ksn(icp.pre, W1, small),
          ambiguity="The specification does not define the key state notice; keripy's "
          "KeyStateRecord is the de facto shape.",
          reason="a key state notice from a designated witness that matches the KEL")

    # -- BADA with equal dt -----------------------------------------------------
    eid = W("routed/eid")
    EID = eid.verfer.qb64
    loc1 = rpy("/loc/scheme", {"eid": EID, "scheme": "http", "url": "http://a/"}, STAMP)
    loc2 = rpy("/loc/scheme", {"eid": EID, "scheme": "http", "url": "http://evil/"}, STAMP)
    g.add("gap/rm-bada-equal-dt", "two /loc/scheme replies of the non-transferable eid B "
          "with the same dt, the first with url http://a/, the second with http://evil/, "
          "each signed with B's couple",
          [nontrans_signed(loc1, eid), nontrans_signed(loc2, eid)], {}, targets=[loc2.said],
          expected="reject", gap="rm-bada-equal-dt", target="reply",
          extra=routed_state(locs=[(EID, "http")]), check=check_loc(EID, "http", "http://evil/"),
          spec_expect={"locs": [{"eid": EID, "scheme": "http", "url": "http://a/"}]},
          reason="an update is accepted only when its date-time is later than the prior's")

    # -- end role cut -------------------------------------------------------------
    cc = [S(f"routed/ctl/{i}") for i in range(2)]
    cicp = ev(eventing.incept, keys=keys(cc[:1]), isith="1", ndigs=digs(cc[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    C = cicp.pre
    m_cicp = Msg(cicp, sigers=sign(cicp, cc[:1]))
    wat = W("routed/watcher").verfer.qb64
    add = rpy("/end/role/add", {"cid": C, "role": "watcher", "eid": wat}, STAMPS[11])
    cut = rpy("/end/role/cut", {"cid": C, "role": "watcher", "eid": wat}, STAMPS[12])
    m_add = trans_signed(add, cicp, cc[:1])

    def check_end(cid, role, eid_, want):
        def check(got):
            for e in got["ends"]:
                if (e["cid"], e["role"], e["eid"]) == (cid, role, eid_):
                    return "accepts" if e["allowed"] == want else "rejects"
        return check
    g.add("gap/rm-endrole-cut-no-nullify", "the controller's inception; /end/role/add "
          "{cid:C, role:watcher, eid:W} at :11 and /end/role/cut for the same at :12, both "
          "signed by C; then the :11 add again",
          [m_cicp, m_add, trans_signed(cut, cicp, cc[:1]), m_add], {C: [cicp]},
          targets=[cut.said], expected="accept", gap="rm-endrole-cut-no-nullify",
          target="reply", extra=routed_state(ends=[(C, "watcher", wat)]),
          check=check_end(C, "watcher", wat, False),
          spec_expect={"ends": [{"cid": C, "role": "watcher", "eid": wat, "allowed": False}]},
          reason="the cut nullifies the authorization; the replayed older add is stale")

    wa, wb = W("routed/wit-a").verfer.qb64, W("routed/wit-b").verfer.qb64
    adda = rpy("/end/role/add", {"cid": C, "role": "witness", "eid": wa}, STAMPS[10])
    addb = rpy("/end/role/add", {"cid": C, "role": "witness", "eid": wb}, STAMPS[0])
    g.add("gap/rm-endrole-bada-key", "the controller's inception; /end/role/add "
          "{cid:C, role:witness, eid:A} at :10, then {cid:C, role:witness, eid:B} at :00, "
          "both signed by C",
          [m_cicp, trans_signed(adda, cicp, cc[:1]), trans_signed(addb, cicp, cc[:1])],
          {C: [cicp]}, targets=[addb.said], expected="accept", gap="rm-endrole-bada-key",
          target="reply", extra=routed_state(ends=[(C, "witness", wa), (C, "witness", wb)]),
          check=check_end(C, "witness", wb, True),
          spec_expect={"ends": [{"cid": C, "role": "witness", "eid": wa, "allowed": True},
                                {"cid": C, "role": "witness", "eid": wb, "allowed": True}]},
          reason="each (cid, role, eid) is its own record; B has no prior to be compared with")

    for variant, role, amb in (
            ("registrar", "registrar", "The specification names watcher, witness, juror, "
             "judge and registrar as examples of roles (\"such as\"); it does not enumerate "
             "the role values."),
            ("mailbox", "mailbox", "mailbox is a keripy role (keriox calls it messagebox); "
             "the specification does not enumerate role values, so whether it is valid is "
             "unspecified.")):
        eidr = W(f"routed/role/{variant}").verfer.qb64
        addr = rpy("/end/role/add", {"cid": C, "role": role, "eid": eidr}, STAMPS[13])
        g.add(f"gap/rm-role-set-ambiguity/{variant}", f"the controller's inception and "
              f"/end/role/add {{cid:C, role:{role}, eid:R}} signed by C",
              [m_cicp, trans_signed(addr, cicp, cc[:1])], {C: [cicp]}, targets=[addr.said],
              expected="accept", gap="rm-role-set-ambiguity", target="reply",
              extra=routed_state(ends=[(C, role, eidr)]), check=check_end(C, role, eidr, True),
              spec_expect={"ends": [{"cid": C, "role": role, "eid": eidr, "allowed": True}]},
              ambiguity=amb, reason=f"{role} is a role an AID may play")

    # -- empty url ------------------------------------------------------------------
    leid = W("routed/wilma")
    LEID = leid.verfer.qb64
    l1 = rpy("/loc/scheme", {"eid": LEID, "scheme": "https",
                             "url": "https://example.com/witness/wilma"}, STAMPS[11])
    l2 = rpy("/loc/scheme", {"eid": LEID, "scheme": "https", "url": ""}, STAMPS[12])
    g.add("gap/rm-locscheme-empty-url", "a /loc/scheme reply of eid B for https at :11, "
          "then one with url \"\" at :12, both signed with B's couple",
          [nontrans_signed(l1, leid), nontrans_signed(l2, leid)], {}, targets=[l2.said],
          expected="accept", gap="rm-locscheme-empty-url", target="reply",
          extra=routed_state(locs=[(LEID, "https")]), check=check_loc(LEID, "https", ""),
          spec_expect={"locs": [{"eid": LEID, "scheme": "https", "url": ""}]},
          reason="an empty url nullifies the location")

    # -- couples with the wrong codes ------------------------------------------
    tr = S("routed/transferable-eid")
    TR = tr.verfer.qb64
    ntr = S("routed/transferable-eid", trans=False)
    lt = rpy("/loc/scheme", {"eid": TR, "scheme": "http", "url": "http://evil/"}, STAMPS[14])
    g.add("gap/rm-nontrans-couple-transferable-code", "a /loc/scheme reply for "
          "eid=D... (transferable Ed25519 code) with a non-transferable receipt couple "
          "(D key, valid signature)",
          [Msg(lt, cigars=[ntr.sign(ser=bytes(lt.raw))],
               fix=lambda t: t.replace(ntr.verfer.qb64, TR, 1))], {}, targets=[lt.said],
          expected="reject", gap="rm-nontrans-couple-transferable-code", target="reply",
          extra=routed_state(locs=[(TR, "http")]), check=check_loc(TR, "http", "http://evil/"),
          spec_expect={"locs": [{"eid": TR, "scheme": "http", "url": None}]},
          reason="a transferable AID must sign with a reference to its key state; only a "
          "non-transferable code has a fixed key state")
    seid = W("routed/sigtype")
    SEID = seid.verfer.qb64
    ls = rpy("/loc/scheme", {"eid": SEID, "scheme": "http", "url": "http://a/"}, STAMPS[15])
    cig = seid.sign(ser=bytes(ls.raw))
    g.add("gap/rm-couple-sig-type-panic/valid-ed25519-bytes", "a /loc/scheme reply of eid "
          "B (Ed25519) whose receipt couple carries B with B's valid Ed25519 signature "
          "bytes coded 0C (ECDSA secp256k1)",
          [Msg(ls, cigars=[cig], fix=lambda t: t.replace(cig.qb64, "0C" + cig.qb64[2:], 1))],
          {}, targets=[ls.said], expected="reject", gap="rm-couple-sig-type-panic",
          target="reply", extra=routed_state(locs=[(SEID, "http")]),
          check=check_loc(SEID, "http", "http://a/"),
          spec_expect={"locs": [{"eid": SEID, "scheme": "http", "url": None}]},
          keripy_note="keripy verifies the signature bytes with the key's algorithm and "
          "ignores the signature code (Cigar.verfer.verify), so it accepts the reply",
          reason="the signature does not verify against the key; the reply is rejected (a "
          "validator must not crash)")

    jeid = W("routed/sigtype-junk")
    JEID = jeid.verfer.qb64
    lj = rpy("/loc/scheme", {"eid": JEID, "scheme": "http", "url": "http://a/"}, STAMPS[15])
    jcig = jeid.sign(ser=bytes(lj.raw))
    jsig = Cigar(raw=junk_sig("sigtype"), code=MtrDex.ECDSA_256k1_Sig).qb64
    g.add("gap/rm-couple-sig-type-panic/junk", "a /loc/scheme reply of eid B (Ed25519) "
          "whose receipt couple carries B with 64 random bytes coded 0C (ECDSA secp256k1)",
          [Msg(lj, cigars=[jcig], fix=lambda t: t.replace(jcig.qb64, jsig, 1))],
          {}, targets=[lj.said], expected="reject", gap="rm-couple-sig-type-panic",
          target="reply", extra=routed_state(locs=[(JEID, "http")]),
          check=check_loc(JEID, "http", "http://a/"),
          spec_expect={"locs": [{"eid": JEID, "scheme": "http", "url": None}]},
          reason="the signature does not verify against the key; the reply is rejected (a "
          "validator must not crash)")

    # -- protocol in the version string ----------------------------------------
    peid = W("routed/proto")
    PEID = peid.verfer.qb64
    lp = rpy("/loc/scheme", {"eid": PEID, "scheme": "http", "url": "http://a/"}, STAMPS[16])
    acdc = saidify(lp.sad, pv, proto=Protocols.acdc)
    g.add("gap/rm-protocol-not-checked", "a /loc/scheme reply whose version string names "
          "the ACDC protocol (size and SAID correct), signed with the eid's couple",
          [nontrans_signed(acdc, peid)], {}, targets=[acdc.said], expected="reject",
          gap="rm-protocol-not-checked", target="reply",
          extra=routed_state(locs=[(PEID, "http")]), check=check_loc(PEID, "http", "http://a/"),
          spec_expect={"locs": [{"eid": PEID, "scheme": "http", "url": None}]},
          reason="the protocol of a KERI message is KERI")

    # -- exn without sender signatures --------------------------------------------
    snd = W("routed/sender")
    SND = snd.verfer.qb64
    rcp = S("routed/recipient").verfer.qb64
    mc = [S(f"routed/member/{i}") for i in range(2)]
    micp = ev(eventing.incept, keys=keys(mc[:1]), isith="1", ndigs=digs(mc[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    m_micp = Msg(micp, sigers=sign(micp, mc[:1]))

    def pathed(path, gv):
        inner = bytearray(Pather(parts=path).qb64b) + m_micp.attachments(gv)
        return bytes(Counter(Codens.PathedMaterialCouples, count=len(inner) // 4,
                             version=V2 if gv.major >= 2 else V1).qb64b) + bytes(inner)
    fwd = exchanging_old(pv, sender=SND, route="/fwd",
                         modifiers={"pre": rcp, "topic": "multisig"},
                         embeds={"evt": micp.raw}, stamp=STAMPS[17])
    g.add("gap/rm-exn-unsigned/keripy-shape", "a KERI 1.0 exn /fwd (keripy's shape "
          "[v,t,d,i,rp,p,dt,r,q,a,e]) embedding an inception, whose only attachment is "
          "the pathed group with the embedded event's signature; no sender signature",
          [Msg(fwd, atc_raw=lambda gv: pathed(["e", "evt"], gv))], {}, targets=[fwd.said],
          expected="reject", gap="rm-exn-unsigned", target="exchange",
          extra=routed_state(exns=[fwd.said]),
          check=lambda got: "accepts" if got["exchanges"][fwd.said] else "rejects",
          reason="an exchange message must carry its sender's signature")
    kx = saidify({"v": "", "t": "exn", "d": "", "dt": STAMPS[17], "r": "/fwd",
                  "q": {"pre": rcp, "topic": "multisig"}, "a": dict(micp.sad)}, pv)
    g.add("gap/rm-exn-unsigned/keriox-shape", "an exn /fwd in keriox's shape "
          "[v,t,d,dt,r,q,a] with the inception in a, whose only attachment is the pathed "
          "group with the embedded event's signature; no sender signature",
          [Msg(kx, atc_raw=lambda gv: pathed(["a"], gv))], {}, targets=[kx.said],
          expected="reject", gap="rm-exn-unsigned", target="exchange",
          extra=routed_state(exns=[kx.said]),
          check=lambda got: "accepts" if got["exchanges"][kx.said] else "rejects",
          reason="an exchange message must carry its sender's signature (and this body "
          "also lacks the required i field)")

    # -- d of qry and exn not verified ------------------------------------------
    unrelated = Diger(ser=b"unrelated").qb64
    q = ev(eventing.query, route="logs", query={"i": C, "src": W1}, stamp=STAMPS[18])
    qbad = Body(bytes(q.raw).replace(q.said.encode(), unrelated.encode(), 1))
    g.add("gap/rm-said-not-verified-qry-exn/qry", "a qry logs whose d is an unrelated "
          "digest, signed over its bytes with the requester's non-transferable couple",
          [nontrans_signed(qbad, snd)], {}, targets=[unrelated], expected="reject",
          gap="rm-said-not-verified-qry-exn", target="query",
          check=lambda got: "accepts" if keripy_loads(qbad.raw) else "rejects",
          keripy_note="outcome is whether keripy loads the body (SerderKERI verifies d)",
          reason="d must be the SAID of the message")
    x = exchanging_old(pv, sender=SND, route="/ping", modifiers={}, attributes={"n": 1},
                       stamp=STAMPS[19])
    xbad = Body(bytes(x.raw).replace(x.said.encode(), unrelated.encode(), 1))
    g.add("gap/rm-said-not-verified-qry-exn/exn", "an exn whose d is an unrelated digest, "
          "signed over its bytes with the sender's non-transferable couple",
          [nontrans_signed(xbad, snd)], {}, targets=[unrelated], expected="reject",
          gap="rm-said-not-verified-qry-exn", target="exchange",
          check=lambda got: "accepts" if keripy_loads(xbad.raw) else "rejects",
          keripy_note="outcome is whether keripy loads the body (SerderKERI verifies d)",
          reason="d must be the SAID of the message")


def exchanging_old(pv, **kwa):
    from keri.peer import exchanging
    return exchanging.exchangeOld(pvrsn=pv, kind=Kinds.json, **kwa)


def ksn_obs(pairs):
    def extra(hby, kvy, rvy):
        out = {}
        for pre, aid in pairs:
            d = hby.db.knas.get(keys=(pre, aid))
            ksr = None if d is None else hby.db.ksns.get(keys=(d.qb64,))
            out[f"{pre}/{aid}"] = None if d is None else {"d": d.qb64,
                                                          "s": None if ksr is None else ksr.s}
        return {"knas": out}
    return extra


def neg_v2(g):
    """Vectors with KERI 2.0 bodies."""
    ev, pv = g.ev, g.pv

    # -- c in rot and drt ------------------------------------------------------
    k = [S(f"v2/rotc/{i}") for i in range(3)]
    icp = ev(eventing.incept, keys=keys(k[:1]), isith="1", ndigs=digs(k[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    rot = ev(eventing.rotate, pre=icp.pre, keys=keys(k[1:2]), dig=icp.said, sn=1, isith="1",
             ndigs=digs(k[2:3]), nsith="1")
    assert list(rot.sad)[-2:] == ["c", "a"], list(rot.sad)
    m_icp = Msg(icp, sigers=sign(icp, k[:1]))
    g.add("gap/kel-rot-c-field-v2/rot-with-c", "KERI 2.0 inception and a KERI 2.0 rotation "
          "with \"c\":[] before \"a\", as in the specification's rotation example",
          [m_icp, Msg(rot, sigers=sign(rot, k[1:2], k=rot.keys, prior=icp.ndigs))],
          {icp.pre: [icp, rot]}, targets=[rot.said], expected="accept",
          gap="kel-rot-c-field-v2", reason="c is a required field of a KERI 2.0 rotation")
    noc = remake(rot, pv, c=None)
    g.add("gap/kel-rot-c-field-v2/rot-without-c", "KERI 2.0 inception and a KERI 2.0 "
          "rotation without the c field (size and SAID recomputed)",
          [m_icp, Msg(noc, sigers=sign(noc, k[1:2], k=noc.keys, prior=icp.ndigs))],
          {icp.pre: [icp]}, targets=[noc.said], expected="reject",
          gap="kel-rot-c-field-v2", review="rejects",
          reason="c is a required field of a KERI 2.0 rotation")

    dr = [S(f"v2/drtc/delegator/{i}") for i in range(3)]
    de = [S(f"v2/drtc/delegate/{i}") for i in range(3)]
    dor = ev(eventing.incept, keys=keys(dr[:1]), isith="1", ndigs=digs(dr[1:2]), nsith="1",
             code=MtrDex.Blake3_256)
    dip = ev(eventing.delcept, keys=keys(de[:1]), delpre=dor.pre, isith="1",
             ndigs=digs(de[1:2]), nsith="1")
    dixn = ev(eventing.interact, pre=dor.pre, dig=dor.said, sn=1,
              data=[SealEvent(i=dip.pre, s="0", d=dip.said)._asdict()])
    drt = ev(eventing.deltate, pre=dip.pre, keys=keys(de[1:2]), dig=dip.said, sn=1,
             isith="1", ndigs=digs(de[2:3]), nsith="1")
    drtnoc = remake(drt, pv, c=None)
    base = [Msg(dor, sigers=sign(dor, dr[:1])), Msg(dixn, sigers=sign(dixn, dr[:1])),
            Msg(dip, sigers=sign(dip, de[:1]), bonds=[SealSource(s="1", d=dixn.said)])]
    for variant, body in (("drt-with-c", drt), ("drt-without-c", drtnoc)):
        dixn2 = ev(eventing.interact, pre=dor.pre, dig=dixn.said, sn=2,
                   data=[SealEvent(i=body.pre, s="1", d=body.said)._asdict()])
        ok = variant == "drt-with-c"
        g.add(f"gap/kel-rot-c-field-v2/{variant}",
              f"KERI 2.0 delegated inception and a delegated rotation "
              f"{'with' if ok else 'without'} the c field, anchored by the delegator",
              base + [Msg(dixn2, sigers=sign(dixn2, dr[:1])),
                      Msg(body, sigers=sign(body, de[1:2], k=body.keys, prior=dip.ndigs),
                          bonds=[SealSource(s="2", d=dixn2.said)])],
              {dor.pre: [dor, dixn, dixn2], dip.pre: [dip, body] if ok else [dip]},
              targets=[body.said], expected="accept" if ok else "reject",
              gap="kel-rot-c-field-v2", review="accepts" if ok else "rejects",
              reason="c is a required field of a KERI 2.0 delegated rotation")

    # -- routed messages ------------------------------------------------------------
    snd = W("v2/sender")
    SND = snd.verfer.qb64
    rcv = W("v2/receiver").verfer.qb64

    def loads(body):
        return lambda got: "accepts" if keripy_loads(body.raw) else "rejects"
    note = ("outcome is whether keripy loads the body (field set of the message type, "
            "version string and SAID); keripy has no stream handler for this type")

    msgs = {}
    msgs["xip"] = ev(eventing.exchept, sender=SND, receiver=rcv, route="/offer",
                     modifiers={"timing": "immediate"}, attributes={"item": "x"},
                     nonce="0ABhY2Rjc3BlY3dvcmtyYXcw", stamp=STAMPS[40])
    msgs["pro"] = ev(eventing.prod, pre=SND, route="/confidential", replyRoute="/reply",
                     query={"d": Diger(ser=b"v2/sealed").qb64}, stamp=STAMPS[41])
    msgs["bar"] = ev(eventing.bare, pre=SND, route="/confidential",
                     data={"d": Diger(ser=b"v2/sealed").qb64, "value": "disclosed"},
                     stamp=STAMPS[42])
    for ilk, body in msgs.items():
        g.add(f"gap/rm-pro-bar-xip-missing/{ilk}", f"a KERI 2.0 {ilk} message from a "
              f"non-transferable sender, signed with its couple",
              [Msg(body, cigars=[snd.sign(ser=bytes(body.raw))])], {}, targets=[body.said],
              expected="accept", gap="rm-pro-bar-xip-missing", target="message",
              check=loads(body), keripy_note=note,
              reason=f"{ilk} is a routed message type of the specification")

    xn = ev(eventing.exchange, sender=SND, receiver=rcv, xid=msgs["xip"].said,
            prior=msgs["xip"].said, route="/agree", modifiers={}, attributes={"ok": True},
            stamp=STAMPS[43])
    assert list(xn.sad)[:7] == ["v", "t", "d", "i", "ri", "x", "p"], list(xn.sad)
    g.add("gap/rm-exn-fields/spec-shape", "a KERI 2.0 exn [v,t,d,i,ri,x,p,dt,r,q,a] from a "
          "non-transferable sender, signed with its couple",
          [Msg(xn, cigars=[snd.sign(ser=bytes(xn.raw))])], {}, targets=[xn.said],
          expected="accept", gap="rm-exn-fields", target="message", check=loads(xn),
          keripy_note=note, reason="the exn fields of the specification")
    short = remake(xn, pv, i=None, ri=None, x=None, p=None)
    g.add("gap/rm-exn-fields/without-i-ri-x-p", "the same exn without i, ri, x and p "
          "(keriox's shape), signed with the sender's couple",
          [Msg(short, cigars=[snd.sign(ser=bytes(short.raw))])], {}, targets=[short.said],
          expected="reject", gap="rm-exn-fields", target="message", check=loads(short),
          review="rejects", keripy_note=note, reason="i, ri, x and p are required")

    q = ev(eventing.query, pre=SND, route="/oobi", replyRoute="/oobi/process",
           query={"i": rcv, "role": "witness"}, stamp=STAMPS[44])
    assert "i" in q.sad, q.sad
    g.add("gap/rm-routed-i-field-ambiguity", "a KERI 2.0 qry with the sender in i, as in "
          "the specification's example, signed with the sender's couple",
          [Msg(q, cigars=[snd.sign(ser=bytes(q.raw))])], {}, targets=[q.said],
          expected="accept", gap="rm-routed-i-field-ambiguity", target="message",
          check=loads(q), keripy_note=note,
          ambiguity="The qry field list [v,t,d,dt,r,rr,q] has no i and forbids other "
                    "fields, but every qry, rpy, pro and bar example (JSON and native CESR) "
                    "carries i, and keripy 2.0 writes it. The expected outcome follows the "
                    "examples and keripy.",
          reason="i names the sender")

    cc = [S(f"v2/loc/ctl/{i}") for i in range(2)]
    cicp = ev(eventing.incept, keys=keys(cc[:1]), isith="1", ndigs=digs(cc[1:2]), nsith="1",
              code=MtrDex.Blake3_256)
    wit = W("v2/loc/wilma").verfer.qb64
    loc = ev(eventing.reply, pre=cicp.pre, route="/loc/scheme",
             data={"eid": wit, "scheme": "https", "url": "https://example.com/witness/wilma"},
             stamp=STAMPS[45])
    tsg = (Prefixer(qb64=cicp.pre), Number(num=0), Diger(qb64=cicp.said), sign(loc, cc[:1]))
    g.add("gap/rm-locscheme-signer-ambiguity", "the controller's KERI 2.0 inception and a "
          "KERI 2.0 /loc/scheme reply with i the controller and a.eid its witness, signed "
          "only by the controller",
          [Msg(cicp, sigers=sign(cicp, cc[:1])), Msg(loc, tsgs=[tsg])], {cicp.pre: [cicp]},
          targets=[loc.said], expected="reject", gap="rm-locscheme-signer-ambiguity",
          target="reply", extra=routed_state(locs=[(wit, "https")]),
          check=lambda got: "accepts" if got["locs"][0]["url"] else "rejects",
          spec_expect={"locs": [{"eid": wit, "scheme": "https", "url": None}]},
          ambiguity="The normative text says the EID authorizes its own location, but the "
                    "specification's examples put the controller in i (the sender) and the "
                    "witness in a.eid.",
          reason="a location is authorized by its eid's signature")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def load_gaps():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "gaps.json")) as f:
        return {g["id"]: g for g in json.load(f)["gaps"]}


def negative_files(g):
    vecs = g.vecs
    edge = [v for v in vecs if not v["keripy"]["agrees_with_spec"]]
    return {"negative/negative.json": ("keri-negative/1", vecs),
            "negative/edge.json": ("keri-negative/1", edge)}


def write(out, gen, files, extra_manifest):
    manifest = {"generator": gen, "files": {}}
    manifest.update(extra_manifest)
    for rel, (schema, vecs) in files.items():
        ids = [v["id"] for v in vecs]
        dups = sorted({i for i in ids if ids.count(i) > 1})
        if dups:
            sys.exit(f"{rel}: duplicate vector ids {dups}")
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"schema": schema, "generator": gen, "vectors": vecs}, f,
                      indent=1, sort_keys=False, ensure_ascii=False)
            f.write("\n")
        manifest["files"][rel] = len(vecs)
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    return manifest


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("out_dir", help="test-vectors/keri")
    ap.add_argument("--keripy-rev", required=True,
                    help="keripy git revision the venv was built from")
    args = ap.parse_args()
    gaps = load_gaps()
    gen = {"tool": "gen_vectors.py", "version": GEN_VERSION,
           "source": {"implementation": "keripy", "revision": args.keripy_rev,
                      "version": __import__("keri").__version__},
           "specification": SPEC}
    covered = {}
    manifests = {}
    for pv, sub, negs in ((V1, "v1", (neg_classic, neg_key_events, neg_delegation,
                                      neg_witnessing, neg_routed)),
                          (V2, "v2", (neg_v2,))):
        files = gen_positive(pv)
        g = NegGen(pv, gaps)
        for fn in negs:
            fn(g)
        files.update(negative_files(g))
        for v in g.vecs:
            if "gap" in v:
                covered.setdefault(v["gap"], []).append(f"{sub}/keripy/{v['id']}")
        out = os.path.join(args.out_dir, sub, "keripy")
        disagree = sorted(v["id"] for v in g.vecs if not v["keripy"]["agrees_with_spec"])
        by_gap = {}
        for v in g.vecs:
            if "gap" in v:
                by_gap.setdefault(v["gap"], []).append(v["id"])
        manifests[sub] = write(out, gen, files, {
            "source": "keripy", "pvrsn": f"{pv.major}.{pv.minor}",
            "gaps": by_gap, "keripy_disagrees_with_spec": disagree})
    missing = sorted(set(gaps) - set(covered))
    if missing:
        sys.exit(f"gaps without vectors: {missing}")
    print(json.dumps(manifests, indent=1))


if __name__ == "__main__":
    main()
