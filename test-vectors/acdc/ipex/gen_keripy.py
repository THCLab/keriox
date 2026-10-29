"""IPEX vectors from keripy: an issuer's KEL anchoring a private registry
and the issuance of an ACDC naming it, the issuer's /ipex/grant of that
ACDC (nested, with its blinded state block) to a holder, and the holder's
/ipex/admit. The grant and admit are built by keri.acdc.ipexing."""
import json, sys
from keri import Vrsn_2_0
from keri.acdc import Regery, Registrar, acdcmap, admit, grant
from keri.app import openHby
from keri.core import Salter, messagize

DT = "2026-01-03T00:00:00.000000+00:00"

with openHby(name="ipex-vectors", base="keriox", temp=True, version=Vrsn_2_0,
             salt=Salter(raw=b"0123456789abcdef").qb64) as hby:
    issuer = hby.makeHab(name="issuer")
    holder = hby.makeHab(name="holder")
    rgy = Regery(hby=hby, name="ipex-vectors", temp=True)
    try:
        registrar = Registrar(rgy=rgy)
        registry = registrar.makeRegistry(name="diplomas", prefix=issuer.pre)
        rip = rgy.store.event(registry.regk)
        def anchor(serder):
            # The issuer anchors each registry event as keripy's tests do.
            seal = dict(i=registry.regk, s=serder.sad["n"], d=serder.said)
            msg = issuer.interact(data=[seal], gvrsn=Vrsn_2_0)
            assert registry.anchorMsg(serder.said) is True
            return msg
        rip_anchor = anchor(rip)
        # keripy leaves an expanded block's `d` as given; the specification
        # makes it the block's SAID, so it is taken from the compact form.
        compact = acdcmap(israid=issuer.pre, regid=registry.regk,
                          attribute=dict(d="", degree="MSc"), iseaid=holder.pre,
                          compactify=True)
        acdc = acdcmap(israid=issuer.pre, regid=registry.regk,
                       attribute=dict(d=compact.sad["a"], degree="MSc"),
                       iseaid=holder.pre)
        assert acdc.said == compact.said
        blinder, bup = registrar.issue(registry, acdc=acdc, state="issued")
        bup_anchor = anchor(bup)
        origin = messagize(serder=acdc, bonds=[blinder.data], framed=False,
                           gvrsn=Vrsn_2_0)
        grant_exn, grant_atc = grant(hab=issuer, recp=holder.pre,
                                     message="Your diploma", origin=origin, dt=DT)
        admit_exn, admit_atc = admit(hab=holder, message="Thanks",
                                     grant=grant_exn, dt=DT)
        kel = lambda hab: b"".join(
            bytes(hab.msgOwnEvent(sn=sn, gvrsn=Vrsn_2_0)) for sn in range(hab.kever.sn + 1))
        out = {
            "issuer": issuer.pre,
            "holder": holder.pre,
            "issuer_kel": kel(issuer).decode(),
            "holder_kel": kel(holder).decode(),
            "registry": registry.regk,
            "rip": rip.raw.decode(),
            "bup": bup.raw.decode(),
            "acdc": acdc.raw.decode(),
            "block": blinder.qb64,
            "grant": (bytes(grant_exn.raw) + bytes(grant_atc)).decode(),
            "admit": (bytes(admit_exn.raw) + bytes(admit_atc)).decode(),
        }
    finally:
        rgy.close()
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(json.dumps(out, indent=1))
