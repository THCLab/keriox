"""Registry vectors from keripy: a rip, two bups (issued, revoked) with
their blinded state blocks, from a fixed salt, issuer and time stamps."""
import json, sys
from keri.acdc import messaging
from keri.core import Salter
from keri.core.structing import Blinder

issuer = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB"
acdc = "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"
salt = Salter(raw=b"0123456789abcdef").qb64
rip = messaging.regcept(issuer, uuid="0ABrZXJpc3BlY3dvcmtyYXcw",
                        stamp="2026-01-01T00:00:00.000000+00:00")
out = {"salt": salt, "issuer": issuer, "acdc": acdc, "rip": rip.raw.decode(), "updates": []}
prior = rip.said
for sn, state in ((1, "issued"), (2, "revoked")):
    blinder = Blinder.blind(salt=salt, sn=sn, acdc=acdc, state=state)
    bup = messaging.blindate(rip.said, prior, blinder.said, sn=sn,
                             stamp=f"2026-01-0{sn+1}T00:00:00.000000+00:00")
    out["updates"].append({"sn": sn, "state": state, "uuid": blinder.uuid,
                           "blid": blinder.said, "block": blinder.qb64,
                           "bup": bup.raw.decode()})
    prior = bup.said
# A public update: empty nonce, as a public registry would use.
pub = Blinder(crew=Blinder.blind(salt=salt, sn=3, acdc=acdc, state="issued").clan(
    d="", u="", td=acdc, ts="issued"), makify=True)
out["public_block"] = {"blid": pub.said, "block": pub.qb64}
# A bound state block.
bound = Blinder.blind(salt=salt, sn=1, acdc=acdc, state="issued", bound=True, bsn=3,
                      bd="ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux")
out["bound_block"] = {"blid": bound.said, "block": bound.qb64}
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(json.dumps(out, indent=1)[:2500])
