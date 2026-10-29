"""Verify a grant written by keriox with keripy's own IPEX handler.

keriox writes the issuer's KEL, the registry events and a grant of a
credential to the holder of keripy.json (see writes_a_keriox_grant_for_keripy
in support/teliox/src/ipex.rs). keripy recreates that holder from the same
salt, learns the issuer's KEL and the registry events (keripy takes registry
events from its own store, as from observers), and handles the grant."""
import json, sys
from keri import Vrsn_2_0
from keri.acdc import Regery, loadHandlers
from keri.app import openHby
from keri.core import Kevery, Parser, Salter
from keri.core.serdering import SerderACDC
from keri.peer import Exchanger

written = json.load(open(sys.argv[1]))

class Recorder:
    def __init__(self):
        self.items = []
    def add(self, attrs):
        self.items.append(attrs)

with openHby(name="ipex-vectors", base="keriox", temp=True, version=Vrsn_2_0,
             salt=Salter(raw=b"0123456789abcdef").qb64) as hby:
    hby.makeHab(name="issuer")
    holder = hby.makeHab(name="holder")
    rgy = Regery(hby=hby, name="ipex-keriox", temp=True)
    try:
        kvy = Kevery(db=hby.db, lax=False, local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(written["issuer_kel"].encode()),
                                       kvy=kvy)
        regk = written["registry"]
        rgy.store.accept(regk, 0, SerderACDC(raw=written["rip"].encode()))
        rgy.store.accept(regk, 1, SerderACDC(raw=written["bup"].encode()))

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)
        ims = bytearray(written["grant"].encode())
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
        assert ims == bytearray(), ims
        said = written["grant_said"]
        assert hby.db.exns.get(keys=(said,)) is not None, "keripy did not accept the grant"
        assert recorder.items[-1]["r"] == "/exn/ipex/grant", recorder.items
        print(f"keripy accepted keriox's grant {said} to {holder.pre}")
    finally:
        rgy.close()
