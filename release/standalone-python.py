"""Smoke test of an installed ace-sdk wheel (see README.md). Run with ``python -I`` from outside any checkout.

Two identities exchange a text packet and its signed receipt in memory (no relay); the receiver keeps its state in a
FileStore and a 0600 prekey file and is reopened from disk before the packet arrives.
"""

import atexit
import json
import os
import shutil
import stat
import tempfile

import ace
from ace import (
    FileStore,
    Inbox,
    MemoryStore,
    Outbox,
    PeerStore,
    PrekeyVault,
    Profiles,
    SoftwareIdentity,
    create_published_agent,
)

assert "site-packages" in ace.__file__, f"not an installed package: {ace.__file__}"
home = tempfile.mkdtemp(prefix="ace-py-smoke-")
atexit.register(shutil.rmtree, home, ignore_errors=True)
received = []


class Agent:
    def __init__(self, path=None):
        self.identity = SoftwareIdentity.generate()
        self.id = self.identity.get_ace_id()
        self.path = path
        self.open()

    def open(self):
        if self.path:
            self.store, self.vault = FileStore(self.path), PrekeyVault(os.path.join(self.path, "prekeys.json"))
        else:
            self.store, self.vault = MemoryStore(), PrekeyVault()
        self.peers = PeerStore(self.store)
        self.outbox = Outbox(self.identity, self.store, Profiles())
        self.inbox = Inbox.open(self.identity, self.store, self.vault, self.peers, Profiles(),
                                on_message=lambda m: received.append(m.body), outbox=self.outbox)

    def published(self):
        return create_published_agent(self.identity, relays=["https://relay.example"], prekey=self.vault.current())


alice, bob = Agent(), Agent(os.path.join(home, "bob"))
for me, other in ((alice, bob), (bob, alice)):
    me.peers.adopt(other.published())
    me.peers.set_status(other.id, "admitted")
assert stat.S_IMODE(os.stat(os.path.join(home, "bob", "prekeys.json")).st_mode) == 0o600

mid = alice.outbox.enqueue(bob.id, "ace:text:1", {"message": "hello from the wheel"})
wire = []
alice.outbox.deliver(mid, lambda packet, agent: wire.append(packet),
                     lambda ace_id, refresh=False: alice.peers.agent(ace_id))

bob.inbox.close()
bob.open()  # restart from disk: pins, admission and prekey seed persist
outcome = bob.inbox.receive(json.dumps(wire[0]).encode())
alice.inbox.receive(json.dumps(outcome.receipt.packet).encode())
assert received == [{"message": "hello from the wheel"}], received
assert alice.outbox.get(mid).status == "delivered"
print(json.dumps({"ok": True, "package": ace.__file__, "delivered": mid}))
