# TODO: this just logs src/dst and always accepts -- no inspection or enforcement is
# wired in. Needs to actually call the parsers (parsers.py) and model (model.py) to get
# a verdict, and apply_tarpit() (active_defense.py) or a drop/reset when warranted.
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

def handle(pkt):
    packet = IP(pkt.get_payload())
    print(f"{packet.src} -> {packet.dst}")
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, handle)

try:
    nfqueue.run()
except KeyboardInterrupt:
    nfqueue.unbind()