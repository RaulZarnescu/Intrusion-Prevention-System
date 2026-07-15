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