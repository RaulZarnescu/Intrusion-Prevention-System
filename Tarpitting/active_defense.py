#Imortam componentele necesare din libraria Scapy

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *


#Verificam daca pachetul este TCP

def apply_tarpit(packet):
    if packet.haslayer(TCP):
        print ("Se aplica Tarpit-ul...")

        #Modificam Window Size-ul la 0 (basically zicem "sunt ocupat tiwnkie")
        packet[TCP].window = 0

        #Stergem checksum urile curente (modificarea window size-ului rezulta in modiifcarea checksum-urilor, basically aici le stergem ca sa le recalculeze scapy)
        del packet[TCP].chksum
        del packet[IP].chksum

        #Returnam ackrt ul dupa ce a fost modificat
        return packet
    else :
        return packet


''''

# --- SIMULARE --- facut de geamanu
# Cream un pachet TCP normal, de la un IP oarecare
pachet_atacator = IP(src="1.2.3.4", dst="192.168.1.100") / TCP(sport=12345, dport=80, window=8192)

print("--- PACHETUL ORIGINAL ---")
pachet_atacator.show() # Afiseaza continutul

# Il trecem prin Tarpit-ul tau
pachet_modificat = apply_tarpit(pachet_atacator)

print("\n--- PACHETUL DUPA TARPIT ---")
pachet_modificat.show() # Afiseaza noul continut

'''

