#Imortam componentele necesare din libraria Scapy
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *


#Verificam daca pachetul este TCP

def apply_tarpit(packet):
    if packet.haslayer(TCP):
        print ("Se aplica Tarpit-ul...")

        #Modificam Window Size-ul la 0 (basically zicem "sunt ocupat tiwnkie")
        packet[TCP].window = 0

        #Stergem checksum urile curente (modificarea window size-ului rezulta in modificarea checksum-urilor, basically aici le stergem ca sa le recalculeze scapy)
        del packet[TCP].chksum
        del packet[IP].chksum

        #Returnam packet ul dupa ce a fost modificat
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


#Functia Sinkhole - Luam o cerere DNS si returnam un ID fals (ma rog, diferit) pt. redirectionare
def apply_sinkhole(packet):

    #Verificam daca pachetul foloseste UDP si are un strat de DNS
    if packet.haslayer(UDP) and packet.haslayer(DNS):
        print ("DNS Exista -> Sinkhole-ing...")


    #Inversam IP src cu IP dst (cine a trimis acum primeste)
    ip_vechi = packet[IP].src
    packet[IP].src = packet[IP].dst
    packet[IP].dst = ip_vechi


    #Inversare porturi
    port_vechi = packet[UDP].sport
    packet[UDP].sport = packet[UDP].dport
    packet[UDP].dport = port_vechi


    #Setam QR (Query - Response-ul) ca raspuns
    packet[DNS].qr = 1

    #Vedem numele site-ului [gen google.com sau altceva acolo]
    site_name = packet[DNS].qd.qname

    #Atasam raspunusul fals cu IP ul nou
    packet[DNS].an = DNSRR(rrname=site_name, ttl=10, rdata ="127.0.0.1") #Aici o sa pui alt IP, asta e doar de test
    packet[DNS].ancount = 1

    #Stergere checksums
    del packet[IP].chksum
    del packet[UDP].chksum

    return packet

'''
# --- SIMULARE SINKHOLE --- facuta de geamanu 
# 1. Cream o intrebare DNS falsa venita de la hacker
cerere_dns = IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=33333, dport=53) / DNS(rd=1, qd=DNSQR(qname="site-hacker.com"))

print("\n--- CEREREA DNS ORIGINALA ---")
cerere_dns.show()

# 2. O trecem prin capcana ta Sinkhole
raspuns_fals = apply_sinkhole(cerere_dns)

print("\n--- RASPUNSUL DNS FALS (SINKHOLE) ---")
raspuns_fals.show()

'''