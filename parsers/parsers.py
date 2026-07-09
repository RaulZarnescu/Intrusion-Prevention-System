from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS

load_layer("tls") #TLS - protocolul criptografic folosit in securizarea comunicarilor pe HTTPS


def extract_sni(packet):

    '''Cautam un mesaj de tipul Client Hello in traficul HTTPS si extragem numele site-ului (SNI - Server Name Indication)'''

    #Vedem pachetele TCP care merg spre HHTPS (port 443)
    if packet.haslayer(TCP) and packet[TCP].dport == 443:

        #Verificam daca pachetul contine TLS Client Hello
        if packet.haslayer(TLSClientHello):

            #folosim try pt cazul in care pachetul e dubios sau malformat
            try:
                #Extragem SNI ul
                site_name_bytes = packet[TLS_Ext_ServerName].servernames[0].servername
                #Se numeste site_name_bytes pt ca așa se extrage din ce am scris

                #Decodam numele site-ului in text normal
                site_name = site_name_bytes.decode('utf-8')

                print (f"S-a interceptat accesarea site-ulu {site_name}")
                return site_name

            except Exception as e: pass

    return None

'''
# --- SIMULARE SINKHOLE & SNI --- facuta de geamanu

# 1. Fabricăm "înregistrarea" SNI pentru site-ul malitios
extensie_sni = TLS_Ext_ServerName(servernames=[ServerName(servername = b"site-malware-super-periculos.com")])

# 2. O băgăm în mesajul de "Client Hello"
mesaj_hello = TLSClientHello(ext=[extensie_sni])

# 3. Împachetăm totul frumos în IP, TCP (pe portul 443) și TLS
pachet_https = IP(src="192.168.1.5", dst="104.20.5.12") / TCP(sport=55555, dport=443) / TLS(msg=[mesaj_hello])

print("--- ANALIZĂM PACHETUL (MOCK) ---")
# Apelăm funcția ta magică pentru a vedea dacă ghicește site-ul
rezultat = extract_sni(pachet_https)

if rezultat:
    print(f"Succes! Am extras domeniul: {rezultat}")
else:
    print("Nu am găsit niciun domeniu.")
'''