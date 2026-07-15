import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff

# 1. porturi considerate suspecte
SUS_PORTS  = [22,23,3389,445] #SSH, Telnet, RDP, SMB

# 2. Prag
SYN_THRESHOLD = 15 #Limita de ppachete de initiere conexiune /sec
TIME_WINDOW = 1.0 #Fereastra de timp pentru calcularea pragurilor

# 3. Deep Packet Inspection Signatures
# Acestea înlocuiesc momentan decizia AI-ului cu reguli fixe (Pattern Matching)
SIGNATURES = [
    b"UNION SELECT",       # Tentativă clasică de SQL Injection
    b"<script>",           # Tentativă de Cross-Site Scripting (XSS)
    b"cat /etc/passwd",    # Path Traversal / Remote Code Execution pe sisteme Linux
    b"nmap",               # Amprente lăsate adesea de scanerul Nmap
    b"eval("               # Posibilă injecție de cod
]

SIGNATURES_LOWER = [s.lower() for s in SIGNATURES]

#Variabile pentru managementul starii
ip_syn_counts = defaultdict(int) #Salveaza fieacre IP si nr de pachete pe care a incercat sa-l trimita
last_check_time = time.time()

def analyze_packet(pkt):
    global last_check_time, ip_syn_counts

    #Resetam contoarele de timp daca a trecut window ul de timp
    current_time = time.time()
    if current_time-last_check_time >= TIME_WINDOW:
        ip_syn_counts.clear()

    #Vedem daca exista stratul IP
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    #Analiza 1 - Detectare SYN Floods / Port scan rapid
    if TCP in pkt and (pkt[TCP].flags.S and not pkt[TCP].flags.A):
        ip_syn_counts[src_ip] += 1
        if ip_syn_counts[src_ip] > SYN_THRESHOLD:
            print (f"Rata mare de SYN de la {src_ip}: {ip_syn_counts[src_ip]} pachete/sec. Posibil port scan sau flood...")

    #Analiza 2: Reguli - Accesare porturi sensibile
    if TCP in pkt and pkt[TCP].dport in SUS_PORTS:
        print(f"ALERTA! (Regula): {src_ip} incearca sa acceseze {pkt[TCP].dport} pe destinatia {dst_ip}")

    #Analiza 3: Semnaturi - Inspectarea continutului brut
    if Raw in pkt:
        payload = pkt[Raw].load
        #Verificam fiecare semantura in payload (case-insensitive)
        # Analiza 3: Semnaturi - Inspectarea continutului brut
        if Raw in pkt:
            payload = pkt[Raw].load
            payload_lower = payload.lower()  # o singura data per pachet
            for sig_orig, sig_low in zip(SIGNATURES, SIGNATURES_LOWER):
                if sig_low in payload_lower:
                    print(f"Alerta( SEMNATURA ). S-a detectat {sig_orig.decode()} in payload de la {src_ip}")
                    print(f"Continut: {payload[:50]}...") #printam doar primele 50 de caractere



#SNIFFER

def sniffer(interface="eth0"):
    print(f"[INFO] Motorul Euristic OoB (MVP) a pornit pe interfața '{interface}'...")
    print(f"[INFO] Aștept trafic suspect trimis de Raspberry Pi...\n")
    print("-" * 50)


    try:
        sniff (iface = interface, prn = analyze_packet, store = False)
    except KeyboardInterrupt:
        print("\n[INFO] Motor OoB oprit de utilizator.")


if __name__ == "__main__": sniffer (interface = "eth0")