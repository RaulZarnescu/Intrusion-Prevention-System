# GHID SETUP ZEEK — #REQ-053 (Analiza euristica OoB)

Scop: pregatirea statiei Out-of-Band pentru ingestia traficului clonat (#REQ-019 / iptables TEE)
si generarea de loguri structurate JSON (#REQ-056), care alimenteaza scripturile de analiza
euristica din #REQ-053.

---

## INSTALARE ZEEK

Vezi documentatia si procesul de instalare, basically cateva comenzi, dar depinde de platforma
deci nu pot pune aici pasii.

    https://docs.zeek.org/en/current/install.html

**Nota (Ubuntu / repo OpenSUSE):** cheia GPG trebuie luata de la URL-ul Release.key, nu de la
domeniul principal. Daca ai primit `gpg: no valid OpenPGP data found`, ruleaza:

    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
      | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt update

Instalarea merge si fara asta, dar `apt update` va da warning de semnatura la fiecare rulare.

---

## PRIMII PASI

### 1. Pune Zeek in PATH

    echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
    source ~/.bashrc
    zeek --version

### 2. Verifica unde e site-ul

    ls /opt/zeek/share/zeek/site/

Ar trebui sa vezi ceva gen `local.zeek`, ceea ce e bine.

### 3. Ia un pcap de test

Nu atinge interfata live inca. Genereaza unul local — ai nevoie de trafic TLS ca sa vezi SNI/JA3:

*Terminal 1:*

    sudo tcpdump -i any -w /tmp/test.pcap -c 200 'tcp port 443'

*Terminal 2:*

    curl -s https://example.com > /dev/null
    curl -s https://github.com > /dev/null

### 4. Ruleaza Zeek pe pcap

*Terminal 1:*

    mkdir -p ~/zeek-work && cd ~/zeek-work
    zeek -r /tmp/test.pcap
    ls

Ar trebui sa apara `conn.log`, `ssl.log`, `dns.log`, `packet_filter.log`. Uita-te la `ssl.log`:

    cat ssl.log

Formatul default e TSV, nu JSON. Cauta coloana `server_name` (SNI) — daca e populata cu
`example.com` / `github.com`, Zeek functioneaza corect si poti trece mai departe.

---

## 5. JSON CONFIG (fisier separat, NU local.zeek)

Nu edita `local.zeek`. Tine configul tau intr-un fisier separat, incarcat *peste* `local`.

**De ce separat:**
- nu-ti dispare configul la upgrade de pachet
- intra in git alaturi de scripturile #REQ-053
- nu-ti trebuie sudo ca sa iterezi pe config (zkg ramane cu sudo, vezi pasul 7)
- `local.zeek` de sistem ramane curat pentru cand ajungi la `zeekctl` pe live

Creeaza fisierul:

    nano ~/zeek-work/mvp.zeek

Continut (doar atat, fisierul e complet):

```zeek
# --- Config MVP #REQ-053 ---

@load policy/tuning/json-logs

redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef Log::default_rotation_interval = 0secs;

event zeek_init() {
    local keep = set(Conn::LOG, SSL::LOG, DNS::LOG, HTTP::LOG, Notice::LOG);
    local doomed: vector of Log::ID;

    # colectam intai, stergem dupa — altfel modificam active_streams
    # in timp ce iteram peste el (iterator invalidation)
    for ( id in Log::active_streams )
        if ( id !in keep )
            doomed += id;

    for ( i in doomed )
        Log::disable_stream(doomed[i]);
}
```

**Ce face fiecare linie:**

| Directiva | Efect |
|---|---|
| `@load policy/tuning/json-logs` | fiecare linie de log devine obiect JSON (JSONL), one-per-line |
| `json_timestamps = TS_ISO8601` | timestamp citibil in loc de epoch float — necesar pentru campul `timestamp` din #REQ-030 |
| `default_rotation_interval = 0secs` | opreste rotatia orara + gzip; fisierele raman in `current/` si pot fi urmarite continuu |
| `zeek_init()` | dezactiveaza cele ~35 de loguri nefolosite, pastrand doar cele 5 necesare pentru #REQ-053 (economie reala de I/O pe statia OoB) |

**Atentie:** `@load packages` este intentionat absent. Il adaugi abia dupa pasul 6 — daca
directorul de pachete nu exista inca, Zeek da eroare la pornire.

---

## 6. RULARE CU CONFIGUL PROPRIU

    cd ~/zeek-work && rm -f *.log
    zeek -C -r /tmp/test.pcap local ./mvp.zeek

Cei doi parametri de la final conteaza:
- `local` → incarca `local.zeek` de sistem (toate `@load`-urile default)
- `./mvp.zeek` → incarca configul tau peste

**Fara `local`, Zeek ruleaza cu scripturile de baza si multe loguri nici nu se genereaza.**
Cauza #1 de confuzie la inceput.

**`./` e obligatoriu** daca esti in `~/zeek-work` — fara el, Zeek cauta fisierul in ZEEKPATH
(deci in `/opt/zeek/share/zeek/site/`) si nu-l gaseste. Alternativ, dai calea completa:
`~/zeek-work/mvp.zeek`.

**De ce `-C`:** placile de retea moderne calculeaza checksum-urile TCP in hardware (checksum
offloading), deci in pcap-urile capturate local ele apar ca invalide. Default, Zeek arunca
pachetele cu checksum gresit si nu genereaza nimic. `-C` ii spune sa le ignore.

Daca vezi warning-ul:

    warning in .../find-checksum-offloading.zeek: Your trace file likely has invalid TCP checksums...

...ai uitat `-C`. Pe trafic live (VLAN 100) problema nu apare — e specifica pcap-urilor
capturate pe aceeasi masina care a generat traficul.

Verifica:

    ls
    head -1 conn.log | python3 -m json.tool

Trebuie sa vezi doar `conn.log`, `ssl.log`, `mvp.zeek` — restul logurilor fiind dezactivate in
`zeek_init()`. (`dns.log` / `http.log` apar doar daca pcap-ul contine efectiv trafic DNS/HTTP.)

Output asteptat, `conn.log`:

```json
{
    "ts": "2026-07-16T09:17:25.963265Z",
    "uid": "Ca4dJ74pVlWAuQPy1i",
    "id.orig_h": "10.180.48.8",
    "id.orig_p": 56882,
    "id.resp_h": "172.217.119.4",
    "id.resp_p": 443,
    "proto": "tcp",
    "duration": 0.00030994415283203125,
    "orig_bytes": 24,
    "resp_bytes": 0,
    "conn_state": "SF",
    "history": "^fDFr",
    "orig_pkts": 2,
    "resp_pkts": 3
}
```

Trei lucruri de confirmat aici:
1. **JSON valid** (nu TSV) → `json-logs` s-a incarcat
2. **`ts` in format ISO8601** (nu epoch float `1752678191.123`) → `json_timestamps` aplicat
3. **Doar logurile din `keep`** → `zeek_init()` a rulat corect

Daca toate trei sunt OK, configul e aplicat integral.

---

## 7. INSTALARE JA3 / JA4

JA3 nu e in core-ul Zeek, se instaleaza ca pachet prin `zkg`.

### Consistenta sudo (important)

`zkg autoconfig` ruleaza cu sudo, deci creeaza state-ul in `/opt/zeek/`. **Din acel moment,
TOATE comenzile zkg au nevoie de sudo** — altfel primesti:

    PermissionError: [Errno 13] Permission denied: '/opt/zeek/share/zeek/site/packages/packages.zeek'
    error: user does not have write access in /opt/zeek/var/lib/zkg
    Consider the --user flag to manage zkg state via /home/<user>/.zkg/config

Exista si modul `--user` (state in `~/.zkg/`, fara sudo), dar atunci trebuie sa configurezi
`ZEEKPATH` manual ca Zeek sa gaseasca pachetele. Pentru statia de laborator, **sudo e varianta
corecta** — la deployment real pe OoB e oricum obligatoriu, pachetele trebuie vizibile
procesului Zeek care ruleaza ca serviciu.

### Instalare

    sudo /opt/zeek/bin/zkg autoconfig
    sudo /opt/zeek/bin/zkg install ja3

### Cautarea numelui corect

Numele pachetelor zkg se muta intre namespace-uri. **Nu ghici — cauta:**

    sudo /opt/zeek/bin/zkg search ja3
    sudo /opt/zeek/bin/zkg search ja4

Rezultate (confirmate la data redactarii):

| Pachet | Observatie |
|---|---|
| `zeek/salesforce/ja3` | **Cel corect pentru JA3.** Se instaleaza si prin scurtatura `zkg install ja3` |
| `zeek/hosom/bro-ja3` | Versiune veche, nu o folosi |
| `zeek/foxio/ja4` | **Cel corect pentru JA4** (oficial FoxIO). Atentie: NU `zeek/FoxIO-LLC/ja4` — da eroare `package name not found` |
| `zeek/anthonykasza/ja4` | Implementare alternativa, neoficiala |

JA4 (optional, mai nou, mai granular):

    sudo /opt/zeek/bin/zkg install zeek/foxio/ja4

**Pentru MVP, JA3 e suficient.** Baza de date de hash-uri malitioase (abuse.ch) e pe JA3, nu
JA4 — deci pentru primul detector, JA4 nu aduce nimic in plus. Lasa-l pentru mai tarziu.

### Activare in mvp.zeek

Abia acum adauga in `~/zeek-work/mvp.zeek`, imediat sub primul `@load`:

```zeek
@load packages
```

Re-ruleaza si verifica:

    cd ~/zeek-work && rm -f *.log
    zeek -C -r /tmp/test.pcap local ./mvp.zeek
    head -1 ssl.log | python3 -m json.tool

Campul `ja3` trebuie sa apara acum in `ssl.log`. Daca lipseste, pachetul nu s-a incarcat —
verifica cu `sudo /opt/zeek/bin/zkg list` (pachetul instalat apare marcat `installed: master`).

---

## CRITERIU DE "GATA"

`ssl.log` in JSON, cu `server_name` **si** `ja3` populate.

Din momentul asta poti scrie primul detector din #REQ-053 (blocklist SNI — cel mai simplu,
zero fals pozitiv).

### Fisierul mvp.zeek final

```zeek
# --- Config MVP #REQ-053 ---

@load policy/tuning/json-logs
@load packages

redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef Log::default_rotation_interval = 0secs;

event zeek_init() {
    local keep = set(Conn::LOG, SSL::LOG, DNS::LOG, HTTP::LOG, Notice::LOG);
    local doomed: vector of Log::ID;

    # colectam intai, stergem dupa — altfel modificam active_streams
    # in timp ce iteram peste el (iterator invalidation)
    for ( id in Log::active_streams )
        if ( id !in keep )
            doomed += id;

    for ( i in doomed )
        Log::disable_stream(doomed[i]);
}
```

### Comanda de rulare finala

    cd ~/zeek-work && rm -f *.log
    zeek -C -r /tmp/test.pcap local ./mvp.zeek

---

## CE URMEAZA (nu acum)

### Alternativa: output direct pe stdout

Daca watcher-ul Python din #REQ-053 e un proces persistent, poti sari complet peste fisiere:

```zeek
redef LogAscii::output_to_stdout = T;
redef LogAscii::use_json = T;
```

    zeek -i eth1.100 local mvp.zeek | python3 analyzer.py

Avantaj: zero rotatie, zero inotify, zero race la truncate. Toate stream-urile se amesteca
intr-un singur flux, dar fiecare linie JSON are campul `_path` (`"conn"`, `"ssl"`, ...) —
filtrezi trivial in Python.

Trade-off: pierzi logurile persistente pe disc (#REQ-037 cere scriere batch pe partitia
read-write). Compromis: stdout pentru pipeline-ul live, iar analyzer-ul scrie pe SSD doar
evenimentele relevante.

### Trecerea pe live (VLAN 100)

`zeekctl` e pentru deployment persistent pe interfata live — necesita `node.cfg` cu
`interface=eth1.100`, worker processes, rotatie. **Nu-ti trebuie pana nu curge trafic real
clonat prin `iptables TEE` (#REQ-019).**

Pentru dezvoltarea detectoarelor din #REQ-053, `zeek -C -r pcap local ./mvp.zeek` e tot ce-ti
trebuie si e mult mai rapid de iterat — reproducibil, si nu blochezi pe hardware.

**Observatie pentru calibrarea pragurilor:** `tcpdump -i any` prinde tot traficul masinii, nu
doar ce generezi tu manual. In pcap-ul de test vei vedea conexiuni TLS catre Google, servere de
update, telemetrie etc. — chiar si o masina "idle" genereaza trafic TLS constant. Relevant cand
ajungi sa calibrezi pragurile detectoarelor: baseline-ul nu e niciodata gol.

**Atentie cand ajungi acolo:** `zeekctl deploy` suprascrie unele setari cu `zeekctl.cfg`.
Verifica in special ca nu-ti reintroduce rotatia (`Log::default_rotation_interval`).

---

## TROUBLESHOOTING RAPID

| Simptom | Cauza probabila |
|---|---|
| Nu se genereaza loguri deloc (pe pcap) | Lipseste `-C` → checksum offloading, toate pachetele aruncate |
| Nu se genereaza loguri deloc (alt caz) | Eroare de sintaxa in `mvp.zeek` — Zeek printeaza linia exacta |
| `warning: ...invalid TCP checksums...` | Idem — adauga `-C` |
| `possible loop/iterator invalidation` | `Log::disable_stream()` apelat in timpul iterarii peste `active_streams` — foloseste varianta cu vectorul `doomed` (pasul 5) |
| `mvp.zeek: no such file` | Lipseste `./` in fata numelui, sau nu esti in `~/zeek-work` |
| Logurile sunt TSV, nu JSON | Ai uitat `local ./mvp.zeek` la finalul comenzii |
| Zeek crapa la pornire | `@load packages` inainte de `zkg autoconfig` |
| `ssl.log` fara `ja3` | Pachetul zkg nu s-a instalat/incarcat — verifica `sudo zkg list`, si ca ai `@load packages` in mvp.zeek |
| `zkg: PermissionError` / `user does not have write access` | Ai facut `autoconfig` cu sudo, dar rulezi zkg fara — pune sudo la toate comenzile zkg |
| `zkg: invalid package ... package name not found` | Nume gresit — cauta cu `sudo zkg search <nume>`. Ex: `zeek/foxio/ja4`, nu `zeek/FoxIO-LLC/ja4` |
| Lipsesc loguri asteptate | Le-ai dezactivat in `zeek_init()` — adauga-le in `keep` |
| `ssl.log` gol pe pcap | Pcap-ul nu contine handshake TLS complet (ai capturat prea putine pachete) |
