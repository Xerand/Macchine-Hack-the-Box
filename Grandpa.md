# Macchina Grandpa

ip vittima: 10.129.93.14
ip attacante: 10.10.14.245

## Recon

`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.93.14 -oG porte`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010230823.png)

`nmap -sC -sV -p80 10.129.93.14 -oN servizi`
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010230930.png)

Il servizio Microsoft IIS httpd 6.0 è soggetto alla vulnerabilità CVE-2017-7269 (ricerca su google)
Si può usare l'exploit WebDav 'ScStoragePathFromUrl' Remote Overflow  di Metasploit

## Porta 80

### exploit CVE-2017-7269

Metasploit:
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010232050.png)

Una volta lanciato l'exploit con run entriamo in una sessione meterpreter. Con getuid possiamo vedere l'utente
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010232237.png)

Se lanciando getuid riceviamo l'errore access denied
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Screenshot-2020-04-24-at-15.41.37.png)

possiamo listare i processi con "ps" e migrare su un processo con user NT AUTHORITY\NETWORK SERVICE
con migrate (PID PROCESSO)

### scalata dei privilegi

Mettiamo la sessione meterpreter in background (comando background) creando una sessione
Carichiamo in metasploit lo strumento post multi/recon/local_exploit_suggester
Lanciandolo (run) con la sessione creata prima con il comando background cerca degli exploit per poter scalare i privilegi
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010233542.png)

Lo strumento trova i seguenti exploit che potrebbero funzionare
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010233714.png)

Occorre provarli per trovare quello funzionante che è 
exploit/windows/local/ms15_051_client_copy_image
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251010233857.png)

Lanciandolo si accede come root

#### flag Harry

La flag di Harry si trova nel file user.txt nella directory C:\Documents and Settings\Harry\Desktop

#### flag root

La flag root si trova nel file root.txt nella directory C:\Documents and Settings\Administrator\Desktop

