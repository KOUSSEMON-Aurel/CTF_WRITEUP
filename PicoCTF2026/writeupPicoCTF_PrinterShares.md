# Writeup PicoCTF - Printer Shares

**Challenge :** Printer Shares
**Catégorie :** Énumération / SMB
**Points :** 50 pts
**Flag :** `picoCTF{p71n7_537v37_5mb_6412ab91}` (Exemple, à remplacer par le vrai si nécessaire)

## Description

Le défi consiste à récupérer un fichier important envoyé par erreur à une imprimante réseau via un serveur d'impression situé sur `mysterious-sea.picoctf.net` au port `56734`.

## Étapes de la solution

### 1. Analyse de l'énoncé

L'adresse et le port inhabituel (56734) associés au terme "print server" suggèrent l'utilisation du protocole **SMB (Server Message Block)**, couramment utilisé pour le partage d'imprimantes et de fichiers.

### 2. Énumération des partages

On commence par lister les ressources partagées pour identifier les accès possibles sans mot de passe (anonyme).

**Commande :**

```bash
smbclient -L //mysterious-sea.picoctf.net -p 56734 -N
```

* `-L` : Liste les partages.
* `-p 56734` : Spécifie le port non-standard.
* `-N` : Connexion sans mot de passe.

**Résultat :** Un partage nommé `shares` est identifié avec le commentaire "Public Share With Guests".

### 3. Connexion et Exploration

On se connecte au partage pour explorer le système de fichiers.

**Commande :**

```bash
smbclient //mysterious-sea.picoctf.net/shares -p 56734 -N
```

Une fois dans l'invite `smb: \>`, on liste les fichiers :

```bash
smb: \> ls
```

*Sortie :*

```text
  .         D      0  Fri Mar  6 20:25:46 2026
  ..        D      0  Fri Mar  6 20:25:46 2026
  dummy.txt N   1142  Wed Feb  4 21:22:17 2026
  flag.txt  N     37  Fri Mar  6 20:25:46 2026
```

### 4. Récupération du Flag

On télécharge le fichier `flag.txt` localement.

**Commande (dans smbclient) :**

```bash
smb: \> get flag.txt
```

Enfin, on quitte le client et on lit le fichier :

```bash
cat flag.txt
```

## Concepts clés retenus

* **SMB sur port non-standard** : Les services SMB ne sont pas toujours sur le port 445.
* **Permissions Anonymes** : Un serveur mal configuré permet l'accès invité (`-N` dans `smbclient`).
* **Outils d'énumération** : `smbclient` est essentiel pour interagir avec les partages Windows/Samba sous Linux.
