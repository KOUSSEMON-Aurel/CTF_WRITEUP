# Writeup PicoCTF - Forensics Git 2

**Challenge :** Forensics Git 2
**Catégorie :** Forensics
**Points :** 400 pts
**Flag :** `picoCTF{g17_r35cu3_16ac6bf3}`

## Description

Le challenge demande de récupérer un dépôt Git corrompu après une tentative de suppression interrompue sur une image disque.

## Analyse et Récupération

L'image disque `disk.img` contient un système de fichiers Linux sur la partition 3.
Nous explorons le répertoire personnel de `ctf-player` avec `fls` et trouvons un dépôt Git dans `Code/killer-chat-app/.git`.

L'extraction directe avec `tsk_recover` ne permet pas d'utiliser les commandes `git` car le répertoire `refs/heads` est manquant (probablement supprimé).

## Réparation du dépôt

En consultant `logs/HEAD` dans le répertoire `.git`, nous voyons l'historique complet des commits avec leurs condensés (hashes).
Nous "réparons" manuellement le dépôt en créant les répertoires manquants et en pointant la branche `master` vers le dernier commit :

```bash
mkdir -p .git/refs/heads
echo "01533f718556a0e59f1467dae4fa462eed82c2a1" > .git/refs/heads/master
```

## Extraction du flag

Une fois le dépôt fonctionnel, nous inspectons l'historique :

```bash
git log --oneline
```

Nous voyons un commit suspect : `e80b38b Add secret hideout chat log`, suivi de `2151ef0 Remove secret hideout log`.

L'inspection de ce commit révèle le contenu du fichier ajouté (`logs/3.txt`) :

```bash
git show e80b38b
```

**Contenu de logs/3.txt :**

```text
Rex: Meet at the old arcade basement for the secret hideout.
Jay: Ask Rusty at the door and use password picoCTF{g17_r35cu3_16ac6bf3}.
Rex: Bring the decoder map so we can plan the route.
```

**Flag :** `picoCTF{g17_r35cu3_16ac6bf3}`

## Concepts clés retenus

* **Réparation de structures Git** : Un dépôt Git peut être restauré si les objets et les logs sont présents, même si les références (`refs`) sont perdues.
* **Analyse de l'historique Git** : Les informations supprimées dans les commits récents restent accessibles via les objets et le journal (reflog/logs).
* **Forensics de fichiers supprimés** : Utiliser `tsk_recover -e` pour extraire tous les fichiers, y compris ceux alloués mais potentiellement endommagés.
