# Writeup PicoCTF - Forensics Git 0

**Challenge :** Forensics Git 0
**Catégorie :** Forensics
**Points :** 200 pts
**Flag :** `picoCTF{g17_1n_7h3_d15k_041217d8}`

## Description

Le challenge demande de trouver un flag caché dans une image disque. Le nom suggère l'utilisation de Git.

## Analyse de l'image

L'image disque `disk.img` possède 3 partitions. La partition 3 (offset 1140736) contient le système de fichiers racine Linux.

## Exploration

À l'aide de `fls`, nous explorons le répertoire personnel de l'utilisateur `ctf-player` :

```bash
fls -o 1140736 -r disk.img 64771
```

Nous identifions un répertoire suspect : `/home/ctf-player/Code/secrets/.git`.

## Recherche du flag dans les métadonnées Git

Dans un dépôt Git, le fichier `logs/HEAD` contient l'historique de tous les mouvements du pointeur HEAD, y compris les messages de commit.

Extraction du fichier avec `icat` :

```bash
icat -o 1140736 disk.img 65704
```

**Sortie :**
`0000000000000000000000000000000000000000 327681bb38cf467cec328eec9707b240e3e74ced ctf-player <ctf-player@example.com> 1763542167 +0000  commit (initial): Wrap this phrase in the flag format: g17_1n_7h3_d15k_041217d8`

Le message de commit contient la phrase : `g17_1n_7h3_d15k_041217d8`.

Un fichier `note.txt` (inode 65692) dans le même répertoire précise :
`The picoCTF flag format is 'picoCTF{}' where there is some leetspeak phrase in between the curly braces`

En combinant les deux, nous obtenons le flag.

**Flag :** `picoCTF{g17_1n_7h3_d15k_041217d8}`

## Concepts clés retenus

* **Analyse de partitions** : Utiliser `mmls` pour identifier les offsets des partitions.
* **Exploration Git** : Même si les fichiers d'un dépôt Git sont supprimés ou modifiés, l'historique dans `.git/logs/HEAD` ou les objets Git peuvent contenir des informations sensibles.
* **The Sleuth Kit** : Utilisation de `fls` et `icat` pour naviguer et extraire des fichiers sans montage.
