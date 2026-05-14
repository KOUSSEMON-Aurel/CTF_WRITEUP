# Writeup PicoCTF - DISKO 4

**Challenge :** DISKO 4
**Catégorie :** Forensics
**Points :** 200 pts
**Flag :** `picoCTF{d3l_d0n7_h1d3_w3ll_fe34c2cb}`

## Description

Le challenge demande de retrouver un flag qui a été délibérément supprimé d'une image disque fournie au format `.dd.gz`.

## Analyse de l'image

L'image disque est compressée (`disko-4.dd.gz`). Après décompression, nous obtenons un fichier brut `disko-4.dd`.
L'analyse avec `file` indique qu'il s'agit d'un système de fichiers FAT32 (secteur de boot DOS/MBR directement présent).

## Exploration et Récupération

Pour lister les fichiers présents sur l'image, y compris ceux supprimés, nous utilisons l'outil `fls` de la suite *The Sleuth Kit*.

### Listing des fichiers

```bash
fls -r disko-4.dd
```

Parmi les nombreux fichiers journaux, un fichier marqué comme supprimé (astérisque `*`) attire l'attention :
`r/r * 532021: dont-delete.gz`

L'inode associé est **532021**.

### Extraction du fichier

Nous utilisons `icat` pour extraire les données associées à cet inode :

```bash
icat disko-4.dd 532021 > recovered.gz
```

### Lecture du flag

Le fichier extrait est une archive GZip. Nous le décompressons pour lire son contenu :

```bash
gunzip -c recovered.gz
```

**Résultat :**
`Here is your flag`
`picoCTF{d3l_d0n7_h1d3_w3ll_fe34c2cb}`

## Concepts clés retenus

* **Récupération de fichiers supprimés** : Sur des systèmes de fichiers comme FAT32, la suppression d'un fichier ne détruit pas immédiatement les données, mais marque seulement l'entrée du répertoire comme libre.
* **The Sleuth Kit (TSK)** : Des outils comme `fls` et `icat` sont essentiels pour l'analyse forensique d'images disques sans avoir à les monter.
* **Analyse d'image brute** : Savoir identifier le système de fichiers sous-jacent à une image `.dd`.
