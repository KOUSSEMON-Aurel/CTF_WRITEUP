# Writeup PicoCTF - Timeline 0

**Challenge :** Timeline 0
**Catégorie :** Forensics
**Points :** 100 pts
**Flag :** `picoCTF{71m311n3_0u7113r_h3r_43a2e7af}`

## Description

Le but de ce challenge était de trouver un flag caché dans une image disque en analysant les horodatages des fichiers. L'indice suggérait que le "timestomping" (modification manuelle des dates) pouvait avoir laissé des traces sous forme de timestamps très anciens.

## Étapes de la solution

### 1. Préparation de l'image

L'image fournie était compressée :

```bash
gunzip -c partition4.img.gz > partition4.img
```

### 2. Génération de la MAC Timeline

J'ai utilisé les outils de **The Sleuth Kit** (`fls` et `mactime`) pour analyser la structure de l'image et générer une chronologie des activités sur les fichiers.

```bash
# Génération du fichier "body"
fls -r -m / partition4.img > timeline.body

# Recherche des timestamps anormaux (très anciens)
awk -F"|" '$9 < 1000000000 && $9 > 0 {print $0}' timeline.body
```

**Résultat :**
J'ai identifié un fichier particulier nommé `/bin/bcab` (inode 4945) dont l'horodatage de modification datait du **1er janvier 1985** (`473446800`), ce qui est totalement incohérent avec le reste du système.

### 3. Extraction du Flag

J'ai extrait le contenu de ce fichier suspect :

```bash
icat partition4.img 4945
```

Le contenu était une chaîne encodée en Base64 : `NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK`.

### 4. Décodage

```bash
echo "NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK" | base64 -d
```

Cela produit la chaîne : `71m311n3_0u7113r_h3r_43a2e7af`.

**Flag :** `picoCTF{71m311n3_0u7113r_h3r_43a2e7af}`

## Concepts clés retenus

* **MAC Timeline** : L'analyse des dates de Modification, Accès et Changement (MAC) est cruciale en forensics pour repérer des anomalies ou reconstruire une chronologie d'événements.
* **Timestomping** : Une technique anti-forensics consistant à changer délibérément les dates des fichiers. Cependant, un choix de date trop ancien ou incohérent devient facile à repérer.
* **The Sleuth Kit (TSK)** : Utilisation de `fls` (listing), `icat` (extraction) et `mactime` (chronologie).
