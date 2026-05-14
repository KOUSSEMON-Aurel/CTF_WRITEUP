# Writeup - Timeline 1 (picoCTF)

**Difficulté** : ★★★☆☆ (300 points)  
**Catégorie** : Forensics  
**Outils utilisés** : Sleuthkit (`fls`, `mactime`, `icat`), Base64

---

## 1. Description du Challenge

L'objectif est de trouver un flag caché dans une image disque en analysant les timestamps et en identifiant des actions suspectes.

---

## 2. Analyse et Exploitation

### Préparation
L'image disque était fournie sous forme compressée : `partition4.img.gz`.  
Après décompression, nous avons utilisé Sleuthkit pour extraire la chronologie des activités (MAC timeline).

### Génération de la Timeline
1. **Extraction des métadonnées** :  
   `fls -r -m / partition4.img > body`
2. **Création de la chronologie lisible** :  
   `mactime -b body > timeline.txt`

### Identification d'activités suspectes
En analysant la timeline, nous avons remarqué :
- Une activité intense peu avant l'arrêt du système (`poweroff`).
- Un fichier suspect situé dans `/etc/chat` avec des permissions inhabituelles et marqué avec les tags `macb` (création/modification récente).
- L'inode de ce fichier est **32716**.

### Extraction du Flag
Nous avons extrait le contenu de ce fichier à l'aide de `icat` :
```bash
icat partition4.img 32716
# Résultat : NTczNDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK
```
Le contenu est une chaîne encodée en **Base64**.  
Décodage :
```bash
echo "NTczNDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK" | base64 -d
# Résultat : 573417h13r_7h4n_7h3_1457_58527bb222
```

---

## 3. Flag Final

**Flag** : `picoCTF{573417h13r_7h4n_7h3_1457_58527bb222}`
