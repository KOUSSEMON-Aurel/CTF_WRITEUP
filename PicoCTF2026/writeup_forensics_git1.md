# Writeup - Forensics Git 1 (picoCTF)

**Difficulté** : ★★★☆☆ (300 points)  
**Catégorie** : Forensics  
**Outils utilisés** : Sleuthkit (`mmls`, `fls`, `tsk_recover`), `git`

---

## 1. Description du Challenge

L'objectif est de trouver un flag caché dans une image disque contenant un dépôt Git. Il faut explorer l'historique du dépôt pour retrouver des données qui auraient pu être supprimées.

---

## 2. Analyse de l'Image Disque

### Identification des Partitions
Après décompression de `disk.img.gz`, nous analysons la table des partitions avec `mmls` :
```bash
mmls disk.img
```
| Slot | Start | End | Description |
| :--- | :--- | :--- | :--- |
| 002 | 2048 | 616447 | Linux (Boot/System) |
| 004 | 1140736 | 2097151 | Linux (User data) |

La partition d'intérêt est la deuxième partition Linux (Slot 004).

---

## 3. Extraction et Localisation du Dépôt Git

Nous utilisons `tsk_recover` pour extraire les fichiers de la partition de données :
```bash
mkdir git_extracted
tsk_recover -e -o 1140736 disk.img git_extracted/
```

En explorant les fichiers extraits, nous trouvons un dépôt Git dans le répertoire personnel d'un utilisateur :
`/home/ctf-player/Code/secrets/.git`

---

## 4. Analyse de l'Historique Git

Nous nous déplaçons dans le dépôt et inspectons les commits :
```bash
git -C git_extracted/home/ctf-player/Code/secrets log --all --oneline
```
**Résultat** :
- `5fb8194` (HEAD -> master) Remove flag
- `177789a` Add flag

L'historique montre clairement que le flag a été ajouté puis supprimé.

---

## 5. Récupération du Flag

Nous affichons les modifications apportées par le commit `177789a` :
```bash
git -C git_extracted/home/ctf-player/Code/secrets show 177789a
```
```diff
diff --git a/flag.txt b/flag.txt
new file mode 100644
index 0000000..f150f47
--- /dev/null
+++ b/flag.txt
@@ -0,0 +1 @@
+picoCTF{g17_r3m3mb3r5_d4ddf904}
```

---

## 6. Flag Final

**Flag** : `picoCTF{g17_r3m3mb3r5_d4ddf904}`
