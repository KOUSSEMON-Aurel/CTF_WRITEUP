# Writeup PicoCTF - My Git

**Challenge :** My Git
**Catégorie :** Git / Impersonation
**Points :** 50 pts
**Flag :** `picoCTF{1mp3rs0n4t4_g17_345y_220a9833}`

## Description

Le défi nous donne accès à un serveur Git personnalisé. L'objectif est de pousser un fichier `flag.txt` en utilisant une identité spécifique pour que le serveur nous renvoie le vrai flag.

## Étapes de la solution

### 1. Analyse du dépôt

Après avoir cloné le dépôt, l'examen du fichier `README.md` révèle la condition de succès :

> "Only flag.txt pushed by root:root@picoctf will be updated with the flag."

Le serveur vérifie donc l'auteur du commit lors du push.

### 2. Usurpation d'identité (Impersonation)

L'indice du challenge demande : "How do you specify your Git username and email?".
En Git, l'identité d'un commit est déterminée par les configurations `user.name` et `user.email`. On peut les modifier localement pour ce dépôt uniquement.

### 3. Exploitation (Commandes Git)

Voici la suite de commandes exécutées pour obtenir le flag :

```bash
# Se placer dans le dépôt
cd /home/aurel/CTF/challenge

# Configurer l'identité exigée par le serveur
git config user.name "root"
git config user.email "root@picoctf"

# Créer le fichier attendu
echo "placeholder" > flag.txt

# Commiter le fichier avec la nouvelle identité
git add flag.txt
git commit -m "Pushing flag.txt as root"

# Pousser vers le serveur (mot de passe : 4f7061f2)
git push origin master
```

### 4. Résultat

Lors du `push`, le serveur effectue une vérification côté serveur (probablement via un git hook `pre-receive` ou `update`) et affiche le flag directement dans la sortie de la console :

```text
remote: Author matched and flag.txt found in commit...
remote: Congratulations! You have successfully impersonated the root user
remote: Here's your flag: picoCTF{1mp3rs0n4t4_g17_345y_220a9833}
```

## Concepts clés retenus

* **Identité Git** : Les métadonnées d'un commit (`Author`) sont purement déclaratives et peuvent être facilement modifiées via `git config`.
* **Git Hooks** : Les serveurs Git peuvent exécuter des scripts lors d'un push pour valider le contenu ou l'identité.
* **Sécurité Git** : Il ne faut jamais se fier à l'identité déclarée dans un commit pour des contrôles d'accès critiques sans authentification forte (comme des clés GPG signées).
