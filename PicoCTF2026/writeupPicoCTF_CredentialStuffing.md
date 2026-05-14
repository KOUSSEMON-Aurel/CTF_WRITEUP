# Writeup PicoCTF - Credential Stuffing

**Challenge :** Credential Stuffing
**Catégorie :** General Skills / Web Exploitation
**Points :** 100 pts
**Flag :** `picoCTF{d0nt_r3u5e_cr3d3nt1als_817212a0}`

## Description

Le challenge illustre les dangers de la réutilisation des mots de passe. On nous fournit un dump d'identifiants (utilisateurs et mots de passe) provenant d'une faille de sécurité fictive. L'objectif est de trouver le bon couple pour se connecter à un service de banque en ligne.

## Analyse des fichiers

Le fichier `creds-dump.txt` contient environ 1500 lignes au format `username;password`.

## Exploitation

Tester manuellement 1500 combinaisons est impossible. J'ai donc automatisé l'attaque avec un script Python utilisant la bibliothèque `pwntools` et `ThreadPoolExecutor` pour paralléliser les tentatives de connexion.

### Stratégie

- Lire le fichier `creds-dump.txt`.
- Diviser chaque ligne pour extraire l'utilisateur et le mot de passe.
- Se connecter à `crystal-peak.picoctf.net` sur le port `55450` (port corrigé dynamiquement par le script).
- Envoyer les identifiants et vérifier si la réponse contient la chaîne "picoCTF".

### Résultat de l'attaque

Le script a identifié l'utilisateur valide :

- **Username :** `hayes`
- **Password :** `farley`

Lors de la connexion, le serveur affiche le message de bienvenue et le flag.

**Flag :** `picoCTF{d0nt_r3u5e_cr3d3nt1als_817212a0}`

## Concepts clés retenus

* **Credential Stuffing** : Cette attaque repose sur la paresse des utilisateurs qui utilisent le même mot de passe sur plusieurs services.
- **Automatisation** : En CTF, savoir scripter des interactions réseau (`nc`, `pwntools`) est essentiel pour gérer de grands volumes de données.
- **Multi-threading** : Pour les attaques de type brute-force ou stuffing sur le réseau, l'utilisation de threads permet de gagner un temps considérable.
