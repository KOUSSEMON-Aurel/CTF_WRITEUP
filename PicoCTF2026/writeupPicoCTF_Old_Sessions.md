# Writeup PicoCTF - Old Sessions

**Challenge :** Old Sessions
**Catégorie :** Web Exploitation
**Points :** 100 pts
**Flag :** `picoCTF{s3t_s3ss10n_3xp1rat10n5_77b6684a}`

## Description

Le challenge porte sur une faille de gestion des sessions. Le site Web est configuré de manière à ce que les sessions n'expirent jamais ("un fois connecté, plus besoin de se reconnecter"). L'objectif est de trouver un moyen de détourner une session active, idéalement celle de l'administrateur.

## Analyse du challenge

### 1. Exploration initiale

En naviguant sur le site (`http://dolphin-cove.picoctf.net:56705/login`), on découvre une application de type "New Twitter". Après avoir créé un compte de test, on accède à la page d'accueil.

### 2. Découverte d'un indice

Dans les commentaires de la page d'accueil, un utilisateur (`mary_jones_8992`) mentionne :
> "Hey I found a strange page at /sessions"

### 3. Analyse de la page `/sessions`

En accédant à `/sessions` tout en étant authentifié, le serveur affiche la liste de toutes les sessions actives stockées en mémoire :

```text
1) session:hC7SwHZ8RxZYnv2zO0G6nO9kyoumqKuR1FgssXlWSkc, {'_permanent': True, 'key': 'admin'}
...
12) session:AMigsOrpz919C5Qfuj59nwYG5wpYaRCz2zEZkyLdkiQ, {'_permanent': True, 'key': 'Aurel'}
```

On identifie immédiatement le cookie de session de l'administrateur : `hC7SwHZ8RxZYnv2zO0G6nO9kyoumqKuR1FgssXlWSkc`.

## Étapes de la solution

### 1. Détournement de session (Session Hijacking)

Il suffit de remplacer son propre cookie `session` par celui de l'administrateur dans le navigateur (ou via `curl`).

### 2. Récupération du flag

En rafraîchissant la page d'accueil avec le cookie d'admin, un message spécial apparaît dans le bandeau supérieur :

```html
<p class="flag-message">picoCTF{s3t_s3ss10n_3xp1rat10n5_77b6684a}</p>
```

**Flag :** `picoCTF{s3t_s3ss10n_3xp1rat10n5_77b6684a}`

## Concepts clés retenus

* **Session Timeout** : Les sessions doivent avoir une durée de vie limitée (expiration) pour réduire la fenêtre d'opportunité d'une attaque en cas de vol de cookie.
* **Information Disclosure** : Exposer la liste des sessions actives (même de manière "cachée") est une vulnérabilité critique permettant le détournement de compte immédiat.
* **Insécurité par l'usage** : Ne jamais se déconnecter (sessions infinies) augmente considérablement les risques de sécurité.
