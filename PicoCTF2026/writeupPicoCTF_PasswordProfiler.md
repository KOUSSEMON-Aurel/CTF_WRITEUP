# Writeup PicoCTF - Password Profiler

**Challenge :** Password Profiler
**Catégorie :** OSINT / Cracking
**Points :** 100 pts
**Flag :** `picoCTF{Aj_15901990}`

## Description

L'objectif était de retrouver un mot de passe à partir de son hash SHA-1 et d'informations personnelles sur la cible (Alice Johnson).

## Étapes de la solution

### 1. Analyse des informations personnelles

Le fichier `userinfo.txt` contenait :

- Prénom : Alice
- Nom : Johnson
- Surnom : AJ
- Date de naissance : 15-07-1990
- Partenaire : Bob
- Enfant : Charlie

### 2. Génération de la wordlist avec CUPP

J'ai utilisé **CUPP (Common User Passwords Profiler)**, un outil Python permettant de générer des dictionnaires basés sur des données personnelles.

**Commande d'installation :**

```bash
git clone https://github.com/Mebus/cupp.git
```

**Commande de génération :**
J'ai fourni les informations d'Alice à l'outil en mode interactif (`python3 cupp.py -i`).

### 3. Script de vérification (Extraction du mot de passe)

Le script `check_password.py` a été utilisé pour tester chaque mot de passe de la liste générée contre le hash SHA-1 cible : `968c2349040273dd57dc4be7e238c5ac200ceac5`.

**Script `check_password.py` :**

```python
import hashlib

HASH_FILE = "hash.txt"
WORDLIST_FILE = "passwords.txt"

def crack_password(target_hash):
    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for password in f:
            password = password.strip()
            if hashlib.sha1(password.encode()).hexdigest() == target_hash:
                return password
    return None

# ... (reste du script)
```

### 4. Résultat

Après avoir généré `alice.txt` et l'avoir renommé en `passwords.txt`, l'exécution du script a trouvé la correspondance :

```text
Password found: picoCTF{Aj_15901990}
```

## Concepts clés retenus

* **Dictionary Attacks (Profilées)** : Les utilisateurs tendent à utiliser des informations prévisibles (noms, dates) dans leurs mots de passe.
- **Outils d'OSINT/Profiling** : CUPP est extrêmement efficace pour réduire considérablement l'espace de recherche par rapport à une attaque par force brute classique.
