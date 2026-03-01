# Rapport d'Investigation CTF - Void

## Introduction

Ce rapport détaille l'investigation menée sur le serveur suspect `172.20.10.49`. L'objectif était d'identifier l'attaquant, d'analyser ses outils et de documenter ses activités malveillantes.

---

## 1. Accès Initial

L'analyse du serveur a révélé une instance de **Webmin 1.890** exposée sur le port `10000`. Ce service est vulnérable à la **CVE-2019-15107**, une exécution de code à distance (RCE) via le paramètre `expired` dans `password_change.cgi`.

L'exploitation de cette faille a permis d'obtenir un accès **root** complet sur le serveur.

---

## 2. Identification de l'Attaquant

L'identité de l'attaquant a été récupérée grâce aux traces laissées dans la configuration Git globale située dans `/root/.git/` :

- **Pseudonyme :** thevoid945
- **Email :** <timmycoat@anonymmail.hv>
- **Token/Password GitHub :** `wTWQzVeTD3vm`

---

## 3. Activités Malveillantes

### A. Phishing et Distribution de Malware

Dans le répertoire `/root`, un fichier nommé `phishing_malware.zip` a été trouvé.

- **Analyse du ZIP :** L'archive était protégée par mot de passe.
- **Crackage du mot de passe :** L'utilisation de `john` avec la wordlist `rockyou` a révélé le mot de passe : **`cookie`**.
- **Contenu :** Un fichier PDF malveillant nommé `phishing_malware.pdf`.
- **Preuve technique (MD5) :** `b82f8ba530a975e9f2acefe675fbffce`

### B. Command & Control (Stealer Logs)

Le serveur servait de réceptacle pour un "Stealer" (logiciel de vol de données). Les logs de la victime ont été trouvés dans `/home/void/Downloads/best-log/`.

- **Victime identifiée :** `christopher1d@zeromail.hv`
- **Données volées :** Mots de passe de réseaux sociaux, captures d'écran du bureau de la victime (Windows 11).

### C. Reconnaissance SQL Injection

L'attaquant utilisait l'outil **sqlmap** pour cibler des infrastructures bancaires.

- **Cible identifiée :** `albireobank.hv`
- **Localisation des preuves :** Répertoire `/root/.local/share/sqlmap/output/albireobank.hv`.

### D. Scanning de Réseau

Des traces d'utilisation de **Nmap** ont été trouvées à la racine du système dans `/nmap/`.

- **Cible scannée :** `45.76.59.241`
- **Détails :** Un scan de services et de ports agressif (`-sS -sV`) a été effectué sur cette IP pour identifier les services Apache et Microsoft RPC.

---

## 4. Réponses aux Questions du Challenge

| Question | Réponse |
| :--- | :--- |
| **MD5 du malware PDF** | `b82f8ba530a975e9f2acefe675fbffce` |
| **Domaine scanné via SQLi** | `albireobank.hv` |
| **Email de la victime** | `christopher1d@zeromail.hv` |
| **IP scannée par Nmap** | `45.76.59.241` |

---

## Conclusion

Le serveur `172.20.10.49` servait de plateforme multi-usage pour l'attaquant **thevoid945**. Ses activités allaient de la reconnaissance (Nmap, SQLmap) à l'exfiltration de données privées via des campagnes de phishing ciblées contre des utilisateurs Windows.
