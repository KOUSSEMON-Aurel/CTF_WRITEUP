# Writeup : PasteZone - Challenge Hackviser

## 1. Introduction

PasteZone est une plateforme de partage de notes anonymes destinée à l'"underground digital". L'objectif était de récupérer les identifiants GitHub de l'administrateur (.hv) ainsi que son numéro de téléphone.

---

## 2. Énumération Initiale

### Interface Web

Le site propose plusieurs fonctionnalités :

- **Create Paste** : Création de notes avec titre et contenu.
- **Recent/Top Pastes** : Listes des notes publiques.
- **Services** : Page informative sur des services tiers (VPN, TOR hosting).

### Découvertes Fichiers

L'analyse nous a permis de découvrir plusieurs fichiers clés :

- `/database/pastezone.db` : Base de données SQLite principale.
- `/assets/db.sqlite` : Une version alternative de la base de données.
- `/view.php` : Script de visualisation des notes.

---

## 3. Analyse de la Vulnérabilité (RCE via SSTI)

L'analyse de `view.php` a révélé l'utilisation du moteur de template **Twig**. Le code incluait un filtre personnalisé dangereux :

```php
$filter = new \Twig\TwigFilter('system', function ($array) {
    if (is_array($array)) {
        ob_start();
        system($array[0]);
        $result = ob_get_clean();
        return htmlspecialchars($result);
    }
    return $array;
});
```

Cette fonction permettait d'exécuter des commandes système via Twig. Nous avons pu exploiter cela en créant une note avec le payload suivant :
`{{ ['id'] | filter('system') }}`

---

## 4. Chemin vers les Privilèges Root

Une fois l'exécution de code à distance (RCE) obtenue en tant qu'utilisateur `www-data`, nous avons cherché à élever nos privilèges.

### L'indice "Admin est ID 0"

L'utilisateur a donné un indice crucial : "Admin est ID 0". Bien que cela puisse suggérer une entrée dans la base de données, l'analyse du système a montré une autre réalité : **l'UID 0 (root)**.

### Exploitation des Capabilities Linux

En vérifiant les capacités des binaires, nous avons trouvé :
`/usr/bin/php8.4 cap_setuid=ep`

Cela signifie que le binaire PHP peut changer son propre UID. Nous avons utilisé notre RCE pour exécuter un script PHP élevant les privilèges à root :

```bash
php8.4 -r 'posix_setuid(0); system("ls -la /root");'
```

---

## 5. Capture des Flags (Identifiants & Téléphone)

### Identifiants GitHub

Dans le répertoire `/root`, nous avons trouvé le fichier `github.txt` :

- **Email/Pass** : `michaelcarter@mailbox.hv:MKEVQV5VsQ4qc`

### Numéro de Téléphone

Nous avons également découvert un script de sauvegarde nommé `/root/backup.py`. Son inspection a révélé les configurations Telegram de l'administrateur :

```python
API_ID = 12345678
API_HASH = "0123456789abcdef0123456789abcdef"
YOUR_PHONE = "+12025550123"
```

- **Téléphone** : `+12025550123`

---

## 6. Réflexions et Doutes

Pendant l'investigation, nous avons eu plusieurs moments de doute :

- **Confusion Initiale sur l'ID 0** : Nous avons d'abord cherché une note avec l'ID 0 dans `pastezone.db` avant de réaliser qu'il s'agissait du compte système `root` (UID 0).
- **Noisy DB** : Les centaines de notes générées par les outils de scan (`SSTI Test`, `cmd`, `q`) rendaient la lecture de la base de données difficile, nous forçant à utiliser des filtres SQL précis (`WHERE creator != 'Anonymous'`).
- **Impasse Stéganographique** : Nous avons brièvement suspecté des données cachées dans les favicons avant de privilégier la piste de l'élévation de privilèges via les capabilities.

---

## Conclusion

Le challenge a nécessité une compréhension de la template injection (Twig), une connaissance des privilèges système Linux (Capabilities) et une analyse minutieuse des scripts présents sur le serveur.
