# Command Injection in Perl-Based Stock Control System - Hackviser Writeup

## Introduction
Ce laboratoire Hackviser nous a mis au défi de découvrir une vulnérabilité d'injection de commande dans un système de contrôle de stock basé sur Perl. L'objectif était d'exécuter des commandes à distance sur le serveur et de récupérer le nom d'hôte de la machine.

## Analyse de l'application
L'application web est accessible à l'adresse `https://actual-jackpot.europe1.hackviser.space`. En visitant l'URL, nous avons découvert une interface simple de "Stock Control | Photo Cameras" qui permet à l'utilisateur de sélectionner un modèle de caméra dans une liste déroulante et de cliquer sur un bouton "Check" pour vérifier le stock.

Après avoir inspecté le code source de la page (`homepage_content.html`), nous avons identifié un formulaire HTML qui soumet les données via la méthode `POST` à la même URL. Le champ de sélection pour les caméras est nommé `search`.

```html
<form action="" method="post">
  <div class=" mt-3 fs-5" style="margin-left: 2px;">
    Select an item to check:
  </div>
  <select class="form-select form-select-lg  mt-2" name="search" style="width: 500px;" id="opt">
    <option selected value="">
      Select a camera
    </option>
    <option value="canon-eos-rebel-t7">
      Canon EOS Rebel T7
    </option>
    <!-- ... autres options ... -->
  </select>
  <div class="d-flex justify-content-center">
    <button type="submit" class="btn btn-warning mt-4">
      Check
    </button>
  </div>
</form>
```

Le paramètre `search` semble être le point d'entrée clé, car la description du laboratoire mentionnait un script Perl de vérification de stock.

## Découverte de la vulnérabilité
Nous avons d'abord envoyé une requête `POST` normale avec une valeur valide pour le paramètre `search` afin de comprendre le comportement attendu de l'application :

```bash
curl -X POST -d "search=canon-eos-rebel-t7" https://actual-jackpot.europe1.hackviser.space
```

La réponse a confirmé que le formulaire fonctionnait en affichant "Number of products in stock: **5**".

Étant donné que l'application est susceptible d'une injection de commande et utilise Perl en arrière-plan, nous avons supposé que la valeur du paramètre `search` était directement passée à une commande système sans assainissement adéquat. Nous avons tenté d'injecter la commande `hostname` en utilisant le caractère `;` (point-virgule) pour enchaîner les commandes sur les systèmes de type Unix.

## Exploitation
La commande d'injection suivante a été utilisée :

```bash
curl -X POST -d "search=canon-eos-rebel-t7;hostname" https://actual-jackpot.europe1.hackviser.space
```

L'idée était que la valeur `canon-eos-rebel-t7` serait traitée, puis la commande `hostname` serait exécutée. Si l'injection réussissait, la sortie de `hostname` devrait apparaître quelque part dans la réponse HTML.

La réponse de la requête `curl` contenait la ligne suivante :

```html
<div class="alert alert-success text-center" style="width: 500px;" role="alert">Number of products in stock: <b>5brilliance </b></div>
```

Comme on peut le voir, la chaîne "brilliance" est apparue directement après le nombre de produits en stock. Cela confirme l'exécution réussie de la commande `hostname` et que "brilliance" est le nom d'hôte du serveur.

## Preuve
Le nom d'hôte du serveur est : `brilliance`
