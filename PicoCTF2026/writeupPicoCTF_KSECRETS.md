# Writeup PicoCTF - KSECRETS

**Challenge :** KSECRETS
**Catégorie :** Kubernetes / Secrets
**Points :** 100 pts
**Flag :** `picoCTF{ks3cr375_41n7_s4f3_e0eeefa6}`

## Description

Le défi nous donne accès à un cluster Kubernetes via un fichier `kubeconfig`. L'objectif est de trouver un flag stocké dans les secrets du cluster.

## Étapes de la solution

### 1. Préparation de l'environnement

Téléchargement du fichier de configuration et installation de `kubectl` :

```bash
wget -O kubeconfig http://green-hill.picoctf.net:58100/kubeconfig
curl -LO "https://dl.k8s.io/release/stable/bin/linux/amd64/kubectl"
chmod +x kubectl
```

### 2. Configuration du cluster

Le fichier `kubeconfig` pointait vers `localhost` par défaut. Il a fallu modifier le champ `server` pour cibler l'instance distante :

```yaml
server: https://green-hill.picoctf.net:52823
```

### 3. Énumération des secrets

Utilisation de `kubectl` pour lister tous les secrets dans tous les namespaces (en ignorant la vérification TLS comme demandé) :

```bash
./kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify get secrets -A
```

*Résultat :* Un secret nommé `ctf-secret` a été trouvé dans le namespace `picoctf`.

### 4. Extraction et décodage

Récupération de la donnée encodée du secret :

```bash
./kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify get secret ctf-secret -n picoctf -o jsonpath='{.data.flag}'
```

*Donnée encodée :* `cGljb0NURntrczNjcjM3NV80MW43X3M0ZjNfZTBlZWVmYTZ9Cg==`

Les secrets Kubernetes sont encodés en **base64** par défaut. Le décodage révèle le flag :

```bash
echo "cGljb0NURntrczNjcjM3NV80MW43X3M0ZjNfZTBlZWVmYTZ9Cg==" | base64 -d
```

## Concepts clés retenus

* **Kubernetes Secrets** : Ce ne sont pas des mécanismes de stockage sécurisés par défaut, car ils sont simplement encodés en base64. N'importe qui ayant accès à l'API peut les lire.
* **Kubeconfig** : Fichier essentiel regroupant l'adresse du serveur, les certificats et les tokens d'accès.
* **Namespaces** : Il est important de chercher les ressources au-delà du namespace par défaut (`default`).
