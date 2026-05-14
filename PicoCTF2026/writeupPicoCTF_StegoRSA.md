# Writeup PicoCTF - StegoRSA

**Challenge :** StegoRSA
**Catégorie :** Steganography / Cryptography
**Points :** 100 pts
**Flag :** `picoCTF{rs4_k3y_1n_1mg_a9a7c4c9}`

## Description

Le challenge fournit un fichier chiffré (`flag.enc`) et une image JPEG. L'objectif est de retrouver la clé privée RSA cachée dans l'image pour déchiffrer le message.

## Étapes de la solution

### 1. Analyse des métadonnées

En examinant les métadonnées de `image.jpg` avec `exiftool`, on découvre une chaîne hexadécimale inhabituelle dans le champ `Comment`.

```bash
exiftool image.jpg
```

**Résultat :**
`Comment : 2d2d2d2d2d424547494e...`

### 2. Extraction de la clé privée

La chaîne hexadécimale commence par `2d2d2d2d2d` (`-----`), ce qui indique le début d'un bloc PEM. On convertit cette chaîne en texte :

```bash
# Extraction et conversion
exiftool -Comment image.jpg | cut -d: -f2- | tr -d ' ' > key.hex
python3 -c "import binascii; print(binascii.unhexlify(open('key.hex').read().strip()).decode())" > private_key.pem
```

Le fichier `private_key.pem` contient maintenant une clé privée RSA valide.

### 3. Déchiffrement du flag

On utilise `openssl` pour déchiffrer le fichier `flag.enc` avec la clé récupérée :

```bash
openssl pkeyutl -decrypt -inkey private_key.pem -in flag.enc
```

**Résultat :** `picoCTF{rs4_k3y_1n_1mg_a9a7c4c9}`

## Concepts clés retenus

* **Stéganographie en métadonnées** : Les champs comme `Comment`, `Artist` ou des tags personnalisés sont des endroits classiques pour cacher des données.
* **RSA Private Key** : La connaissance de la clé privée permet de déchiffrer tout message chiffré avec la clé publique correspondante.
* **Encodage Hex** : Souvent utilisé pour masquer du texte clair ou des structures PEM dans des champs de métadonnées.
