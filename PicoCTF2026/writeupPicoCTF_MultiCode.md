# Writeup PicoCTF - MultiCode

**Challenge :** MultiCode
**Catégorie :** Obfuscation / Encoding
**Points :** 200 pts
**Flag :** `picoCTF{nested_enc0ding_66b54257}`

## Description

Le challenge présente un message caché derrière plusieurs couches d'encodage imbriquées : Base64, Hexadécimal, URL encoding et ROT13.

## Étapes de la solution

### 1. Couche 1 : Base64

Le contenu initial du fichier `message.txt` était :
`NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM2MzY2ZjM1MzQzMjM1MzcyNTM3NDQ=`

**Décodage :**

```bash
cat message.txt | base64 -d
```

*Résultat :* `637670625047532537426172666772715f72617030717661745f36366f3534323537253744`

### 2. Couche 2 : Hexadécimal

Le résultat précédent est une chaîne de caractères représentant des valeurs hexadécimales.

**Décodage :**

```bash
echo "6376..." | xxd -r -p
```

*Résultat :* `cvpbPGS%7Barfgrq_rap0qvat_66o54257%7D`

### 3. Couche 3 : URL Encoding

On observe des séquences `%7B` et `%7D`.

- `%7B` correspond à `{`
- `%7D` correspond à `}`

**Décodage :**
*Résultat :* `cvpbPGS{arfgrq_rap0qvat_66o54257}`

### 4. Couche 4 : ROT13

La chaîne `cvpbPGS` est une transformation ROT13 classique de `picoCTF`.

**Décodage final :**

```bash
echo "cvpbPGS{arfgrq_rap0qvat_66o54257}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

*Résultat :* `picoCTF{nested_enc0ding_66b54257}`

## Concepts clés retenus

* **Encodages imbriqués** : Savoir identifier les signatures des encodages courants (padding `=` pour Base64, `%` pour URL, pairs de caractères pour Hex).
- **CyberChef** : Un outil excellent pour automatiser ce genre de "pelage d'oignon".
- **ROT13** : Une constante dans les challenges introductifs.
