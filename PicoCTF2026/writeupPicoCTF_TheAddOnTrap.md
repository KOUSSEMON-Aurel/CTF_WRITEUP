# Writeup PicoCTF - The Add/On Trap

**Challenge :** The Add/On Trap
**Catégorie :** Web / Cryptography
**Points :** 200 pts
**Flag :** `picoCTF{Us3_4dd/0ns_v3ry_c4r3fully1}`

## Description

Le challenge consiste à analyser une extension de navigateur fournie au format `.xpi`. L'objectif est de trouver un flag caché à l'intérieur en inspectant le code source et en comprenant les mécanismes de chiffrement utilisés.

## Analyse de l'extension

Un fichier `.xpi` est une archive ZIP. Après extraction, on trouve plusieurs fichiers intéressants :

- `manifest.json` : Définit la configuration de l'extension.
- `background/main.js` : Contient la logique d'arrière-plan.

### Code de `background/main.js`

Le script contient les éléments suivants :

```javascript
// Secret key must be 32 url-safe base64-encoded bytes!
const key="cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
const webhookUrl='gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE'
```

### Décodage de la clé

La clé décodée en Base64 donne : `picoCTF{you're on the right tray}`.
Bien que cela ressemble à un flag, la présence d'un token commençant par `gAAAAA` (format typique de **Fernet**) suggère que cette clé est utilisée pour déchiffrer le token `webhookUrl`.

## Déchiffrement

Le format Fernet utilise une clé de 32 octets encodée en Base64.
À l'aide d'un script Python, nous pouvons déchiffrer le message :

```python
from cryptography.fernet import Fernet

key = "cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
token = "gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE"

f = Fernet(key)
flag = f.decrypt(token.encode()).decode()
print(flag)
```

**Résultat :** `picoCTF{Us3_4dd/0ns_v3ry_c4r3fully1}`

## Concepts clés retenus

* **Extensions de navigateur** : Les fichiers `.xpi` et `.crx` sont des archives contenant du code web (JS, HTML, CSS).
- **Fernet (Cryptography)** : Un système de chiffrement symétrique standardisé, souvent utilisé en Python, qui produit des tokens commençant par `gAAAAA`.
- **Analyse statique** : Toujours vérifier les commentaires et les chaînes de caractères codées dans les scripts d'arrière-plan.
