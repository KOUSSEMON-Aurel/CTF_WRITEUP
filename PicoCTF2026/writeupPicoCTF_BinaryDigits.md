# Writeup PicoCTF - Binary Digits

**Challenge :** Binary Digits
**Catégorie :** Forensics / Cryptography
**Points :** 100 pts
**Flag :** `picoCTF{h1dd3n_1n_th3_b1n4ry_a59b2b0a}`

## Description

Le fichier `digits.bin` contient une longue suite de `1` et de `0`. L'objectif est de retrouver un message caché dans ce "bruit".

## Étapes de la solution

### 1. Analyse du fichier

Le fichier fait environ 70 Ko et ne contient que les caractères ASCII `1` et `0`.
Les premiers bits sont `11111111 11011000`. Convertis en hexadécimal, cela donne `FF D8`, ce qui est le nombre magique (magic number) d'un fichier **JPEG**.

### 2. Conversion des bits en octets

J'ai utilisé un script Python pour lire la chaîne de bits et convertir chaque groupe de 8 bits en un octet binaire.

```python
def solve():
    with open("digits.bin", "r") as f:
        binary_str = f.read().strip()
    
    # Conversion de blocs de 8 bits en octets
    byte_list = []
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) == 8:
            byte_list.append(int(byte, 2))
    
    # Écriture du fichier JPEG
    with open("recovered.jpg", "wb") as f:
        f.write(bytearray(byte_list))
```

### 3. Récupération du flag

L'image `recovered.jpg` générée contient le flag écrit en rouge au centre de l'image.

**Flag :** `picoCTF{h1dd3n_1n_th3_b1n4ry_a59b2b0a}`

## Concepts clés retenus

* **Représentation binaire** : Un fichier peut être représenté sous forme de texte (0/1) avant d'être reconverti en binaire pur.
* **File Signatures** : Connaître les signatures de fichiers (`FF D8` pour JPEG, `89 50 4E 47` pour PNG) permet d'identifier rapidement la nature d'un blob de données.
