# Writeup PicoCTF - Hidden Cipher 1

**Challenge :** Hidden Cipher 1
**Catégorie :** Reversing
**Points :** 100 pts
**Flag :** `picoCTF{xor_unpack_4nalys1s_425e5956}`

## Description

Le challenge demande de trouver un flag chiffré dissimulé dans un binaire. Un indice suggère que le binaire est packé et qu'il utilise un chiffrement XOR.

## Analyse du binaire

Le binaire `hiddencipher` est un ELF 64-bit packé avec **UPX**, comme le confirment les chaînes de caractères visibles (« UPX! »).

### 1. Comportement

L'exécution locale du binaire affiche :

```bash
Here your encrypted flag:
235a201d70201548251358110c552f135409
```

Ce flag local se déchiffre en `picoCTF{fake_flag}`. Cela confirme que la logique de chiffrement est présente dans le binaire.

### 2. Chiffrement XOR

En comparant les premiers octets du flag chiffré (`23 5a 20 1d ...`) avec le préfixe connu `picoCTF{` (`70 69 63 6f ...`), on peut déduire la clé XOR :

- `0x23 ^ 'p' (0x70) = 0x53 ('S')`
- `0x5a ^ 'i' (0x69) = 0x33 ('3')`
- `0x20 ^ 'c' (0x63) = 0x43 ('C')`
- `0x1d ^ 'o' (0x6f) = 0x72 ('r')`
- `0x70 ^ 'C' (0x43) = 0x33 ('3')`
- `0x20 ^ 'T' (0x54) = 0x74 ('t')`

La clé est la chaîne répétitive **`S3Cr3t`**.

## Récupération du flag

En se connectant au serveur distant (`nc candy-mountain.picoctf.net 56012`), on reçoit une autre chaîne hexadécimale :
`235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d07466656764b06422e`

### Script de déchiffrement (Python)

```python
hex_str = '235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d07466656764b06422e'
key = 'S3Cr3t'
bytes_list = bytes.fromhex(hex_str)
flag = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(bytes_list))
print(flag)
```

**Résultat :**
`picoCTF{xor_unpack_4nalys1s_425e5956}`

## Concepts clés retenus

* **UPX Packing** : Les développeurs utilisent souvent des packers comme UPX pour masquer la logique de leur programme et réduire sa taille.
- **Propriétés du XOR** : Si `A ^ B = C`, alors `A ^ C = B`. On peut retrouver la clé si on connaît une partie du message clair (Known Plaintext Attack).
- **Analyse de flux** : Parfois, l'exécution locale d'un binaire de challenge ("fake flag") est nécessaire pour valider une hypothèse avant de l'appliquer au serveur distant.
