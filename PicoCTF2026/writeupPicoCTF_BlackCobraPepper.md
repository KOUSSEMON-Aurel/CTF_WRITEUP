# Writeup PicoCTF - Black Cobra Pepper

**Challenge :** Black Cobra Pepper
**Catégorie :** Cryptography
**Points :** 200 pts
**Flag :** `picoCTF{spi1cy!}`

## Description

Le challenge fournit un script Python `chall.py` implémentant une variante d'AES, et un fichier `output.txt` contenant deux textes chiffrés :

1. Le chiffré d'un texte connu (`pt1`).
2. Le chiffré du flag.

L'objectif est de retrouver le flag malgré l'absence de la clé.

## Analyse de l'algorithme

En examinant `chall.py`, on remarque plusieurs simplifications par rapport à l'AES standard :

- `sub_bytes` est une fonction identité (retourne l'état inchangé).
- `sub_word` est une fonction identité.
- `rcon` est une fonction identité.

Ces modifications suppriment toute non-linéarité (S-Box) du chiffrement. L'algorithme devient une transformation purement linéaire sur le corps fini utilisé (GF(2) ou GF(2^8)).

## Exploitation

Puisque le chiffrement est linéaire, nous pouvons écrire :
$AES(P, K) = f(P) \oplus G(K)$
où $f$ est la partie linéaire dépendant du texte clair (ShiftRows, MixColumns) et $G$ la partie dépendant de la clé.

On nous donne :

- $C_1 = AES(pt1, key)$
- $C_2 = AES(flag, key)$

En calculant le XOR des deux chiffrés :
$C_1 \oplus C_2 = (f(pt1) \oplus G(key)) \oplus (f(flag) \oplus G(key)) = f(pt1) \oplus f(flag) = f(pt1 \oplus flag)$

Où $f(P)$ est simplement le résultat de `AES(P, key=0)`.

### Étapes de résolution

1. Calculer $D = C_1 \oplus C_2$.
2. Puisque $f$ est une permutation linéaire de l'espace de 128 bits, nous pouvons construire sa matrice de transformation bit à bit.
3. Inverser cette matrice pour retrouver $X = pt1 \oplus flag$.
4. Enfin, $flag = X \oplus pt1$.

Le script de résolution `solve_black_cobra.py` implémente cette logique en construisant la matrice de transformation de $f$ et en résolvant le système linéaire via l'élimination de Gauss.

**Résultat :** `picoCTF{spi1cy!}`

## Concepts clés retenus

* **Linéarité en cryptographie** : La sécurité d'AES repose crucialement sur sa seule composante non-linéaire, la S-Box. Sans elle, le système s'effondre face à une analyse linéaire simple.
- **Algèbre linéaire sur GF(2)** : L'utilisation de matrices et de l'élimination de Gauss est un outil puissant pour attaquer des ciphers affines ou linéaires.
