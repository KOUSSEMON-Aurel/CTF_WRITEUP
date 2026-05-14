# Writeup PicoCTF - Shared Secrets

**Challenge :** Shared Secrets
**Catégorie :** Cryptography
**Points :** 100 pts
**Flag :** `picoCTF{dh_s3cr3t_32ec2679}`

## Description

Le challenge utilise un échange de clés Diffie-Hellman pour générer un secret partagé, lequel sert ensuite de clé XOR pour chiffrer le flag.

## Analyse du challenge

### 1. Protocole Diffie-Hellman

Le serveur génère un secret `a` et calcule `A = g^a mod p`.
Le client génère un secret `b` (fourni dans `message.txt`) et calcule `B = g^b mod p`.
Le secret partagé est calculé comme :
`shared = A^b mod p = (g^a)^b mod p = g^(ab) mod p`

### 2. Paramètres fournis (`message.txt`)

- `g = 2`
- `p` : Un nombre premier de 1048 bits.
- `A` : La clé publique du serveur.
- `b` : Le secret privé du client (la fuite mentionnée dans l'énoncé).
- `enc` : Le flag chiffré par XOR.

## Étapes de la solution

### 1. Calcul du secret partagé

On utilise `A`, `b` et `p` pour retrouver le secret `shared` :

```python
shared = pow(A, b, p)
key = shared % 256
```

### 2. Déchiffrement XOR

On applique un XOR entre chaque octet du message chiffré et `key`.

```python
enc_bytes = binascii.unhexlify(enc_hex)
flag = bytes([x ^ key for x in enc_bytes])
```

## Résultat

Le flag déchiffré est :
**Flag :** `picoCTF{dh_s3cr3t_32ec2679}`

## Concepts clés retenus

* **Diffie-Hellman (DH)** : Un protocole permettant à deux parties de s'accorder sur un secret via un canal non sécurisé.
- **Sécurité DH** : Le protocole repose sur la difficulté du problème du logarithme discret. Si l'un des secrets privés (`a` ou `b`) est révélé, le secret partagé est compromis.
- **XOR Simple** : Souvent utilisé comme étape finale de chiffrement après dérivation d'une clé.
