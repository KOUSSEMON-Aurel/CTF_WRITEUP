# Writeup : Secure Password Database (200 pts)

**Challenge :** Secure Password Database
**Catégorie :** Reversing / Binary Exploitation
**Flag :** `picoCTF{d0nt_trust_us3rs}`

## Description
Un service d'authentification affiche le mot de passe stocké. L'objectif est d'accéder au compte pour obtenir le flag.

## Analyse

### 1. Vulnérabilité Heartbleed
Le binaire utilise `calloc(0x5a, 1)` pour allouer 90 octets sur le heap.
- `[0x00 - 0x3B]` : Mot de passe.
- `[0x3C - 0x59]` : Données sensibles (flag XORé).

En entrant un mot de passe court et en demandant une longueur d'affichage élevée (jusqu'à 89), on peut lire les données situées après le mot de passe sur le tas.

### 2. Reverse Engineering
- **`make_secret`** : Remplace systématiquement le mot de passe utilisateur par la chaîne `iUbh81!j*hn!`.
- **`hash`** : Implémente l'algorithme **djb2** (h = h * 33 + c, init 5381).

## Exploitation
Pour s'authentifier, il faut envoyer le hash décimal de la chaîne `iUbh81!j*hn!`.

1. **Secret :** `iUbh81!j*hn!`
2. **Calcul du Hash (djb2) :** `15237662580160011234`

### Script d'Exploit (Python)
```python
import socket

def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
        h &= 0xFFFFFFFFFFFFFFFF
    return h

s = socket.socket()
s.connect(('candy-mountain.picoctf.net', 56575))
s.recv(1024); s.send(b'A\n') # Password
s.recv(1024); s.send(b'1\n') # Length
s.recv(1024)
h = djb2("iUbh81!j*hn!")
s.send(str(h).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
```

## Conclusion
Le flag est obtenu en court-circuitant l'entrée utilisateur pour fournir le hash attendu par le serveur.

**Flag :** `picoCTF{d0nt_trust_us3rs}`
