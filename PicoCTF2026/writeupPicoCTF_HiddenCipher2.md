# Writeup PicoCTF - Hidden Cipher 2

**Challenge :** Hidden Cipher 2
**Catégorie :** Reversing / Cryptography
**Points :** 100 pts
**Flag :** `picoCTF{m4th_b3h1nd_c1ph3r_f8ce7ad6}`

## Description

Le challenge demande de résoudre une opération mathématique simple. Cependant, la réponse à cette opération est utilisée pour obfusquer le flag. L'objectif est de comprendre cette relation pour déchiffrer le flag réel fourni par le serveur distant.

## Analyse du binaire

En exécutant le binaire localement (`./hiddencipher2`), on observe le comportement suivant :

1. Le programme pose une question mathématique aléatoire (ex: `What is 5 + 5?`).
2. Après avoir donné la réponse (`10`), il affiche une liste de nombres ("Encoded flag values").

### Logique d'encodage

En comparant les nombres obtenus avec le préfixe connu `picoCTF{`, on remarque une proportionnalité directe :

- `1120 / 10 = 112` ('p')
- `1050 / 10 = 105` ('i')
- `990 / 10 = 99` ('c')
- ...

La formule est simple : `EncodedValue = ASCII_Code * MathResponse`.

## Exploitation

Pour obtenir le flag réel, il faut se connecter au serveur distant (`nc crystal-peak.picoctf.net 50801`) et appliquer la même logique.

### Script de résolution (Python)

```python
import socket
import re

# Connexion au serveur
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("crystal-peak.picoctf.net", 50801))

# Lecture du calcul
data = s.recv(1024).decode()
match = re.search(r"What is (\d+) ([\+\-]) (\d+)\?", data)
num1 = int(match.group(1))
op = match.group(2)
num2 = int(match.group(3))
result = num1 + num2 if op == '+' else num1 - num2

# Envoi de la réponse
s.sendall(f"{result}\n".encode())

# Lecture et déchiffrement
response = s.recv(4096).decode()
numbers_str = response.split("Encoded flag values:")[1].strip()
numbers = [int(x.strip(",")) for x in numbers_str.split()]
flag = "".join(chr(n // result) for n in numbers)
print(flag)
```

**Flag :** `picoCTF{m4th_b3h1nd_c1ph3r_f8ce7ad6}`

## Concepts clés retenus

* **Obfuscation simple** : L'utilisation de constantes dynamiques (comme une réponse utilisateur) pour masquer des données est une technique courante de protection de bas niveau.
- **Analyse de motifs** : Identifier le format `picoCTF{` permet souvent de déduire instantanément la clé ou la méthode de chiffrement si elle est élémentaire.
