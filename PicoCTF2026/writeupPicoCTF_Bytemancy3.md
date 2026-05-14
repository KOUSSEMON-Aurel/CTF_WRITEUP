# Writeup PicoCTF - Bytemancy 3

**Challenge :** Bytemancy 3
**Catégorie :** Binary Exploitation / General Skills
**Points :** 400 pts
**Flag :** `picoCTF{0bjdump_m4g1c_de613af3}`

## Description du problème

Le challenge demande de fournir les adresses de 3 fonctions aléatoires parmi une liste de 4, présentes dans le binaire `spellbook`. Les adresses doivent être envoyées sous forme de 4 octets bruts en format petit-boutiste (little-endian).

## Analyse

Le script `app.py` utilise la bibliothèque `pwntools` pour charger le binaire et extraire les adresses des fonctions. Il attend ensuite que l'utilisateur envoie ces adresses.
Les fonctions cibles sont :

- `ember_sigil`
- `glyph_conflux`
- `astral_spark`
- `binding_word`

## Extraction des adresses

On utilise l'outil `nm` (ou `objdump -t`) pour extraire les adresses des symboles du binaire `spellbook` :

```bash
nm spellbook | grep -E "ember_sigil|glyph_conflux|astral_spark|binding_word"
```

Résultats :

- `08049176 T ember_sigil`
- `0804919a T glyph_conflux`
- `080491c1 T astral_spark`
- `080491e3 T binding_word`

## Exploitation

On utilise un script Python avec `pwntools` pour automatiser la connexion et l'envoi des adresses au format `p32()` (little-endian, 4 octets).

```python
from pwn import *

targets = {
    "astral_spark": 0x080491c1,
    "binding_word": 0x080491e3,
    "ember_sigil": 0x08049176,
    "glyph_conflux": 0x0804919a
}

io = remote('green-hill.picoctf.net', 56354)

for i in range(3):
    io.recvuntil(b"procedure '")
    func_name = io.recvuntil(b"'").decode().strip("'")
    addr = targets[func_name]
    io.send(p32(addr))

io.interactive()
```

**Flag :** `picoCTF{0bjdump_m4g1c_de613af3}`
