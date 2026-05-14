# Writeup PicoCTF - Bypass Me

**Challenge :** Bypass Me
**Catégorie :** Binary Exploitation / Reverse Engineering
**Points :** 100 pts
**Flag :** `picoCTF{d3bugg3r_p0w3r_is_4w3s0m3_f4dd81c8}`

## Description

L'objectif est de contourner l'authentification d'un binaire `bypassme.bin` protégé par mot de passe. Le binaire effectue une sanitization des entrées, empêchant l'utilisation de caractères spéciaux ou numériques.

## Analyse du binaire

Le binaire est un ELF 64-bit avec symboles de débogage.

### 1. Fonction `decode_password`

Le binaire ne stocke pas le mot de passe en clair. Il utilise une fonction `decode_password` qui effectue une opération XOR entre une série d'octets et la constante `0xAA`.

Désassemblage de `decode_password` :

```asm
    1352:       48 b8 f9 df da cf d8    movabs rax,0xc9cff9d8cfdadff9
    1359:       f9 cf c9 
    [...]
    1386:       83 f0 aa                xor    eax,0xffffffaa
```

Octets encodés : `f9 df da cf d8 f9 cf c9 df d8 cf`
Décodage :

- `0xf9 ^ 0xaa = 'S'`
- `0xdf ^ 0xaa = 'u'`
- `0xda ^ 0xaa = 'p'`
- `0xcf ^ 0xaa = 'e'`
- `0xd8 ^ 0xaa = 'r'`
- `0xf9 ^ 0xaa = 'S'`
- `0xcf ^ 0xaa = 'e'`
- `0xc9 ^ 0xaa = 'c'`
- `0xdf ^ 0xaa = 'u'`
- `0xd8 ^ 0xaa = 'r'`
- `0xcf ^ 0xaa = 'e'`

Mot de passe : **SuperSecure**

### 2. Fonction `sanitize`

Le programme nettoie l'entrée utilisateur avant comparaison :

```c
void sanitize(const char *in, char *out) {
    int j = 0;
    for (int i = 0; in[i] != '\0'; i++) {
        if (isalpha(in[i])) { // Ne garde que les lettres
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
}
```

Le mot de passe `SuperSecure` ne contenant que des lettres, il passe la sanitization sans modification.

## Exploitation

1. Connexion SSH au serveur.
2. Exécution du binaire `./bypassme.bin`.
3. Saisie du mot de passe `SuperSecure`.

Le serveur valide l'accès et affiche le flag.

**Flag :** `picoCTF{d3bugg3r_p0w3r_is_4w3s0m3_f4dd81c8}`

## Concepts clés retenus

* **Obfuscation simple** : L'utilisation de XOR avec une constante est une technique de base pour masquer des chaînes de caractères.
- **Sanitization Bypass** : Comprendre comment les entrées sont transformées avant d'être traitées est crucial en Reverse Engineering.
- **Debug Symbols** : La présence de symboles facilite énormément l'analyse avec des outils comme `objdump` ou `gdb`.
