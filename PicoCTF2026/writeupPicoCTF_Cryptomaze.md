# Writeup PicoCTF - Cryptomaze

**Challenge :** cryptomaze
**Catégorie :** Cryptography
**Points :** 100 pts
**Flag :** `picoCTF{scr8mbledt_flvg_9130bf07}`

## Description

Le challenge demande de déchiffrer un flag protégé par AES-ECB. La clé de déchiffrement n'est pas fournie directement mais doit être générée à l'aide d'un registre à décalage à rétroaction linéaire (LFSR).

## Analyse du challenge

### 1. Paramètres fournis (`output.txt`)

Le fichier contient :

- **État initial du LFSR** (64 bits).
- **Taps du LFSR** : `[63, 61, 60, 58]`.
- **Flag chiffré** (Hexadécimal).

### 2. Algorithme de génération de la clé

L'énoncé indique la procédure :

1. Générer une séquence de **128 bits** à partir du LFSR.
2. Grouper les bits par paquets de 8 pour former **16 octets**.
3. Ces 16 octets constituent la clé **AES-128**.

## Étapes de la solution

### 1. Implémentation du LFSR

Le LFSR est mis à jour à chaque étape en calculant un bit de rétroaction (feedback) via XOR sur les positions indiquées par les "taps". Le bit sortant est le premier bit du registre.

```python
state = initial_state[:]
output_bits = []
for _ in range(128):
    output_bits.append(state[0])
    feedback = state[63] ^ state[61] ^ state[60] ^ state[58]
    state = state[1:] + [feedback]
```

### 2. Déchiffrement AES-ECB

Une fois la clé dérivée (`25ec96954d8bc45b2d7798a9fa0e1236`), on utilise la bibliothèque `cryptography` pour déchiffrer le flag en mode ECB.

## Résultat

Après déchiffrement, le flag apparaît :

**Flag :** `picoCTF{scr8mbledt_flvg_9130bf07}`

## Concepts clés retenus

* **LFSR (Linear Feedback Shift Register)** : Un outil cryptographique simple pour générer des suites de bits pseudo-aléatoires.
- **AES-ECB** : Le mode le moins sécurisé d'AES car il ne nécessite pas d'IV et chiffre chaque bloc de manière indépendante.
- **Dérivation de clé** : Utiliser un algorithme (ici LFSR) pour passer d'un état interne à une clé utilisable par un chiffrement par bloc.
