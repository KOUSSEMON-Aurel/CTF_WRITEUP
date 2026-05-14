# Writeup PicoCTF - Gatekeeper

**Challenge :** Gatekeeper
**Catégorie :** Reversing
**Points :** 100 pts
**Flag :** `picoCTF{3_digit_hex_GT_999_1c573d3e}`

## Description

Le challenge demande de trouver une entrée numérique qui permet de passer une "porte" logique dans un programme binaire.

## Analyse du binaire

Le binaire `gatekeeper` est un ELF 64-bit non strippé. L'analyse du code désassemblé (fonction `main`) révèle la logique suivante :

1. **Lecture de l'entrée** : Le programme lit une chaîne de caractères via `scanf`.
2. **Validation de la longueur** : La longueur de l'entrée doit être exactement **3** (`cmp DWORD PTR [rbp-0x34], 0x3`).
3. **Validation du format** :
    - Si l'entrée est composée uniquement de chiffres décimaux (`is_valid_decimal`), elle est convertie par `atoi`. La valeur résultante doit être **> 999** (`cmp val, 0x3e7` suivi de `jg`). Or, une chaîne de 3 chiffres décimaux ne peut pas dépasser 999. Cette branche est donc une impasse.
    - Si l'entrée n'est pas purement décimale mais est valide en hexadécimal (`is_valid_hex`), elle est convertie par `strtol(..., 16)`. La valeur résultante doit être comprise entre **1000** et **9999** (`0x3e7 < val <= 0x270f`).
4. **Accès au Flag** : Si les conditions sont remplies, la fonction `reveal_flag` est appelée.

## Exploitation

Pour satisfaire les conditions (longueur 3 et valeur hexadécimale >= 1000), j'ai choisi l'entrée **"a00"**.
En hexadécimal, `0xa00` vaut `2560`, ce qui est bien supérieur à 999 et inférieur à 9999.

### Connexion au serveur

```bash
echo "a00" | nc green-hill.picoctf.net 50189
```

L'output reçu était :
`Access granted: }e3dftc_oc_ip375cftc_oc_ip1_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip`

### Nettoyage du Flag

L'indice suggérait que l'output était inversé et contenait du texte superflu.

1. **Inversion** (Python `[::-1]`) :
    `pi_co_ctfpicopi_co_ctfCTF{pi_co_ctf3_dipi_co_ctfgit_pi_co_ctfhex_pi_co_ctfGT_9pi_co_ctf99_1pi_co_ctfc573pi_co_ctfd3e}`
2. **Nettoyage** : En retirant la chaîne de bruit `pi_co_ctf`, on obtient le flag.

**Flag :** `picoCTF{3_digit_hex_GT_999_1c573d3e}`

## Concepts clés retenus

* **Reversing statique** : Identifier les conditions de saut (`jg`, `jle`, `jne`) pour comprendre le chemin vers la fonction cible.
- **Différence entre bases** : Un programme peut valider le format d'une chaîne (décimal) puis l'interpréter d'une autre manière (hexadécimal).
- **Obfuscation simple** : L'inversion de chaîne et l'insertion de "canaris" (texte de bruit) sont des techniques classiques de base pour masquer un flag.
