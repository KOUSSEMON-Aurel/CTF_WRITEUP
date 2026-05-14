# Writeup : Binary Instrumentation 4 (picoCTF 2026)

## Flag
```
picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```

## Description du Challenge
Un exécutable Windows 64-bit packé (`bin-ins.exe`) doit être analysé pour extraire le flag. Le binaire utilise une technique de packing classique pour obscurcir le vrai code.

## Analyse et Solution

### 1. Reconnaissance du Binaire

**Informations du binaire :**
- **Architecture** : x86-64 (PE32+)
- **Système** : Windows CUI
- **Taille** : 482 KB (0x75C00 bytes)
- **Compilé** : Sat Sep 24 14:09:03 2022
- **Packer** : PP64Stub (visible dans les strings)

**Sections importantes :**
```
[rabin2 -S bin-ins.exe]
6   0x00006000  0x6fe00  0x14000b000  0x70000 -r-- ---- .ATOM
```

La section `.ATOM` contient les données packées (458 240 bytes compressés).

### 2. Identification de la Compression

La section `.ATOM` commence par les bytes `5d 00 00 10 00 7f 5b 28 00 00 00 00 00 00 26 96`, ce qui correspond à la signature **LZMA** (raw LZMA format).

### 3. Extraction et Décompression

**Script Python complet :**
```python
#!/usr/bin/env python3
import lzma

# Extract the .ATOM section (offset 0x6000, size 0x6fe00)
with open('bin-ins.exe', 'rb') as f:
    f.seek(0x6000)
    compressed_data = f.read(0x6fe00)

print(f"[*] Extracted {len(compressed_data)} bytes from .ATOM section")

# Decompress using LZMA
decompressed = lzma.decompress(compressed_data)
print(f"[+] Decompressed to {len(decompressed)} bytes")

# Save the payload
with open('payload.exe', 'wb') as out:
    out.write(decompressed)
print("[+] Saved to payload.exe")
```

**Résultat :**
- Données compressées : 458 240 bytes
- Données décompressées : 2 644 863 bytes (~2.6 MB)

### 4. Extraction des Chaînes et Découverte du Flag

**Recherche dans le payload décompressé :**

```bash
strings payload.exe | grep -B10 -A10 "I think I worked"
```

**Sortie clé :**
```
[+] Let me get started!
C:\random\output_flag.txt
[!] Failed to open output file.
cmd.exe /c echo testing if redirection works
[!] Failed
[!] I didn't work!
cmd.exe /c echo 
[+] I think I worked!
cGljb0NURns0
MTFfNHIzXzRw
MTVfbjA3aDFu
OV8zbDUzXzEy
NTA5NDI2fQo=
```

### 5. Décodage du Flag

Les 5 fragments Base64 trouvés immédiatement après le message de succès contiennent le flag fragmenté :

**Script de décodage :**
```python
import base64

# Base64 fragments found in the binary
base64_parts = [
    "cGljb0NURns0",      # "picoCTF{4"
    "MTFfNHIzXzRw",      # "11_4r3_4p"
    "MTVfbjA3aDFu",      # "15_n07h1n"
    "OV8zbDUzXzEy",      # "9_3l53_12"
    "NTA5NDI2fQo="       # "509426}\n"
]

# Concatenate all parts
combined = "".join(base64_parts)
print(f"Combined Base64: {combined}")

# Decode to get the flag
decoded = base64.b64decode(combined).decode('utf-8')
print(f"Flag: {decoded.strip()}")
```

**Résultat :**
```
Base64 combined: cGljb0NURns0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzEyNTA5NDI2fQo=
Decoded: picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```

## Explication Technique

### Packing et Unpacking
Le binaire original utilise **PP64Stub** pour :
1. **Compresser** le vrai exécutable avec LZMA
2. **Protéger** le code contre l'analyse statique
3. **Placer** les données compressées dans une section `.ATOM` non-standard

### Fragmentation du Flag
Le flag est délibérément fragmenté en 5 parties Base64 pour :
1. Compliquer l'extraction statique
2. Obfusquer le contenu
3. Tester la capacité d'analyse du participant

### Stratégie de Résolution
1. **Identifier** le format de packing (PP64Stub + LZMA)
2. **Extraire** la section `.ATOM` à l'offset exact
3. **Décompresser** avec LZMA
4. **Rechercher** les chaînes de succès
5. **Décoder** les fragments Base64

## Outils Utilisés

- **rabin2** : Analyse du binaire PE et identification des sections
- **strings** : Extraction des chaînes du payload décompressé
- **Python 3 + lzma** : Décompression LZMA
- **Python 3 + base64** : Décodage du flag

## Fichiers et Commandes

### Extraction du payload :
```bash
dd if=bin-ins.exe bs=1 skip=$((0x6000)) count=$((0x6fe00)) | python3 -c "
import sys, lzma
data = sys.stdin.buffer.read()
decompressed = lzma.decompress(data)
with open('payload.exe', 'wb') as f:
    f.write(decompressed)
"
```

### Recherche du flag :
```bash
strings payload.exe | grep -B5 -A5 "I think I worked"
```

### Décodage final :
```bash
python3 << 'EOF'
import base64
parts = ["cGljb0NURns0", "MTFfNHIzXzRw", "MTVfbjA3aDFu", "OV8zbDUzXzEy", "NTA5NDI2fQo="]
flag = base64.b64decode("".join(parts)).decode('utf-8').strip()
print(flag)
EOF
```

## Points Clés d'Apprentissage

1. **Packing de binaires** : Comprendre les techniques de compression et de protection
2. **Reverse engineering** : Analyser les binaires sans accès au code source
3. **Analyse de sections PE** : Identifier les sections non-standard
4. **Décompression** : Reconnaître et utiliser les algorithmes de compression courants
5. **Fragmentation** : Gérer les données obscurcies et fragmentées

## Timeline

| Étape | Durée | Action |
|-------|-------|--------|
| Reconnaissance | 5 min | Analyse du binaire avec rabin2 |
| Identification compression | 5 min | Reconnaissance de la signature LZMA |
| Extraction | 2 min | Extraction de la section .ATOM |
| Décompression | 1 min | LZMA decompress |
| Recherche strings | 5 min | Analyse des chaînes du payload |
| Décodage | 2 min | Base64 decode |
| **Total** | **~20 min** | |

## Conclusion

Le challenge "Binary Instrumentation 4" teste la capacité à :
- Identifier et contourner les techniques de packing
- Utiliser des outils d'analyse de binaires
- Appliquer des techniques de reverse engineering
- Décoder des données obscurcies

Le flag `picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}` est extrait avec succès par la combinaison d'extraction LZMA et de décodage Base64.
