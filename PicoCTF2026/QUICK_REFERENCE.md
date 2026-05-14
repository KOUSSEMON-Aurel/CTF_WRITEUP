# Binary Instrumentation 4 - Quick Commands

## One-liner complet

```bash
# Extraction + Décompression + Décodage en une seule commande
python3 << 'EOF'
import lzma, base64
with open('bin-ins.exe', 'rb') as f:
    f.seek(0x6000)
    decompressed = lzma.decompress(f.read(0x6fe00))
fragments = ["cGljb0NURns0", "MTFfNHIzXzRw", "MTVfbjA3aDFu", "OV8zbDUzXzEy", "NTA5NDI2fQo="]
print(base64.b64decode("".join(fragments)).decode().strip())
EOF
```

**Résultat immédiat :**
```
picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```

## Commandes étape par étape

### 1. Extraction du payload
```bash
# Option 1 : Avec dd + lzma
dd if=bin-ins.exe bs=1 skip=$((0x6000)) count=$((0x6fe00)) 2>/dev/null | lzma -d > payload.exe

# Option 2 : Avec Python
python3 -c "
import lzma
with open('bin-ins.exe', 'rb') as f:
    f.seek(0x6000)
    decompressed = lzma.decompress(f.read(0x6fe00))
with open('payload.exe', 'wb') as f:
    f.write(decompressed)
"
```

### 2. Vérifier l'extraction
```bash
# Vérifier la taille
ls -lah payload.exe  # Devrait être ~2.6 MB

# Vérifier avec file
file payload.exe     # Devrait reconnaître le format PE

# Vérifier les strings
strings payload.exe | wc -l
```

### 3. Trouver les fragments
```bash
# Recherche simple
strings payload.exe | grep -A 5 "I think I worked"

# Recherche plus robuste
strings payload.exe | tail -300 | head -20

# Recherche pour vérifier les Base64 parts
strings payload.exe | grep "cGljb0NUR"
```

### 4. Décoder le flag
```bash
# Option 1 : Python
python3 -c "
import base64
fragments = ['cGljb0NURns0', 'MTFfNHIzXzRw', 'MTVfbjA3aDFu', 'OV8zbDUzXzEy', 'NTA5NDI2fQo=']
print(base64.b64decode(''.join(fragments)).decode().strip())
"

# Option 2 : Base64 command-line
echo "cGljb0NURns0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzEyNTA5NDI2fQo=" | base64 -d

# Option 3 : Python one-liner
python3 -m base64 -d <<< "cGljb0NURns0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzEyNTA5NDI2fQo="
```

## Vérification intermédiaire

### Vérifier que le .ATOM est bien extrait
```bash
# Extraire et afficher les premiers bytes
dd if=bin-ins.exe bs=1 skip=$((0x6000)) count=16 2>/dev/null | xxd
# Devrait afficher : 5d 00 00 10 00 7f 5b 28 ...
```

### Vérifier que le décodage LZMA fonctionne
```bash
# Test de décompression uniquement
python3 << 'EOF'
import lzma
try:
    with open('bin-ins.exe', 'rb') as f:
        f.seek(0x6000)
        data = f.read(0x6fe00)
    result = lzma.decompress(data)
    print(f"✓ Décompression réussie: {len(result)} bytes")
except Exception as e:
    print(f"✗ Erreur: {e}")
EOF
```

### Vérifier les fragments Base64
```bash
# Vérifier que chaque fragment est du Base64 valide
python3 << 'EOF'
import base64
fragments = ['cGljb0NURns0', 'MTFfNHIzXzRw', 'MTVfbjA3aDFu', 'OV8zbDUzXzEy', 'NTA5NDI2fQo=']
for i, frag in enumerate(fragments):
    try:
        decoded = base64.b64decode(frag).decode()
        print(f"Fragment {i+1}: {frag} → {decoded}")
    except Exception as e:
        print(f"Fragment {i+1}: ERREUR - {e}")
EOF
```

## Variantes et alternatives

### Avec radare2
```bash
# Lister les sections
rabin2 -S bin-ins.exe | grep ATOM

# Extraire avec r2
r2 bin-ins.exe -c "s 0x6000; p10x" | head -5
```

### Avec hexdump
```bash
# Afficher les bytes du .ATOM
hexdump -C bin-ins.exe | grep -A 20 "6000"
```

### Avec nm/objdump
```bash
# Informations sur le binaire
objdump -h bin-ins.exe | grep -i atom
```

## Scripts prêts à l'emploi

### Version ultra-rapide (bash)
```bash
#!/bin/bash
FLAG=$(python3 -c "import lzma,base64;f=open('bin-ins.exe','rb');f.seek(0x6000);d=lzma.decompress(f.read(0x6fe00));f.close();parts=['cGljb0NURns0','MTFfNHIzXzRw','MTVfbjA3aDFu','OV8zbDUzXzEy','NTA5NDI2fQo='];print(base64.b64decode(''.join(parts)).decode().strip())")
echo "Flag: $FLAG"
```

### Version complète (Python)
```python
#!/usr/bin/env python3
import lzma, base64, sys
with open(sys.argv[1] if len(sys.argv) > 1 else 'bin-ins.exe', 'rb') as f:
    f.seek(0x6000)
    payload = lzma.decompress(f.read(0x6fe00))
parts = ["cGljb0NURns0", "MTFfNHIzXzRw", "MTVfbjA3aDFu", "OV8zbDUzXzEy", "NTA5NDI2fQo="]
flag = base64.b64decode("".join(parts)).decode().strip()
print(f"Flag: {flag}")
```

## Temps d'exécution

- Extraction .ATOM : < 1 sec
- Décompression LZMA : 1-2 sec
- Recherche strings : 2-5 sec
- Décodage Base64 : < 1 sec
- **Total** : ~5-10 secondes

## Validation du flag

```bash
# Vérifier la format
FLAG="picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}"

# Vérifier le préfixe picoCTF
echo "$FLAG" | grep -q "^picoCTF{" && echo "✓ Format valide"

# Vérifier la fermeture
echo "$FLAG" | grep -q "}$" && echo "✓ Fermeture valide"

# Vérifier la longueur
echo "$FLAG" | wc -c  # Devrait être 44 caractères (43 + newline)
```

## Légende des variables

```
.ATOM section offset: 0x6000 (24576 bytes from start)
.ATOM section size:   0x6fe00 (458240 bytes)
Decompressed size:    2644863 bytes (~2.6 MB)
LZMA signature:       5d 00 00 10 00 7f 5b 28
Base64 parts:         5 fragments
Final flag:           picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```
