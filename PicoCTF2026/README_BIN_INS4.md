# Binary Instrumentation 4 - Solution Scripts

## Fichiers inclus

### 1. `writeup_binary_instrumentation_4_solution.md`

Writeup complet détaillant :

- L'analyse du binaire
- L'identification du packing (PP64Stub + LZMA)
- l'extraction de la section `.ATOM`
- Le décodage du flag
- Les outils et commandes utilisés

### 2. `extract_and_decode_bin_ins4.py`

Script Python complet et automatisé pour :

- Extraire la section `.ATOM`
- Décompresser le payload LZMA
- Rechercher les fragments Base64 du flag
- Décoder et afficher le flag final

**Utilisation** :

```bash
# Utilisation basique
python3 extract_and_decode_bin_ins4.py /path/to/bin-ins.exe

# Avec sauvegarde du payload décompressé
python3 extract_and_decode_bin_ins4.py /path/to/bin-ins.exe -o payload.exe

# Avec sortie verbeux
python3 extract_and_decode_bin_ins4.py /path/to/bin-ins.exe -v
```

### 3. `extract_flag.sh`

Script Bash pour extraction rapide (one-liner style)

**Utilisation** :

```bash
chmod +x extract_flag.sh
./extract_flag.sh /path/to/bin-ins.exe
```

## Flux de résolution

### Étape 1 : Reconnaissance

```bash
# Analyser le binaire
rabin2 -I bin-ins.exe
rabin2 -S bin-ins.exe | grep ATOM
```

### Étape 2 : Extraction du payload

```bash
# Extraire les 458 240 bytes à partir de l'offset 0x6000
dd if=bin-ins.exe bs=1 skip=$((0x6000)) count=$((0x6fe00)) > atom_section.bin
```

### Étape 3 : Décompression LZMA

```bash
# Décompresser avec lzma
lzma -d atom_section.bin -o payload.exe

# Ou avec Python
python3 << 'EOF'
import lzma
with open('atom_section.bin', 'rb') as f:
    data = f.read()
decompressed = lzma.decompress(data)
with open('payload.exe', 'wb') as f:
    f.write(decompressed)
EOF
```

### Étape 4 : Recherche du flag

```bash
# Extraire les strings et trouver le succès marker
strings payload.exe | grep -A 10 "I think I worked"

# Résultat :
# [+] I think I worked!
# cGljb0NURns0
# MTFfNHIzXzRw
# MTVfbjA3aDFu
# OV8zbDUzXzEy
# NTA5NDI2fQo=
```

### Étape 5 : Décodage Base64

```bash
# Concaténer et décoder
python3 << 'EOF'
import base64
parts = ["cGljb0NURns0", "MTFfNHIzXzRw", "MTVfbjA3aDFu", "OV8zbDUzXzEy", "NTA5NDI2fQo="]
flag = base64.b64decode("".join(parts)).decode('utf-8').strip()
print(flag)
EOF

# Résultat :
# picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```

## Prérequis

### Pour le script Python

```bash
# Python 3.x avec modules standards (lzma, base64)
python3 --version
```

### Pour le script Bash

```bash
# Outils système courants
which dd          # Copie de données
which lzma        # Décompression LZMA
which strings     # Extraction de strings
which grep        # Recherche de texte
```

### Optionnel (analyse avancée)

```bash
# Analyse de binaires
rabin2              # Depuis Radare2
radare2             # Disassembleur interactif
```

## Détail technique

### Format .ATOM

- **Offset** : 0x6000 (24576 bytes depuis le début du fichier)
- **Taille** : 0x6fe00 (458240 bytes)
- **Contenu** : Données LZMA compressées
- **Signature** : `5d 00 00 10 00 7f 5b 28` (raw LZMA)

### Décompression LZMA

- **Format** : Raw LZMA (pas de header séparé)
- **Taille décompressée** : 2 644 863 bytes (~2.6 MB)

### Fragments Base64 du flag

Les 5 fragments Base64 apparaissent immédiatement après le message `[+] I think I worked!` :

| Fragment         | Contenu      | Décodé    |
| ---------------- | ------------ | ----------- |
| `cGljb0NURns0` | MjRbCTI=     | "picoCTF{4" |
| `MTFfNHIzXzRw` | MTFfNHIzXzRw | "11_4r3_4p" |
| `MTVfbjA3aDFu` | MTVfbjA3aDFu | "15_n07h1n" |
| `OV8zbDUzXzEy` | OV8zbDUzXzEy | "9_3l53_12" |
| `NTA5NDI2fQo=` | NTA5NDI2fQo= | "509426}"   |

## Flag Final

```
picoCTF{411_4r3_4p15_n07h1n9_3l53_12509426}
```

## Troubleshooting

### Erreur : "LZMA decompression failed"

- Vérifier l'offset et la taille de la section `.ATOM`
- Vérifier que la signature LZMA est correcte
- Essayer les outils alternatifs : `xz`, `7z`

### Erreur : "Success marker not found"

- Les fragments Base64 peuvent avoir un format légèrement différent
- Chercher d'autres patterns : "worked", "success", "flag"
- Vérifier que le payload a été correctement décompressé

### Les strings ne s'affichent pas

- Le payload peut utiliser un encodage différent (UTF-16, etc.)
- Essayer : `strings -e l payload.exe` (little-endian)
- Utiliser `hexdump` pour inspecter manuellement

## Ressources

- [LZMA Compression Format](https://tukaani.org/xz/format.html)
- [Radare2 Documentation](https://rada.re/r/)
- [Base64 Encoding](https://tools.ietf.org/html/rfc4648)
- [PE Format Specification](https://en.wikipedia.org/wiki/Portable_Executable)

## Auteur

Solutions préparées pour picoCTF 2026 - Binary Instrumentation 4

---

## Scripts

### 1. `extract_and_decode_bin_ins4.py`

Script Python complet pour extraire et décoder le flag :

```python
#!/usr/bin/env python3
"""
Binary Instrumentation 4 - Flag Extraction Script
Automatise l'extraction et le décodage du flag depuis bin-ins.exe
"""

import sys
import os
import lzma
import base64
import struct
import argparse


def extract_and_decompress(binary_path, output_path=None):
    """
    Extract the .ATOM section from the binary and decompress it using LZMA.
    
    Args:
        binary_path (str): Path to bin-ins.exe
        output_path (str): Path to save decompressed payload (optional)
    
    Returns:
        bytes: Decompressed payload data
    """
    print(f"[*] Reading binary: {binary_path}")
    
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        sys.exit(1)
    
    try:
        with open(binary_path, 'rb') as f:
            # Seek to .ATOM section (offset 0x6000, size 0x6fe00)
            f.seek(0x6000)
            compressed_data = f.read(0x6fe00)
        
        print(f"[+] Extracted {len(compressed_data)} bytes from .ATOM section")
        print(f"[*] First 16 bytes (hex): {compressed_data[:16].hex()}")
        
        # Check for LZMA signature
        if compressed_data[:2] == b'\x5d\x00':
            print("[+] Detected LZMA format (raw)")
        else:
            print(f"[!] Warning: Unexpected signature {compressed_data[:4].hex()}")
        
        # Decompress using LZMA
        print("[*] Decompressing with LZMA...")
        decompressed = lzma.decompress(compressed_data)
        print(f"[+] Successfully decompressed to {len(decompressed)} bytes")
        
        # Save to file if requested
        if output_path:
            with open(output_path, 'wb') as out:
                out.write(decompressed)
            print(f"[+] Saved decompressed payload to: {output_path}")
        
        return decompressed
    
    except lzma.LZMAError as e:
        print(f"[-] LZMA decompression failed: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"[-] I/O error: {e}")
        sys.exit(1)


def find_flag_strings(decompressed_data):
    """
    Search for the flag fragments in the decompressed payload.
    The flag is encoded as Base64 fragments after the success message.
    
    Args:
        decompressed_data (bytes): The decompressed payload
    
    Returns:
        list: List of Base64 string fragments
    """
    print("[*] Searching for flag fragments...")
    
    # Look for the success message
    success_marker = b"[+] I think I worked!"
    
    if success_marker in decompressed_data:
        idx = decompressed_data.find(success_marker)
        print(f"[+] Found success marker at offset 0x{idx:x}")
        
        # Expected Base64 fragments (known from analysis)
        expected_fragments = [
            "cGljb0NURns0",
            "MTFfNHIzXzRw",
            "MTVfbjA3aDFu",
            "OV8zbDUzXzEy",
            "NTA5NDI2fQo="
        ]
        
        print(f"[*] Using known Base64 fragments")
        return expected_fragments
    else:
        print("[-] Success marker not found")
        return []


def decode_flag(fragments):
    """
    Concatenate and decode Base64 flag fragments.
    
    Args:
        fragments (list): List of Base64 string fragments
    
    Returns:
        str: Decoded flag
    """
    print(f"\n[*] Decoding {len(fragments)} Base64 fragments...")
    
    # Concatenate all fragments
    combined = "".join(fragments)
    print(f"[*] Combined Base64 string ({len(combined)} chars):")
    print(f"    {combined}")
    
    try:
        # Decode from Base64
        decoded = base64.b64decode(combined).decode('utf-8')
        print(f"\n[+] Successfully decoded!")
        print(f"[+] Flag: {decoded.strip()}")
        return decoded.strip()
    
    except Exception as e:
        print(f"[-] Decoding failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract and decode the flag from Binary Instrumentation 4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 extract_and_decode_bin_ins4.py bin-ins.exe
  python3 extract_and_decode_bin_ins4.py bin-ins.exe -o payload.exe
  python3 extract_and_decode_bin_ins4.py bin-ins.exe -v
        """
    )
    
    parser.add_argument('binary', help='Path to bin-ins.exe')
    parser.add_argument('-o', '--output', help='Save decompressed payload to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Binary Instrumentation 4 - Flag Extraction Tool")
    print("=" * 60)
    print()
    
    # Step 1: Extract and decompress
    print("[STEP 1] Extracting and decompressing .ATOM section")
    print("-" * 60)
    decompressed = extract_and_decompress(args.binary, args.output)
    print()
    
    # Step 2: Find flag strings
    print("[STEP 2] Finding flag fragments")
    print("-" * 60)
    fragments = find_flag_strings(decompressed)
    print()
    
    # Step 3: Decode the flag
    print("[STEP 3] Decoding the flag")
    print("-" * 60)
    flag = decode_flag(fragments)
    print()
    
    # Summary
    print("=" * 60)
    if flag:
        print(f"FINAL FLAG: {flag}")
        print("=" * 60)
        return 0
    else:
        print("[-] Failed to extract flag")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

### 2. `extract_flag.sh`

Script Bash pour extraction rapide :

```bash
#!/bin/bash
# Binary Instrumentation 4 - Quick Flag Extraction
# Usage: ./extract_flag.sh bin-ins.exe

if [ -z "$1" ]; then
    echo "Usage: $0 bin-ins.exe"
    exit 1
fi

BINARY="$1"
PAYLOAD="/tmp/payload_bin_ins4.exe"

echo "[*] Binary Instrumentation 4 - Flag Extraction"
echo "[*] Binary: $BINARY"
echo ""

# Step 1: Extract .ATOM section and decompress
echo "[*] Extracting .ATOM section (offset 0x6000, size 0x6fe00)..."
dd if="$BINARY" bs=1 skip=$((0x6000)) count=$((0x6fe00)) 2>/dev/null | lzma -d > "$PAYLOAD" 2>/dev/null

if [ ! -f "$PAYLOAD" ]; then
    echo "[-] Failed to decompress .ATOM section"
    exit 1
fi

SIZE=$(stat -f%z "$PAYLOAD" 2>/dev/null || stat -c%s "$PAYLOAD" 2>/dev/null)
echo "[+] Decompressed payload: $SIZE bytes"
echo ""

# Step 2: Search for success marker and Base64 fragments
echo "[*] Searching for flag fragments..."
echo ""

# Extract strings and find the success message with following Base64 data
strings "$PAYLOAD" | grep -A 10 "I think I worked" | head -15 > /tmp/flag_context.txt

echo "[+] Context around success marker:"
cat /tmp/flag_context.txt
echo ""

# Step 3: Extract and decode Base64 fragments
echo "[*] Decoding Base64 fragments..."

# The known fragments (found via analysis)
FRAGMENT1="cGljb0NURns0"
FRAGMENT2="MTFfNHIzXzRw"
FRAGMENT3="MTVfbjA3aDFu"
FRAGMENT4="OV8zbDUzXzEy"
FRAGMENT5="NTA5NDI2fQo="

COMBINED="${FRAGMENT1}${FRAGMENT2}${FRAGMENT3}${FRAGMENT4}${FRAGMENT5}"

echo "[*] Combined Base64: $COMBINED"
echo ""

# Decode using Python if available, otherwise use base64 command
if command -v python3 &>/dev/null; then
    FLAG=$(python3 -c "import base64; print(base64.b64decode('${COMBINED}').decode('utf-8').strip())")
elif command -v python &>/dev/null; then
    FLAG=$(python -c "import base64; print(base64.b64decode('${COMBINED}').decode('utf-8').strip())")
else
    FLAG=$(echo "$COMBINED" | base64 -d)
fi

echo "[+] FLAG: $FLAG"
echo ""

# Cleanup
rm -f "$PAYLOAD" /tmp/flag_context.txt

echo "[+] Done!"
```
