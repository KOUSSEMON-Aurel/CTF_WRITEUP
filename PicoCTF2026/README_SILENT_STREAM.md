# Silent Stream - Solution

**Difficulté** : ★★★☆☆ (300 points)  
**Catégorie** : Forensics / Réseau  
**Outils utilisés** : `scapy`, Python 3

---

## 1. Description du Challenge

L'objectif est de récupérer un fichier caché dans une capture réseau PCAP. Le fichier a été envoyé via TCP sur le port 9000 avec un chiffrement simple XOR utilisant la clé `42`.

---

## 2. Analyse

### Trafic Réseau
- **Protocole** : TCP
- **Port destination** : 9000
- **Chiffrement** : XOR avec le byte `42` (la clé)
- **Format** : Le fichier est fragmenté en plusieurs paquets TCP

### Approche
1. Charger le fichier PCAP avec `scapy`
2. Filtrer les paquets TCP destinés au port 9000
3. Trier les paquets par numéro de séquence (pour garantir l'ordre)
4. Concaténer les payloads
5. Appliquer le déchiffrement XOR : `(byte - 42) % 256`
6. Sauvegarder le fichier reconstruit

---

## 3. Explication de la Formule

Le déchiffrement utilise :
$$\text{octet\_original} = (\text{octet\_chiffré} - 42) \bmod 256$$

Cette opération inverse le chiffrement qui avait appliqué :
$$\text{octet\_chiffré} = (\text{octet\_original} + 42) \bmod 256$$

Le modulo 256 gère le débordement sur 8 bits.

---

## 4. Résultat

Le script reconstruit le fichier original avec le message du flag calculé à partir du contenu récupéré.

**Flag** : Extrait du fichier reconstruit dans le flux TCP.

---

## 5. Prérequis

```bash
pip install scapy
python3 --version  # Python 3.6+
```

---

## 6. Utilisation

Placer le fichier `packets.pcap` dans le répertoire courant, puis :

```bash
python3 soluceSilentStream.py
```

Le fichier reconstruit sera sauvegardé sous le nom `reconstructed_file`.
