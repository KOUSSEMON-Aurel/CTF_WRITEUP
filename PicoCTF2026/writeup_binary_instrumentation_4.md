# Writeup : Binary Instrumentation 4 (picoCTF)

## 1. Découverte et déballage (Unpacking)
L'exécutable original `bin-ins.exe` (compilé pour Windows 64 bits) est en réalité un "PE Loader" packé avec **PP64Stub**. 
En l'analysant, on découvre qu'il cache un autre exécutable dans une de ses sections nommée `.ATOM`. Cette section contient des données compressées au format **LZMA**.

À l'aide d'un script Python, on peut décompresser cette section pour extraire le binaire réel :

```python
import lzma
with open('bin-ins.exe', 'rb') as f:
    f.seek(0x6000) # Offset et taille de la section .ATOM
    data = f.read(0x6fe00)

decompressed = lzma.decompress(data)
with open('payload.exe', 'wb') as out:
    out.write(decompressed)
```
Cela produit un exécutable C++ d'environ 2.6 Mo (`payload.exe`).

## 2. Analyse de l'exécutable réel
Une fois le payload principal récupéré, l'analyse statique et dynamique montre que le programme tente de se connecter à une adresse IP codée en dur (`192.168.29.25`) et échoue généralement sur (`WSAStartup failed` ou `Connection failed`).

En effectuant une extraction des chaînes de caractères (`strings payload.exe`), on tombe sur ce message de victoire très parlant qui aurait dû être affiché si la connexion fonctionnait :
```text
Congratulations! Here's your flag:
```

Juste en dessous de cette chaîne, on remarque une suite de petits blocs répartis sur plusieurs lignes ressemblant fortement à du **Base64** :
- `cGljb0NURnt`
- `uM3R3MHJrXz`
- `FzXzRQMXNfN`
- `FNfVzMxMV9j`
- `ZTU5ZWM5ZX0K`

## 3. Récupération du flag final
En concaténant l'ensemble de ces blocs, on forme la chaîne Base64 continue :
`cGljb0NURntuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV9jZTU5ZWM5ZX0K`

Il ne reste plus qu'à la décoder pour obtenir le flag en clair. Le binaire avait de toute évidence prévu de découper et d'envoyer statiquement le flag au moment de l'exécution ou en cas de validation réseau.

**Flag :** `picoCTF{n3tw0rk_1s_4P1s_4S_W311_ce59ec9e}`
