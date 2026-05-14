# Writeup PicoCTF - tea-cash

**Challenge :** tea-cash
**Catégorie :** Binary Exploitation (Heap)
**Points :** 100 pts
**Flag :** `picoCTF{0fd522cb3e9905002631d25e21a4750b}`

## Description

Le challenge demande de traverser une "free list" (liste de morceaux de mémoire libérés) dans le tas (heap) pour trouver un flag caché. Il fait référence au mécanisme `tcache` de la bibliothèque glibc.

## Analyse du code source (`heapedit.c`)

Le programme effectue les opérations suivantes :

1. **Allocation** : Il alloue 6 "chunks" de mémoire de taille `0x80` via `malloc`.
    - `chunks[0]`, `chunks[1]`, ..., `chunks[5]`.
2. **Stockage du Flag** : Il copie le flag dans le dernier chunk (`chunks[5]`).
3. **Libération (Free)** : Il libère les chunks dans l'ordre inverse :

    ```c
    for (int i = CHUNK_COUNT - 1; i >= 0; --i) {
        free(chunks[i]);
    }
    ```

4. **Tcache Head** : Le pointeur `head` est défini sur `chunks[0]`.

### Mécanisme du Tcache

Dans les versions récentes de glibc, les petites allocations libérées sont stockées dans une structure appelée `tcache` (thread local cache). Le tcache fonctionne comme une pile (LIFO - Last In, First Out).

- `free(chunks[5])` -> tcache head -> `chunks[5]`
- `free(chunks[4])` -> tcache head -> `chunks[4]` -> `chunks[5]`
- ...
- `free(chunks[0])` -> tcache head -> `chunks[0]` -> `chunks[1]` -> `chunks[2]` -> `chunks[3]` -> `chunks[4]` -> `chunks[5]`

Une allocation de `0x80` octets demande en réalité `0x90` octets sur la heap (taille demandée + 16 octets de métadonnées, alignés sur 16 octets). Les chunks étant alloués consécutivement, ils se suivent avec un décalage de `0x90`.

## Exploitation

Le programme nous donne l'adresse du `head` (`chunks[0]`) et nous demande les adresses des chunks suivants dans la liste chaînée.

### Calcul des adresses

Si `head` = `ADDR`, alors :

- Chunk 1 : `ADDR`
- Chunk 2 : `ADDR + 0x90`
- Chunk 3 : `ADDR + 0x120` (`+ 0x90 * 2`)
- Chunk 4 : `ADDR + 0x1b0` (`+ 0x90 * 3`)
- Chunk 5 : `ADDR + 0x240` (`+ 0x90 * 4`)
- Chunk 6 : `ADDR + 0x2d0` (`+ 0x90 * 5`)

En envoyant ces adresses au serveur, le programme valide la traversée de la liste et affiche le flag stocké dans le dernier chunk.

**Flag :** `picoCTF{0fd522cb3e9905002631d25e21a4750b}`

## Concepts clés retenus

* **Structure de la Heap** : Comprendre comment `malloc` et `free` gèrent la mémoire est crucial en exploitation binaire.
- **Glibc Tcache** : Le tcache simplifie l'exploitation de base de la heap car il ne possède pas de vérifications de sécurité complexes (comme les "safe unlinking" des binaires plus gros) dans ses versions initiales.
- **Alignement et Taille des Chunks** : La taille réelle sur la heap n'est pas la taille demandée à `malloc`. Il faut toujours tenir compte de l'alignement (généralement 16 octets sur x64).
