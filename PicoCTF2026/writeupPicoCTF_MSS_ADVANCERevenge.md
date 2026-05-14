# Writeup PicoCTF - MSS_ADVANCE Revenge

**Challenge :** MSS_ADVANCE Revenge
**Catégorie :** Cryptographie
**Points :** 400 pts
**Flag :** `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

## Description du problème

Le serveur génère un polynôme de degré 29 sur $\mathbb{Z}_p$ (p premier, 1024 bits) :
$$P(x) = \sum_{i=0}^{29} c_i \cdot x^{29-i} \pmod p$$

Les coefficients sont enchaînés par SHA-256 :

- `c[0] = bytes_to_long(SHA256(flag))` — la **clé maître AES**
- `c[i+1] = bytes_to_long(SHA256(long_to_bytes(c[i])))`

Puis 20 évaluations $(x_j, y_j)$ sont divulguées. Le flag est chiffré avec AES-CBC, la clé étant `SHA256(flag)` = `long_to_bytes(c[0])`.

## Analyse de la vulnérabilité

Chaque équation satisfait :
$$\sum_{i=0}^{29} c_i \cdot x_j^{29-i} - k_j \cdot p = y_j$$

Tous les $c_i \leq 2^{256}$ (sortie SHA-256) alors que $p \sim 2^{1024}$. Cela crée un **Hidden Number Problem (HNP)** : les inconnues (coefficients) sont **beaucoup plus courtes** que le module. Avec 20 équations pour 30 inconnues, le système est sur-déterminé. La clé d'attaque est l'algorithme de réduction LLL sur un réseau approprié.

## Construction du réseau

Dimension de la matrice : $20 + 30 + 1 = 51$.

| Bloc | Lignes | Description |
|------|--------|-------------|
| Bloc $k_j$ | 0 à 19 | Diagonale : $K \cdot p$ |
| Bloc $c_i$ | 20 à 49 | Ligne $i$ : $[K \cdot x_0^{29-i}, \dots, K \cdot x_{19}^{29-i}, 0, \dots, 1, \dots, 0]$ |
| Vecteur cible | 50 | $[K \cdot y_0, \dots, K \cdot y_{19}, 0, \dots, 0, X]$ |

Avec $K = X = 2^{256}$, le vecteur cherché `(0, ..., 0, c0, c1, ..., c29, X)` est naturellement court par rapport au volume du réseau. LLL le trouve en pratique en quelques secondes.

## Exploitation

```python
from fpylll import IntegerMatrix, LLL
# Construire la matrice 51x51...
LLL.reduction(M)
# Chercher le vecteur avec les 20 premières colonnes à 0 et la dernière à ±X
# Extraire c0 (= bytes_to_long(master_key))
master_key = long_to_bytes(c0).rjust(32, b'\x00')
# Déchiffrer AES-CBC
flag = unpad(AES.new(master_key, AES.MODE_CBC, iv).decrypt(ct), 16)
```

**Flag :** `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

## Concepts clés

- **Lattice Attacks / LLL** : quand un problème algébrique implique de "petites" solutions relatives au module, LLL peut retrouver ces solutions.
- **HNP (Hidden Number Problem)** : paradigme cryptographique exploitant la faiblesse de petits secrets dans des équations modulaires.
- **fpylll** : bibliothèque Python pour la réduction de réseaux (wrapper de fplll).
