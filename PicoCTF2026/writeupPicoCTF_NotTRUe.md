# Writeup PicoCTF - Not TRUe

**Challenge :** Not TRUe
**Catégorie :** Cryptographie
**Points :** 400 pts
**Flag :** `picoCTF{th4ts_s0_N0t_TRU3_d15f40a6}`

## Description du problème

Le challenge implémente le cryptosystème **NTRU** (N-th degree TRUncated polynomial ring unit lattice) sur l'anneau $R = \mathbb{Z}_q[x]/(x^N - 1)$.
Les paramètres fournis sont :

- $N = 48$
- $p = 3$
- $q = 509$
- Clé publique $h$

## Analyse de la vulnérabilité

La sécurité de NTRU repose sur la difficulté de trouver le vecteur le plus court dans un réseau (SVP - Shortest Vector Problem). Cependant, la dimension $N=48$ est extrêmement faible. Le réseau de Coppersmith-Shamir associé à NTRU a une dimension de $2N = 96$.
Pour $N=48$, l'algorithme de réduction de base **LLL** est capable de retrouver la clé privée $f$ quasi instantanément.

## Construction du réseau

Nous construisons une matrice $M$ de taille $2N \times 2N$ :
$$M = \begin{pmatrix} I_{N \times N} & H \\ 0 & qI_{N \times N} \end{pmatrix}$$
où $H$ est la matrice circulante de la clé publique $h$.

Le vecteur $(f, g)$ appartient à ce réseau. Comme $f$ et $g$ ont des coefficients très petits (dans $\{-1, 0, 1\}$), $(f, g)$ est un vecteur très court que LLL identifiera dans les premières lignes de la matrice réduite.

## Exploitation (SageMath)

1. **Calcul de la clé privée** : On réduit la matrice avec `LLL()` et on cherche une ligne dont la première moitié ne contient que des valeurs dans $\{-1, 0, 1\}$.
2. **Déchiffrement** :
   - Calculer $a \equiv f \cdot c \pmod q$
   - Appliquer un `center_lift` sur $a$ pour ramener les coefficients dans l'intervalle $[-q/2, q/2]$.
   - Calculer $m \equiv f_p^{-1} \cdot a \pmod p$ où $f_p^{-1}$ est l'inverse de $f$ modulo $p$.

**Flag :** `picoCTF{th4ts_s0_N0t_TRU3_d15f40a6}`
