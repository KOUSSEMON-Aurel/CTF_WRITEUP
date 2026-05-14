# Writeup PicoCTF - Related Messages

**Challenge :** Related Messages
**Catégorie :** Cryptography
**Points :** 200 pts
**Flag :** `picoCTF{m3ssage_w1th_typ0}`

## Description

Le challenge fournit un script `chall.py` et son résultat `output.txt`. Le script chiffre deux messages RSA en utilisant la même clé publique (`N` et `e=17`).
Le deuxième message est une version corrigée du premier, et nous connaissons la différence exacte entre les deux (`M - M_fixed = -3`).

## Analyse de l'algorithme

La situation correspond exactement aux conditions d'une attaque de **Franklin-Reiter sur des messages liés** (Related Message Attack) :

1. Nous avons deux textes clairs : $M_1$ et $M_2$.
2. Une relation affine connue entre les deux : $M_2 = M_1 + 3$.
3. Les deux messages sont chiffrés avec la même clé publique $(N, e)$.
4. L'exposant $e$ est petit ($e = 17$).

On forme les deux polynômes dans l'anneau $\mathbb{Z}_N[x]$ :

- $f_1(x) = x^e - C_1$
- $f_2(x) = (x + 3)^e - C_2$

Puisque $M_1$ est racine des deux polynômes, le PGCD de $f_1(x)$ et $f_2(x)$ sera de la forme $x - M_1$.

## Exploitation

Bien que cette attaque soit nativement réalisable avec `SageMath`, il est tout à fait possible de l'implémenter en Python pur avec une classe `Polynomial` gérant les opérations modulo $N$ et l'algorithme d'Euclide.

Le calcul du PGCD donne un polynôme de degré 1 de la forme $ax + b$.
Le message clair original s'obtient par $M_1 = -b \times a^{-1} \pmod N$.

Le déchiffrement de $M_1$ donne la chaîne en bytes : `b'picoCTF{m3ssage_w1th_typ0z'`.
Puisque $M_{fixed} = M_1 + 3$, on ajoute 3 au dernier code ASCII (`'z'` = 122).
$122 + 3 = 125$, ce qui correspond au caractère de fermeture d'accolade `}`.

Le message corrigé (et donc le flag) est bien `picoCTF{m3ssage_w1th_typ0}`.

## Concepts clés retenus

* **Attaque de Franklin-Reiter** : Exploitée lorsque deux messages ayant une relation connue sont chiffrés avec un petit $e$.
- **Arithmétique polynomiale** : Le calcul du PGCD de polynômes modulaires permet d'extraire des racines communes très efficacement sans factoriser le module $N$.
