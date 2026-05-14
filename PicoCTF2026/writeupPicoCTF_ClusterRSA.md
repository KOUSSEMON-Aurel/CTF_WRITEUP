# Writeup PicoCTF - ClusterRSA

**Challenge :** ClusterRSA
**Catégorie :** Cryptography
**Points :** 400 pts
**Flag :** `picoCTF{mul71_rsa_bcbee34d}`

## Description

Le challenge présente un chiffrement RSA classique, mais avec un module `n` qui semble inhabituel. L'indice suggère que `n` pourrait posséder plus de deux facteurs premiers ("greedy" with primes).

## Analyse du challenge

### 1. Paramètres fournis

- `n` : Un nombre de 100 chiffres (332 bits).
- `e = 65537`.
- `ct` : Le texte chiffré.

### 2. Factorisation de `n`

En interrogeant **Factordb**, on découvre que `n` n'est pas composé de deux grands nombres premiers, mais de **quatre** facteurs de taille égale (environ 25 chiffres chacun) :

- `p1 = 9671406556917033397931773`
- `p2 = 9671406556917033398314601`
- `p3 = 9671406556917033398439721`
- `p4 = 9671406556917033398454847`

## Étapes de la solution

### 1. Calcul de l'Indicateur d'Euler ($\phi$)

Dans le cas d'un RSA multi-prime, $\phi(n)$ est donné par :
$\phi(n) = (p_1 - 1)(p_2 - 1)(p_3 - 1)(p_4 - 1)$

### 2. Calcul de la Clé Privée ($d$)

On calcule l'inverse modulaire de `e` modulo $\phi(n)$ :
$d = e^{-1} \pmod{\phi(n)}$

### 3. Déchiffrement

Le message clair $m$ est retrouvé avec :
$m = ct^d \pmod n$

J'ai utilisé un script Python avec la bibliothèque `pycryptodome` pour effectuer ces calculs de manière précise.

**Résultat :** `picoCTF{mul71_rsa_bcbee34d}`

## Concepts clés retenus

* **Multi-prime RSA** : L'algorithme RSA fonctionne avec n'importe quel nombre de facteurs premiers distincts. $\phi(n)$ est toujours le produit de $(p_i - 1)$.
- **Vulnérabilité** : Si les facteurs premiers sont trop petits (même s'ils sont nombreux), ils peuvent être trouvés via des algorithmes de factorisation ou des bases de données comme Factordb.
- **Factordb** : Un outil indispensable pour vérifier si un module RSA a déjà été factorisé.
