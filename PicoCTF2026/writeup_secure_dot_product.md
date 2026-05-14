# Writeup - Secure Dot Product (picoCTF)

**Difficulté** : ★★★☆☆ (300 points)  
**Catégorie** : Cryptographie / Réseau  
**Vecteurs d'attaque** : SHA-512 Length Extension Attack (LEA), AES-CBC Decryption, Linear Algebra

---

## 1. Description du Challenge

Le service permet de calculer le produit scalaire (dot product) entre une clé secrète de 32 octets et n'importe quel vecteur, à condition que ce vecteur soit "approuvé". Un vecteur est considéré comme approuvé s'il est accompagné d'un hachage SHA-512 valide calculé avec un sel secret de 256 octets.

Le hachage serveur est calculé comme suit :  
`SHA512(sel + vecteur[1:-1])` où `vecteur[1:-1]` est le contenu textuel à l'intérieur des crochets.

---

## 2. Analyse de la Vulnérabilité

### Length Extension Attack (LEA)
Puisque le sel est utilisé comme un préfixe, nous n'avons pas besoin de le connaître pour "étendre" un hachage existant. Si nous avons un couple `(message, hash)`, nous pouvons calculer `SHA512(sel + message + padding + extra_data)` sans connaître le sel.

### Sanitization Bypass
Le serveur applique un filtre strict : il ne garde que les caractères `0123456789,[]`.
Grâce à `unicode_escape`, nous pouvons envoyer le padding binaire du hachage sous forme d'échappements (ex: `\x80\x00...`). 
1. Le hash est validé sur la chaîne avec padding.
2. La sanitisation supprime les octets binaires du padding.
3. Le vecteur final est interprété comme `[vecteur_original, extra_data]`.

---

## 3. Stratégie d'Exploitation

1. **Collecte de Base** : Se connecter et récupérer le vecteur de confiance fourni par le serveur ainsi que son hash.
2. **Forger des Vecteurs** : Utiliser la bibliothèque `hashpumpy` pour étendre le vecteur de base. En ajoutant des coefficients `1` un par un, on génère un système d'équations.
3. **Système Linéaire** : Chaque réponse du serveur nous donne une équation :
   $$\sum_{i=0}^{31} v_i \cdot k_i = \text{dot\_product}$$
4. **Résolution** : Avec 32 équations linéairement indépendantes, on résout le système avec `numpy` ou `Z3` pour trouver les 32 octets de la clé AES.
5. **Déchiffrement** : Utiliser la clé trouvée pour déchiffrer le flag fourni initialement.

---

## 4. Flag Final

**Flag** : `picoCTF{n0t_so_s3cure_.x_w1th_sh@512_cabf48c0}`

---

## 5. Script de Solution
Le script complet est disponible dans [test.py](./test.py).
