# Small Trouble - Solution (Wiener Attack on RSA)

**Difficulté** : ★★★★☆ (400 points)  
**Catégorie** : Cryptographie  
**Attaque** : Wiener Attack (fractions continues)  
**Outils utilisés** : Python 3, `pycryptodome`

---

## 1. Description du Challenge

Un message RSA a été chiffré avec une paire de clés $(n, e, c)$ où le paramètre RSA `d` (exposant privé) vérifie une condition spéciale : il est suffisamment petit pour être vulnérable à l'attaque de Wiener.

### Paramètres fournis

- **n** : modulo RSA (2048 bits)
- **e** : exposant public
- **c** : message chiffré

---

## 2. Théorie de l'Attaque de Wiener

### Condition vulnérable

L'attaque de Wiener s'applique quand :
$$d < \frac{1}{3} n^{1/4}$$

### Algorithme

1. **Développement en fractions continues** : On calcule les convergentes de $\frac{e}{n}$

2. Pour chaque convergente $\frac{k}{d}$ où $k$ est petit :
   - Calculer $\phi = \frac{ed - 1}{k}$
   - Vérifier si $n$, $\phi$ et $d$ satisfont les équations RSA

3. **Test de validité** :
   $$\phi = n - p - q + 1$$
   
   où $p$ et $q$ sont les facteurs premiers de $n$ :
   $$b = n - \phi + 1$$
   $$\Delta = b^2 - 4n$$
   
   Si $\Delta \geq 0$ et $\sqrt{\Delta}$ est un entier, alors $d$ est valide.

---

## 3. Explication Mathématique

### Fractions continues

Pour la fraction $\frac{e}{n}$, on calcule les convergentes :

$$\frac{k_0}{d_0}, \frac{k_1}{d_1}, \frac{k_2}{d_2}, \ldots$$

Chaque convergente $\frac{k_i}{d_i}$ est une approximation rationnelle de $\frac{e}{n}$.

### Récupération des racines

Avec $b = n - \phi + 1$, les facteurs $p$ et $q$ se calculent par :

$$p, q = \frac{b \pm \sqrt{b^2 - 4n}}{2}$$

Si le discriminant $\Delta = b^2 - 4n$ est un carré parfait, nous pouvons factoriser $n$.

---

## 4. Étapes de la Solution

1. **Convertir** $\frac{e}{n}$ en fractions continues
2. **Calculer** toutes les convergentes
3. **Pour chaque** convergente $(k, d)$ :
   - Vérifier que $k \neq 0$ et $d$ est impair
   - Calculer $\phi = \frac{ed - 1}{k}$
   - Vérifier la condition discriminante
4. **Récupérer** les facteurs $p$ et $q$
5. **Déchiffrer** : $m = c^d \bmod n$
6. **Convertir** en texte lisible

---

## 5. Résultat

Après récupération de la clé privée $d$, le message est déchiffré et décodé :

$$m = c^d \pmod{n}$$

**Flag** : Texte décodé du message déchiffré.

---

## 6. Prérequis

```bash
pip install pycryptodome
python3 --version  # Python 3.6+
```

**Note** : Le script augmente la limite `sys.set_int_max_str_digits(10000)` pour gérer les très grands entiers (Python 3.11+).

---

## 7. Utilisation

```bash
python3 soluceSmallTrouble.py
```

Le script affiche :
- La clé privée $d$ découverte
- Le message déchiffré
- Le flag final

---

## 8. Références

- [Wiener's Attack on RSA](https://en.wikipedia.org/wiki/Wiener's_attack)
- [Continued Fractions and Cryptography](https://crypto.stackexchange.com/questions/33901/wieners-attack-on-rsa)
- [RSA Factorization via Continued Fractions](https://www.jstor.org/stable/2007875)
