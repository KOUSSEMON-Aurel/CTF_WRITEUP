# Writeup PicoCTF - Undo

**Challenge :** Undo
**Catégorie :** Linux / Text Transformation
**Points :** 100 pts
**Flag :** `picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_3a939318}`

## Description

L'objectif était d'inverser une série de transformations de texte appliquées à un flag, en fournissant les commandes Linux correspondantes à chaque étape.

## Étapes de la solution

### Étape 1 : Inversion du Base64

Le texte était encodé en Base64.

- **Hint :** Base64 encoded the string.
- **Commande :** `base64 -d`
- **Résultat :** `)813939n3-fa01g@ze0sfa4eG-gk3g-ta1ferirE(SGPbpvc`

### Étape 2 : Inversion du texte

Le texte était renversé.

- **Hint :** Reversed the text.
- **Commande :** `rev`
- **Résultat :** `cvpbPGS(Eriref1at-g3kg-Ge4afs0ez@g10af-3n939318)`

### Étape 3 : Remplacement des caractères (Tirets -> Underscores)

Les underscores originaux avaient été remplacés par des tirets.

- **Hint :** Replaced underscores with dashes.
- **Commande :** `tr '-' '_'`
- **Résultat :** `cvpbPGS(Eriref1at_g3kg_Ge4afs0ez@g10af_3n939318)`

### Étape 4 : Remplacement des caractères (Parenthèses -> Accolades)

Les accolades du flag avaient été remplacées par des parenthèses.

- **Hint :** Replaced curly braces with parentheses.
- **Commande :** `tr '()' '{}'`
- **Résultat :** `cvpbPGS{Eriref1at_g3kg_Ge4afs0ez@g10af_3n939318}`

### Étape 5 : Inversion du ROT13

Un chiffrement César de 13 positions (ROT13) avait été appliqué aux lettres.

- **Hint :** Applied ROT13 to letters.
- **Commande :** `tr 'A-Za-z' 'N-ZA-Mn-za-m'` (ou `rot13` si disponible)
- **Résultat final :** `picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_3a939318}`

## Concepts clés retenus

* **Pipeline de texte Linux** : Maîtrise des outils fondamentaux comme `tr`, `rev` et `base64`.
- **Compétences en Scripting** : Automatiser l'envoi de commandes interactives via des pipes (`printf "..." | nc`).
- **ROT13** : Un cas particulier de substitution mono-alphabétique qui est sa propre fonction inverse.
