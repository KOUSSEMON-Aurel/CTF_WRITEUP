# Writeup : Autorev 1 (picoCTF)

## Informations sur le Challenge
- **Nom** : Autorev 1
- **Points** : 200
- **Catégorie** : Reverse Engineering / Automation
- **Auteur** : SkrubLawd

## Description
Le challenge teste notre rapidité en reverse engineering. En se connectant au service `nc mysterious-sea.picoctf.net 53388`, on découvre que le serveur envoie **20 binaires** consécutifs sous forme de dump hexadécimal. Pour chaque binaire, nous avons seulement **1 seconde** pour extraire un "secret" et l'envoyer en réponse.

## Analyse
Chaque binaire envoyé est un exécutable ELF. Une analyse de la fonction `main` montre qu'elle effectue une vérification simple :

```c
if (user_input == 0xSECRET_VALUE) {
    puts("Correct!");
}
```

La valeur secrète est stockée en dur dans le code sous forme de valeur immédiate dans une instruction de comparaison (`cmp`) ou de chargement (`mov`).

## Solution : Automatisation
Vu la contrainte de temps, une résolution manuelle est impossible. J'ai utilisé un script Python pour automatiser le processus.

### Étapes du script :
1. **Connexion** : Utilisation de `socket` pour communiquer avec le serveur.
2. **Récupération** : Lecture du flux hexadécimal et conversion en binaire avec `binascii.unhexlify`.
3. **Désassemblage** : Utilisation d' `objdump -d -M intel` sur le binaire temporaire.
4. **Extraction** : Recherche du secret via des expressions régulières dans la section `<main>`.
5. **Soumission** : Envoi du secret converti en base 10.

## Conclusion
Après avoir passé les 20 rounds, le serveur délivre le flag.

**Flag** : `picoCTF{4u7o_r3v_g0_brrr_78c345aa}`
