# Writeup PicoCTF - Bytemancy 1

**Challenge :** Bytemancy 1
**Catégorie :** Cryptography / Scripting
**Points :** 100 pts
**Flag :** `picoCTF{h0w_m4ny_e's???_f569ad6f}`

## Description

Ce challenge est une variante de Bytemancy 0. Le programme attend cette fois une répétition beaucoup plus longue du caractère 'e'.

## Étapes de la solution

### 1. Analyse du code source

Le fichier `app.py` contient la condition suivante :

```python
if user_input == "\x65"*1751:
    print(open("./flag.txt", "r").read())
```

Il faut donc envoyer le caractère `e` (ASCII 101 / `\x65`) exactement **1751 fois**.

### 2. Script d'exploitation

L'utilisation d'un script est recommandée par l'indice ("No copy-pasta, please - use Python!").

```python
import socket

def solve():
    host = "foggy-cliff.picoctf.net"
    port = 61988
    payload = "e" * 1751 + "\n"
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.recv(4096) # Bannière
            s.sendall(payload.encode())
            
            response = ""
            while True:
                chunk = s.recv(4096).decode()
                if not chunk: break
                response += chunk
                if "picoCTF{" in response: break
            print(f"Flag : {response.strip()}")
            
    except Exception as e:
        print(f"Erreur : {e}")

if __name__ == "__main__":
    solve()
```

### 3. Résultat

L'envoi automatique du long buffer d'octets a permis de débloquer l'accès au fichier `flag.txt` sur le serveur.

**Flag :** `picoCTF{h0w_m4ny_e's???_f569ad6f}`

## Concepts clés retenus

* **Automatisation** : Certains payloads sont trop longs pour être saisis manuellement, l'utilisation de scripts (Python, pwntools) est essentielle en CTF.
* **Manipulation de buffers** : Programmer l'envoi exact de $N$ octets spécifiques.
