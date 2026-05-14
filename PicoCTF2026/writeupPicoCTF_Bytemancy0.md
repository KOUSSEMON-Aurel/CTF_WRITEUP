# Writeup PicoCTF - Bytemancy 0

**Challenge :** Bytemancy 0
**Catégorie :** Cryptography / Reverse Engineering
**Auteur :** LT 'syreal' Jones
**Flag :** `picoCTF{pr1n74813_ch4r5_184029cd}`

## Description

Le challenge demande d'envoyer les bons octets à un programme distant.

## Étapes de la solution

### 1. Analyse du code source

Le fichier `app.py` contient la condition de victoire :

```python
if user_input == "\x65\x65\x65":
    print(open("./flag.txt", "r").read())
```

`\x65` est le caractère `e` en ASCII (101 en décimal).

### 2. Script d'exploitation

Voici le script Python utilisé pour automatiser la récupération du flag :

```python
import socket

def solve():
    host = "candy-mountain.picoctf.net"
    port = 59117
    payload = "eee\n"
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.recv(1024) # Bannière
            s.sendall(payload.encode())
            
            response = ""
            while True:
                chunk = s.recv(1024).decode()
                if not chunk: break
                response += chunk
                if "picoCTF{" in response: break
            print(f"Flag récupéré : {response.strip()}")
            
    except Exception as e:
        print(f"Erreur : {e}")

if __name__ == "__main__":
    solve()
```

### 3. Résultat

L'exécution a retourné le flag : `picoCTF{pr1n74813_ch4r5_184029cd}`.
