# Writeup PicoCTF - North-South

**Challenge :** North-South
**Catégorie :** Web Exploitation
**Points :** 100 pts
**Flag :** `picoCTF{g30_b453d_r0u71n9_b5f36094}`

## Description

Le challenge met en place un serveur Nginx utilisant le routage basé sur la géolocalisation (module `ngx_http_geoip2_module`). Seules les requêtes provenant d'Islande (`IS`) sont redirigées vers le serveur contenant le flag (upstream `south`). Le but est de contourner cette restriction, en « voyageant sans quitter sa chaise ».

## Analyse du challenge

### 1. La Configuration Nginx

En lisant le fichier de configuration `nginx.conf` fourni :

```nginx
geoip2 /etc/nginx/GeoLite2-Country.mmdb {
    $geoip2_data_country_code default=ZZ country iso_code;
}

if ($geoip2_data_country_code = IS) {
    proxy_pass http://south;
}
```

L'absence de directives comme `geoip2_proxy` ou le traitement de headers spécifiques signifie que le module `geoip2` inspecte l'adresse IP source réelle de la connexion TCP (`$remote_addr`). Le spoofing traditionnel par entêtes HTTP (`X-Forwarded-For`, `X-Real-IP`, etc.) échouera inévitablement.

### 2. Stratégie adoptée

Puisqu'il n'est pas possible de forger l'IP via des headers HTTP, la requête TCP doit physiquement provenir d'une adresse IP localisée en Islande.
La solution la plus élégante et gratuite pour obtenir une adresse IP spécifique est d'utiliser le réseau **Tor** en forçant le nœud de sortie.

## Étapes de la solution

### 1. Configuration de Tor

J'ai installé et configuré le démon `tor` sur ma machine d'attaque pour demander explicitement un nœud de sortie islandais, via le fichier de configuration `torrc` :

```text
SocksPort 9050
ExitNodes {is}
StrictNodes 1
```

### 2. Exécution du daemon

J'ai lancé le service `tor` avec cette configuration personnalisée et attendu qu'il construise un circuit (le bootstrapping à 100%).

### 3. Requête finale

Une fois le circuit établi, il suffit de router la requête HTTP via le proxy SOCKS5 local vers le serveur de challenge :

```bash
curl -s --socks5-hostname 127.0.0.1:9050 http://lonely-island.picoctf.net:64058/
```

Le serveur `lonely-island.picoctf.net` a perçu la requête comme provenant d'une IP islandaise, et la redirection locale vers l'upstream `south` s'est opérée :

**Résultat :**
`picoCTF{g30_b453d_r0u71n9_b5f36094}`

## Concepts clés retenus

* **Limites du Spoofing IP** : La géolocalisation de niveau TCP base ses décisions sur l'endpoint de connexion final. Si un serveur Nginx ou un WAF n'est pas configuré pour faire confiance à un Load Balancer ou un header `X-Forwarded-For`, l'usurpation simple est impossible.
* **Réseau Tor et Nœuds de Sortie** : Tor permet un paramétrage fin, comme la sélection du pays de son nœud de sortie (`ExitNodes {code_pays}`). C'est un outil extrêmement puissant pour tester ou contourner des restrictions géographiques.
