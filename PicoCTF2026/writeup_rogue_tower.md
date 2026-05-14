# Writeup - Rogue Tower (picoCTF)

**Difficulté** : ★★★☆☆ (300 points)  
**Catégorie** : Forensics / Réseau  
**Outils utilisés** : `tshark`, `python`, `base64`

---

## 1. Description du Challenge

Une tour cellulaire suspecte a été détectée. L'objectif est d'analyser une capture réseau (`.pcap`) pour identifier la tour malveillante, le périphérique compromis, l'IMSI de la victime, et récupérer le flag exfiltré via des requêtes HTTP POST.

---

## 2. Analyse du Trafic Réseau

### Identification de la Tour Malveillante
En filtrant les broadcasts sur le port **UDP 55000**, nous identifions une balise réseau suspecte :
```bash
tshark -r rogue_tower.pcap -Y "udp.port == 55000" -T fields -e data.data | xxd -r -p
# Résultat : UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=91521
```
La tour malveillante a l'adresse IP **192.168.99.1**.

### Identification du Périphérique et de l'IMSI
Nous analysons ensuite le trafic HTTP pour identifier le périphérique qui s'est connecté à ce `CELLID` :
```bash
tshark -r rogue_tower.pcap -Y "http" -T fields -e ip.src -e http.user_agent | grep "91521"
# Résultat : 10.100.101.252 MobileDevice/1.0 (IMSI:310410050746829; CELL:91521)
```
- **IP Victime** : `10.100.101.252`
- **IMSI** : `310410050746829`

---

## 3. Récupération des Données Exfiltrées

Le flag est envoyé en plusieurs parties via des requêtes HTTP POST vers le serveur de l'attaquant (`198.51.100.102`). Nous récupérons les données brutes :
Concaténation des payloads POST -> `RVlUW3VsdEJHAFBBBWdRCllcaEAGTwFLagNWAVINB1sHTQ==` (Base64).

---

## 4. Déchiffrement

Le challenge indique que la clé est dérivée de l'IMSI. Après quelques tests de XOR, il s'avère que la clé est constituée des 8 derniers chiffres de l'IMSI : `50746829`.

### Script de Solution (Python)
```python
data = base64.b64decode("RVlUW3VsdEJHAFBBBWdRCllcaEAGTwFLagNWAVINB1sHTQ==")
key = b"50746829"
flag = "".join(chr(data[i] ^ key[i % len(key)]) for i in range(len(data)))
print(flag)
```

---

## 5. Flag Final

**Flag** : `picoCTF{r0gu3_c3ll_t0w3r_3a5d55b2}`
