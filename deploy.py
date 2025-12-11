from solcx import compile_standard, install_solc
import json
from web3 import Web3
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration Ganache
GANACHE_URL = os.environ.get('GANACHE_URL', 'HTTP://127.0.0.1:7545')
CHAIN_ID = int(os.environ.get('CHAIN_ID', '1337'))
ADMIN_ADDRESS = os.environ.get('ADMIN_ADDRESS')
ADMIN_KEY = os.environ.get('ADMIN_KEY')

# Connexion Web3
w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

def compile_contract():
    """Compile le contrat Loterie.sol et retourne l'ABI et le Bytecode."""
    with open("Loterie.sol", "r") as file:
        loterie_file = file.read()

    install_solc("0.8.2")

    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {"Loterie.sol": {"content": loterie_file}},
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                    }
                }
            },
        },
        solc_version="0.8.2",
    )

    with open("compiled_code.json", "w") as file:
        json.dump(compiled_sol, file)

    bytecode = compiled_sol["contracts"]["Loterie.sol"]["Loterie"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["Loterie.sol"]["Loterie"]["abi"]
    
    return abi, bytecode

def get_contract_data():
    """Charge l'ABI et le Bytecode depuis le fichier compilé ou compile si nécessaire."""
    if not os.path.exists("compiled_code.json"):
        return compile_contract()
    
    with open("compiled_code.json", "r") as file:
        compiled_sol = json.load(file)
        
    bytecode = compiled_sol["contracts"]["Loterie.sol"]["Loterie"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["Loterie.sol"]["Loterie"]["abi"]
    return abi, bytecode

def deploy_contract():
    """Déploie un nouveau contrat et retourne son adresse."""
    abi, bytecode = get_contract_data()
    Loterie = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    nonce = w3.eth.get_transaction_count(ADMIN_ADDRESS)
    
    transaction = Loterie.constructor().build_transaction({
        "chainId": CHAIN_ID,
        "from": ADMIN_ADDRESS,
        "nonce": nonce
    })
    
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=ADMIN_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    contract_address = tx_receipt.contractAddress
    
    # Sauvegarder l'état
    with open("state.json", "w") as f:
        json.dump({"contract_address": contract_address}, f)
        
    return contract_address

def get_contract(contract_address):
    """Retourne une instance du contrat."""
    abi, _ = get_contract_data()
    contract = w3.eth.contract(address=contract_address, abi=abi)
    return contract

def participer(contract_address, user_address, user_private_key):
    """Fait participer un utilisateur à la loterie."""
    contract = get_contract(contract_address)
    nonce = w3.eth.get_transaction_count(user_address)
    
    transaction = contract.functions.participer().build_transaction({
        "chainId": CHAIN_ID,
        "from": user_address,
        "nonce": nonce,
        "value": w3.to_wei(1, "ether")
    })
    
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=user_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def tirage(contract_address):
    """Lance le tirage au sort (Admin seulement)."""
    contract = get_contract(contract_address)
    nonce = w3.eth.get_transaction_count(ADMIN_ADDRESS)
    
    transaction = contract.functions.tirage().build_transaction({
        "chainId": CHAIN_ID,
        "from": ADMIN_ADDRESS,
        "nonce": nonce
    })
    
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=ADMIN_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    # Get winner from event logs
    winner_address = None
    prize_amount = None
    owner_fee = None
    
    for log in tx_receipt['logs']:
        try:
            event = contract.events.Winner().process_log(log)
            winner_address = event['args']['winner']
            prize_amount = w3.from_wei(event['args']['prize'], 'ether')
            owner_fee = w3.from_wei(event['args']['ownerFee'], 'ether')
        except:
            pass
    
    # Save winner info to state.json with contract address
    if winner_address:
        if os.path.exists("state.json"):
            with open("state.json", "r") as f:
                data = json.load(f)
        else:
            data = {}
        
        data["last_winner"] = winner_address
        data["prize_amount"] = float(prize_amount)
        data["owner_fee"] = float(owner_fee)
        data["winner_contract"] = contract_address
        
        with open("state.json", "w") as f:
            json.dump(data, f)
    
    return tx_receipt

def get_balance(contract_address):
    """Retourne le solde du contrat en Ether."""
    balance_wei = w3.eth.get_balance(contract_address)
    return w3.from_wei(balance_wei, "ether")

def get_last_winner(contract_address=None):
    """Récupère les informations du dernier gagnant depuis state.json"""
    if os.path.exists("state.json"):
        try:
            with open("state.json", "r") as f:
                data = json.load(f)
                # Vérifier que le gagnant appartient au contrat actuel
                if contract_address and data.get("winner_contract") != contract_address:
                    return None
                return {
                    "winner": data.get("last_winner"),
                    "prize": data.get("prize_amount"),
                    "owner_fee": data.get("owner_fee"),
                    "contract": data.get("winner_contract")
                }
        except:
            return None
    return None