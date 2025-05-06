import hashlib
from web3 import Web3
import json
from config.settings import BLOCKCHAIN

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN['PROVIDER']))
with open('smart_community/blockchain/contract_abi.json', 'r') as f:
    contract_abi = json.load(f)
contract = w3.eth.contract(address=BLOCKCHAIN['CONTRACT_ADDRESS'], abi=contract_abi)

def store_hash(data: str) -> str:
    data_hash = hashlib.sha256(data.encode()).hexdigest()
    account = w3.eth.account.from_key(BLOCKCHAIN['PRIVATE_KEY'])
    tx = contract.functions.storeHash(data_hash).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 200000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, BLOCKCHAIN['PRIVATE_KEY'])
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    return data_hash