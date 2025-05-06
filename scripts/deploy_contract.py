from solcx import compile_source
from web3 import Web3
import json
from settings import BLOCKCHAIN

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN['PROVIDER']))
with open('contracts/DataStorage.sol', 'r') as f:
    source = f.read()
compiled = compile_source(source, output_values=['abi', 'bin'])
contract_id, contract_interface = compiled.popitem()
abi = contract_interface['abi']
bytecode = contract_interface['bin']

account = w3.eth.account.from_key(BLOCKCHAIN['PRIVATE_KEY'])
contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = contract.constructor().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 2000000,
    'gasPrice': w3.to_wei('20', 'gwei')
})
signed_tx = w3.eth.account.sign_transaction(tx, BLOCKCHAIN['PRIVATE_KEY'])
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # 注意是 snake_case
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = receipt.contractAddress
print(f"Contract deployed at {contract_address}")

with open('smart_community/blockchain/contract_abi.json', 'w') as f:
    json.dump(abi, f)