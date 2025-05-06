from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
account = w3.eth.account.from_key('0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d')

tx = contract.constructor().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 2000000,  # 适当调低 Gas Limit
    'gasPrice': w3.to_wei('10', 'gwei'),  # 手动设置较低的 Gas Price
})