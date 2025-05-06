import json
import requests

with open('data/sample_data.json', 'r') as f:
    data = json.load(f)

auth = ('admin', 'admin123')
for i, item in enumerate(data):
    response = requests.post(
        'http://127.0.0.1:8000/api/store/',
        auth=auth,
        json={'data': item['data']}
    )
    print(f"Record {i}: {response.json()}")