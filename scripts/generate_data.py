import json
import os

data = [
    {"id": i, "resident_name": f"Resident_{i}", "data": f"Community record {i}"}
    for i in range(1, 11)
]
with open('data/sample_data.json', 'w') as f:
    json.dump(data, f, indent=2)