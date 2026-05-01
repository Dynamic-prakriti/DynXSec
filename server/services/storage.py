import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_FILE = os.path.join(BASE_DIR, "data", "logs.json")

def save_log(log, alerts):
    entry = {
        "log": log,
        "alerts": alerts
    }

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    with open(DATA_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")