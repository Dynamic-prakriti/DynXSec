import json
import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "siem.db")
LOG_PATH = os.path.join(BASE_DIR, "data", "logs.json")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

with open(LOG_PATH, "r") as f:
    for line in f:
        if not line.strip():
            continue

        data = json.loads(line)

        #  Extract LOG
        log = data.get("log", {})

        cursor.execute("""
            INSERT INTO logs (ip, event, status, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        """, (
            log.get("ip"),
            log.get("event"),
            log.get("status")
        ))

        #  Extract ALERTS
        alerts = data.get("alerts", [])

        for alert in alerts:
            cursor.execute("""
                INSERT INTO alerts (type, ip, message, severity, timestamp)
                VALUES (?, ?, ?, ?, datetime('now'))
            """, (
                alert.get("type"),
                alert.get("ip"),
                alert.get("message"),
                "high"  # default severity 
            ))

conn.commit()
conn.close()

print(" Logs + Alerts inserted correctly")