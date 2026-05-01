import sys
import os
from flask import Flask, render_template
from collections import Counter
import sqlite3

#  Fix import path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

from server.database import init_db
app = Flask(__name__)

@app.route("/")
def index():
    
    DB_PATH = os.path.join(BASE_DIR,"siem.db")
    print("Using DB:", DB_PATH)

    #from server.database import init_db

    init_db()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    
    # Logs
    cursor.execute("SELECT ip, event, status, timestamp FROM logs")
    logs = cursor.fetchall()

    # Alerts
    cursor.execute("SELECT id, type, ip, message, severity, timestamp FROM alerts")
    alerts = cursor.fetchall()

    ips = [a[2] for a in alerts]
    types = [a[1] for a in alerts]

    ip_counts = dict(Counter(ips))
    type_counts = dict(Counter(types))
    

    # Cases

    cursor.execute("""
    SELECT 
        c.id,
        c.status,
        c.notes,
        c.created_at,
        a.type,
        a.ip
    FROM cases c
    LEFT JOIN alerts a ON c.alert_id = a.id
    """)

    cases = cursor.fetchall()
    conn.close()

    case_count = len(cases)
    alert_count = len(alerts)
    log_count = len(logs)

    return render_template(
    "index.html",
    logs=logs,
    alerts=alerts,
    cases=cases,
    case_count=case_count,
    alert_count=alert_count,
    log_count=log_count,
    ip_counts=ip_counts,
    type_counts=type_counts
)


if __name__ == "__main__":
    app.run(port=5001, debug=True)