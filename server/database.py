import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
DB_PATH = os.path.join(BASE_DIR, "siem.db")

from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc)


def init_db():

    print("SERVER DB PATH:", DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        event TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        ip TEXT,
        message TEXT,
        severity TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Cases table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        status TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


#  Insert log
def insert_log(log):
    import sqlite3
    import os

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    DB_PATH = os.path.join(BASE_DIR, "siem.db")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    #  ENSURE TABLE EXISTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        event TEXT,
        status TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    #  INSERT LOG
    cursor.execute("""
        INSERT INTO logs (ip, event, status)
        VALUES (?, ?, ?)
    """, (log.get("ip"), log.get("event"), log.get("status")))

    conn.commit()
    conn.close()

    print(" LOG INSERTED")

def insert_alert(alert):
    import sqlite3
    import os

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    DB_PATH = os.path.join(BASE_DIR, "siem.db")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    #  ENSURE TABLE EXISTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        ip TEXT,
        message TEXT,
        severity TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    #  INSERT ALERT
    cursor.execute("""
        INSERT INTO alerts (type, ip, message, severity)
        VALUES (?, ?, ?, ?)
    """, (
        alert.get("type"),
        alert.get("ip"),
        alert.get("message"),
        alert.get("severity")
    ))

    conn.commit()
    conn.close()

    print(" ALERT INSERTED")

#  Insert case

def insert_case(alert_id, status, notes):
    import sqlite3
    import os

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    DB_PATH = os.path.join(BASE_DIR, "siem.db")

    print("INSERT USING DB:", DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    #  GUARANTEE TABLE EXISTS (THIS FIXES YOUR ISSUE)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        status TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    #  NOW INSERT
    cursor.execute("""
        INSERT INTO cases (alert_id, status, notes)
        VALUES (?, ?, ?)
    """, (alert_id, status, notes))

    conn.commit()
    conn.close()

    print(" CASE INSERTED")


def get_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows


def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows


def get_cases():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 50")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows


