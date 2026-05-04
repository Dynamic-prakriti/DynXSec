import os
from flask import Flask, request, jsonify
from routes.logs import log_bp
import sqlite3
from database import init_db, insert_case, get_logs, get_alerts, get_cases
from flask_cors import CORS

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "siem.db")

app = Flask(__name__)
CORS(app)

# Register routes
app.register_blueprint(log_bp)

# Home route
@app.route("/")
def home():
    return "DynXSec Server Running"

# Create case
@app.route("/create_case", methods=["POST"])
def create_case():
    data = request.json
    print("DEBUG:", data)

    alert_id = data.get("alert_id")
    notes = data.get("notes", "")

    insert_case(alert_id, "open", notes)

    return({"message": "Case created"})


@app.route("/update_case", methods=["POST"])
def update_case():
    data = request.json

    case_id = data.get("case_id")
    status = data.get("status")

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
    DB_PATH = os.path.join(BASE_DIR,"siem.db")
    print("Using DB:", DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cases
        SET status = ?
        WHERE id = ?
    """, (status, case_id))

    conn.commit()
    conn.close()

    return {"message": "updated"}
    
    return jsonify({"message": "Case updated"})

@app.route("/data", methods=["GET"])
def get_data():
    import sqlite3
    import os

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    DB_PATH = os.path.join(BASE_DIR, "siem.db")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT ip, event, status, timestamp FROM logs")
    logs = cursor.fetchall()

    cursor.execute("SELECT id, type, ip, message, severity FROM alerts")
    alerts = cursor.fetchall()

    cursor.execute("""
        SELECT c.id, c.status, c.notes, c.created_at, a.type, a.ip
        FROM cases c
        LEFT JOIN alerts a ON c.alert_id = a.id
    """)
    cases = cursor.fetchall()

    conn.close()

    return jsonify({
        "logs": get_logs(),
        "alerts": get_alerts(),
        "cases": get_cases()
    })


@app.route("/logs", methods=["GET"])
def get_logs():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    offset = (page - 1) * limit

    sort = request.args.get("sort", "timestamp")
    direction = request.args.get("dir", "desc")

    ip = request.args.get("ip", "")
    status = request.args.get("status", "")
    keyword = request.args.get("keyword", "")

    start = request.args.get("startDate")
    end = request.args.get("endDate")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = "SELECT timestamp, ip, event, status FROM logs WHERE 1=1"
    params = []

    if ip:
        query += " AND ip LIKE ?"
        params.append(f"%{ip}%")

    if status:
        query += " AND status = ?"
        params.append(status)

    if keyword:
        query += " AND event LIKE ?"
        params.append(f"%{keyword}%")

    date = request.args.get("date")

    if date == "24h":
        query += " AND datetime(timestamp) >= datetime('now','-1 day')"
    elif date == "7d":
        query += " AND datetime(timestamp) >= datetime('now','-7 day')"

     # custom date 
    if start and end:
        query += " AND date(timestamp) BETWEEN date(?) AND date(?)"
        params.extend([start, end])

    query += f" ORDER BY {sort} {direction} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    logs = cursor.fetchall()

    conn.close()

    return jsonify({"logs": logs})

  

@app.route("/log-statuses")
def get_log_statuses():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT status FROM logs")
    rows = cursor.fetchall()

    conn.close()

    statuses = [r[0] for r in rows if r[0]]

    return jsonify({"statuses": statuses})

@app.route("/alerts")
def get_alerts_paginated():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    offset = (page - 1) * limit

    sort = request.args.get("sort", "id")
    direction = request.args.get("dir", "desc")

    # whitelist fields 
    valid_fields = {
        "id": "id",
        "severity": "severity"
    }

    sort_field = valid_fields.get(sort, "id")
    order = "ASC" if direction == "asc" else "DESC"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = f"""
        SELECT id, type, ip, message, severity
        FROM alerts
        ORDER BY {sort_field} {order}
        LIMIT ? OFFSET ?
    """

    cursor.execute(query, (limit, offset))
    rows = cursor.fetchall()

    alerts = [{
        "id": r[0],
        "type": r[1],
        "ip": r[2],
        "message": r[3],
        "severity": r[4]
    } for r in rows]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        "alerts": alerts,
        "total": total
    })


# Init DB
init_db()

if __name__ == "__main__":
    app.run(port=5000, debug=True)
