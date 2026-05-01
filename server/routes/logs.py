from flask import Blueprint, request, jsonify
from database import insert_log, insert_alert
from collections import defaultdict
import json
import os
import time

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES_PATH = os.path.join(BASE_DIR, "rules", "rules.json")

with open(RULES_PATH, "r") as f:
    RULES = json.load(f)["rules"]

log_bp = Blueprint("log_bp", __name__)

# In-memory counters (simple for now)
event_counter = defaultdict(int)

# Store logs per IP
event_buffer = defaultdict(list)



def detect(log):
    alerts = []
    now = time.time()

    for rule in RULES:

        rule_type = rule.get("type")
        group_field = rule.get("group_by")
        group = log.get(group_field) if group_field else "global"

        # unique key per rule + group
        key = f"{rule['name']}:{group}"

        # =========================
        # THRESHOLD RULE
        # =========================
        if rule_type == "threshold":
            field = rule["field"]
            value = rule["value"]

            if log.get(field) == value:
                event_counter[key] += 1

                if event_counter[key] >= rule["threshold"]:
                    alerts.append({
                        "type": rule["name"],
                        "ip": group,
                        "message": rule["message"],
                        "severity": rule["severity"]
                    })

                    event_counter[key] = 0  # reset (cooldown)

        # =========================
        #  TIME WINDOW RULE
        # =========================
        elif rule_type == "time_window":
            field = rule["field"]
            value = rule["value"]
            window = rule["window_seconds"]

            if log.get(field) == value:
                event_buffer[key].append(now)

                # keep only events inside window
                event_buffer[key] = [
                    t for t in event_buffer[key]
                    if now - t <= window
                ]

                if len(event_buffer[key]) >= rule["threshold"]:
                    alerts.append({
                        "type": rule["name"],
                        "ip": group,
                        "message": rule["message"],
                        "severity": rule["severity"]
                    })

                    event_buffer[key] = []  # reset after alert

        # =========================
        #  SEQUENCE RULE
        # =========================
        elif rule_type == "sequence":
            fail_key = f"{key}:fail"

            if log.get("status") == "failed":
                event_counter[fail_key] += 1

            elif log.get("status") == "success":
                if event_counter[fail_key] >= rule["failure_count"]:
                    alerts.append({
                        "type": rule["name"],
                        "ip": group,
                        "message": rule["message"],
                        "severity": rule["severity"]
                    })

                event_counter[fail_key] = 0  # reset

    return alerts


@log_bp.route("/logs", methods=["POST"])
def receive_log():
    data = request.json

    print("Incoming log:", data)  # DEBUG

    #  1. Store log
    insert_log(data)

    #  2. Detect alerts
    alerts = detect(data)

    #  3. Store alerts
    for alert in alerts:
        insert_alert(alert)

    return jsonify({"message": "Log processed"})