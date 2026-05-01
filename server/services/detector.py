import time
from collections import defaultdict

counters = defaultdict(lambda: defaultdict(int))
history = defaultdict(list)
time_events = defaultdict(list)

def detect(log):
    alerts = []

    if not log:
        return alerts

    ip = log.get("ip")

    for rule in RULES:

        #  Filter by log type
        if "log_type" in rule and log.get("log_type") != rule["log_type"]:
            continue

        #  THRESHOLD
        if rule["type"] == "threshold":
            if log.get(rule["field"]) == rule["value"]:
                counters[rule["name"]][ip] += 1

                if counters[rule["name"]][ip] > rule["threshold"]:
                    alerts.append({
                        "type": rule["name"],
                        "ip": ip,
                        "message": rule["message"],
                        "severity": rule.get("severity", "medium")
                    })

        #  SEQUENCE
        elif rule["type"] == "sequence":
            history[ip].append(log["status"])
            history[ip] = history[ip][-10:]

            if (
                history[ip].count("failed") >= rule["failure_count"]
                and history[ip][-1] == "success"
            ):
                alerts.append({
                    "type": rule["name"],
                    "ip": ip,
                    "message": rule["message"],
                    "severity": rule.get("severity", "medium")
                })

                history[ip] = []

        #  TIME WINDOW 
        elif rule["type"] == "time_window":
            current_time = time.time()

            if log.get(rule["field"]) == rule["value"]:
                time_events[ip].append(current_time)

                window = rule["window_seconds"]

                # keep only recent events
                time_events[ip] = [
                    t for t in time_events[ip]
                    if current_time - t <= window
                ]

                if len(time_events[ip]) >= rule["threshold"]:
                    alerts.append({
                        "type": rule["name"],
                        "ip": ip,
                        "message": rule["message"],
                        "severity": rule.get("severity", "high")
                    })

                    time_events[ip] = []  # reset

    return alerts