def parse_log(log):
    if not log:
        return None

    return {
        "ip": log.get("ip"),
        "event": log.get("event"),
        "status": log.get("status")
    }