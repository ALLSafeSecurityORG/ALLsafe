import re
import logging
from flask import request
import requests
from datetime import datetime

# Attack logger
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
attack_logger.addHandler(attack_handler)

def get_geo_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "GeoLookup Failed"

def detect_malicious_upload(filename, content_type, user_info):
    ip = request.remote_addr or "Unknown"
    geo = get_geo_location(ip)

    alerts = []

    if re.search(r"\.(php|asp|aspx|jsp|exe|sh|py|rb|pl|cgi|html?|js)(\s|$)", filename, re.IGNORECASE):
        alerts.append("🚨 Dangerous extension")
    if re.search(r"\.(jpg|jpeg|png|gif)\.(php|html?|exe|js)$", filename, re.IGNORECASE):
        alerts.append("⚠️ Double extension")
    if re.search(r"\.(jpg|jpeg|png|gif)\.[a-z0-9]{1,6}\.(php|html?|exe|js)$", filename, re.IGNORECASE):
        alerts.append("⚠️ Triple extension")
    if re.search(r"%00", filename, re.IGNORECASE):
        alerts.append("🚨 Null byte injection attempt")
    if re.search(r"(?:\x00|\s|%00|\\x00|\/|\\)+", filename, re.IGNORECASE):
        alerts.append("⚠️ Filename obfuscation")
    if not content_type.startswith("image/"):
        alerts.append("🚨 MIME spoofing")

    if alerts:
        log_entry = (
            f"[⚠️ File Upload Detection] {datetime.now()}\n"
            f"IP: {ip} | Geo: {geo}\n"
            f"User: {user_info.get('name')} | Email: {user_info.get('email')}\n"
            f"Filename: {filename}\n"
            f"MIME Type: {content_type}\n"
            f"Issues: {', '.join(alerts)}\n"
            f"{'-'*80}\n"
        )
        attack_logger.warning(log_entry)
        return True

    return False
