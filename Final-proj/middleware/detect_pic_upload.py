import re
import logging
from flask import request
import requests
from datetime import datetime

# Attack logger setup
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
attack_logger.addHandler(attack_handler)

# Trusted proxies like Cloudflare
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # IPv6 ranges
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

def get_real_ip():
    """Extract real client IP, considering proxy headers."""
    # If X-Forwarded-For header is present, get the real client IP
    if "X-Forwarded-For" in request.headers:
        forwarded_for = request.headers.get("X-Forwarded-For")
        ip = forwarded_for.split(",")[0].strip()  # Get the first IP in the list
    else:
        ip = request.remote_addr or "Unknown"  # If no X-Forwarded-For, fall back to remote_addr
    return ip

def get_geo_location(ip):
    """Fetch geolocation based on the client IP."""
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "GeoLookup Failed"

def detect_malicious_upload(filename, content_type, user_info):
    ip = get_real_ip()  # Get the real IP
    geo = get_geo_location(ip)  # Get the geolocation for the real IP

    alerts = []

    # Checking for common malicious file upload patterns
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

    # If any alerts are triggered, log them
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
        return True  # Malicious upload detected

    return False  # No issues found
