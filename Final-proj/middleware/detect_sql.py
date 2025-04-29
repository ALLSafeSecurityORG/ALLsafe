# middleware/detect_sql.py

import re
from datetime import datetime
import requests
from flask import request

# ========== GEOLOCATION SETUP ========== #
GEO_API = "http://ip-api.com/json/"

def get_real_ip():
    """Extract real client IP even if behind Cloudflare proxy."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    remote_ip = request.remote_addr or "Unknown"

    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
        return ip
    return remote_ip

def get_geolocation(ip):
    """Get geolocation of the IP address."""
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

def detect_sql_injection(email, password, ip=None):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # ' or -- or #
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",      # OR 1=1, AND 1=1
        r"(\bUNION\b.*\bSELECT\b)",         # UNION SELECT
        r"(\bSELECT\b.*\bFROM\b)",          # SELECT * FROM users
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",  # INSERT/UPDATE/DELETE
        r"(\bDROP\b\s+\bTABLE\b)"           # DROP TABLE
    ]

    combined = f"{email} {password}"

    # Use real IP if not passed explicitly
    if ip is None:
        ip = get_real_ip()
    location = get_geolocation(ip)

    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, ip, location, combined)
            return True
    return False

def log_attack(email, ip, location, payload):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = (
        f"[{timestamp}] [SQL INJECTION DETECTED] "
        f"IP: {ip} | Location: {location} | Email: {email} | Payload: {payload}\n"
    )
    with open("logs/attacks.log", "a") as f:
        f.write(log_message)
