import re
import requests
import ipaddress
from flask import request
from datetime import datetime

# ========== LOG FILE ==========
ATTACK_LOG = "logs/attacks.log"

# ========== GEOLOCATION SETUP ==========
GEO_API = "http://ip-api.com/json/"

# ========== TRUSTED PROXIES ==========
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

def is_trusted_proxy(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False

# ========== IP EXTRACTOR ==========
def get_real_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For", "")
    x_real_ip = request.headers.get("X-Real-IP", "")
    remote_ip = request.remote_addr or "Unknown"

    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    return remote_ip

# ========== GEOLOOKUP ==========
def get_geolocation(ip):
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

# ========== SQLi DETECTION ==========
def detect_sql_injection(email, password, ip=None):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bSLEEP\s*\(\s*\d+\s*\))",
        r"(\bWAITFOR\s+DELAY\b)",
        r"(\bEXEC(\s+|UTE)\b)",
        r"(\bINFORMATION_SCHEMA\b)",
        r"(\bCAST\s*\()",
        r"(\bCONVERT\s*\()",
        r"(\bHAVING\b\s+\d+=\d+)",
        r"(\bLIKE\s+['\"]?%\w+%['\"]?)",
        r"(\bBENCHMARK\s*\(\s*\d+\,)",
        r"(\bOUTFILE\b|\bDUMPFILE\b|\bINTO\b\s+\bFILE\b)",
        r"(\bLOAD_FILE\s*\()",
        r"(\bGROUP\s+BY\b\s+[\w\W]*\()",
        r"(\bXPATH\b\s*\()",
        r"(\bCHAR\s*\(\d+\))"
    ]

    combined = f"{email} {password}"
    ip = ip or get_real_ip()
    location = get_geolocation(ip)

    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, ip, location, combined)
            return True
    return False

# ========== ATTACK LOGGER ==========
def log_attack(email, ip, location, payload):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = (
        f"[{timestamp}] [SQL INJECTION DETECTED] "
        f"IP: {ip} | Location: {location} | Email: {email} | Payload: {payload}\n"
    )
    with open(ATTACK_LOG, "a") as f:
        f.write(log_message)
