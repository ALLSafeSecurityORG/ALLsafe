import re
import requests
import ipaddress
from datetime import datetime
from flask import request

# ----------------- Trusted Proxies (Cloudflare + Custom) -----------------
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # Add your own proxy IPs if needed
]

# ----------------- Utility: Get Real IP -----------------
def is_trusted_proxy(ip):
    """Check if the IP is within a trusted proxy range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        return False
    return False

def get_real_ip():
    """Get the real client IP address, accounting for trusted proxies."""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    x_real_ip = request.headers.get("X-Real-IP")
    remote_ip = request.remote_addr

    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    else:
        return remote_ip

# ----------------- Geolocation -----------------
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

# ----------------- SQL Injection Detection -----------------
def detect_sql_injection(email, password, ip):
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
    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, ip, combined)
            return True
    return False

# ----------------- Attack Logger -----------------
def log_attack(email, ip, payload):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    real_ip = get_real_ip()  # Get real IP after checking for trusted proxies
    geo = get_geolocation(real_ip)

    log_message = (
        f"[{timestamp}] [SQL INJECTION DETECTED] "
        f"REAL_IP: {real_ip} | PROXY_IP: {ip} | GEO: {geo} | "
        f"X-Real-IP: {request.headers.get('X-Real-IP')} | "
        f"X-Forwarded-For: {request.headers.get('X-Forwarded-For')} | "
        f"Payload: {payload}\n"
    )
    with open("logs/attacks.log", "a") as f:
        f.write(log_message)

# ----------------- Example of SQL Injection detection -----------------
# In your application, you would call detect_sql_injection like this:
# detect_sql_injection(email="test@example.com", password="OR 1=1", ip="192.168.1.1")
