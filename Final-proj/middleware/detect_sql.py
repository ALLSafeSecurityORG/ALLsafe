import re
import ipaddress
from datetime import datetime

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
    """Check if the given IP is part of a trusted proxy network (e.g., Cloudflare)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False

# ========== IP EXTRACTOR ==========
def get_real_ip(request):
    """Get the real client IP by checking headers or request.remote_addr."""
    # Check headers for X-Forwarded-For or X-Real-IP
    x_forwarded_for = request.headers.get("X-Forwarded-For", "")
    x_real_ip = request.headers.get("X-Real-IP", "")
    remote_ip = request.remote_addr or "Unknown"

    # If the request is from a trusted proxy (like Cloudflare) and has an X-Forwarded-For header
    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()  # The first IP in the list is the real client IP
    elif x_real_ip:
        return x_real_ip.strip()  # If X-Real-IP is available, use it
    return remote_ip  # Fallback to remote IP

# ========== SQLi DETECTION ==========
def detect_sql_injection(email, password, ip, request):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # ' or -- or #
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",      # OR 1=1, AND 1=1
        r"(\bUNION\b.*\bSELECT\b)",         # UNION SELECT
        r"(\bSELECT\b.*\bFROM\b)",          # SELECT * FROM users
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",  # INSERT/UPDATE/DELETE
        r"(\bDROP\b\s+\bTABLE\b)"           # DROP TABLE
    ]

    combined = f"{email} {password}"
    ip = ip or get_real_ip(request)  # Get real IP from headers if available
    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, ip, combined)
            return True
    return False

# ========== ATTACK LOGGER ==========
def log_attack(email, ip, payload):
    """Log detected attacks to a file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] [SQL INJECTION DETECTED] IP: {ip} | Email: {email} | Payload: {payload}\n"
    with open("logs/attacks.log", "a") as f:
        f.write(log_message)
