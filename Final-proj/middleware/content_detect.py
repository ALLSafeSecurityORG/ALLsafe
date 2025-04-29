import re
import os
import requests
from datetime import datetime
from flask import request

ATTACK_LOG = 'logs/attacks.log'
GENERAL_LOG = 'logs/general.log'

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

# Patterns to detect common attack content (basic XSS for now)
suspicious_patterns = [
    r"<script.*?>.*?</script>",
    r"on\w+\s*=",
    r"javascript:",
    r"<iframe.*?>",
    r"<img\s+.*?onerror\s*=.*?>",
]

def is_suspicious_content(content):
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False

def get_real_ip():
    """Extract real client IP from X-Forwarded-For or Remote Addr."""
    if "X-Forwarded-For" in request.headers:
        forwarded_for = request.headers.get("X-Forwarded-For")
        # May contain multiple IPs. The first is the client.
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.remote_addr or "Unknown"
    return ip

def get_geo_info(ip):
    """Fetch geolocation data using a public API."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            country = data.get("country_name", "Unknown")
            region = data.get("region", "Unknown")
            city = data.get("city", "Unknown")
            org = data.get("org", "Unknown")
            return f"{city}, {region}, {country} | ISP: {org}"
        else:
            return "Geolocation API error"
    except Exception as e:
        return f"Geolocation failed: {e}"

def log_content(content, filename):
    now = datetime.now()
    ip = get_real_ip()
    geo = get_geo_info(ip)
    user_agent = request.headers.get("User-Agent", "Unknown")
    referer = request.headers.get("Referer", "Unknown")
    method = request.method
    url = request.url

    extension = os.path.splitext(filename)[-1].lower()
    suspicious_filetype = extension in ['.php', '.html', '.js']

    suspicious = is_suspicious_content(content) or suspicious_filetype
    log_path = ATTACK_LOG if suspicious else GENERAL_LOG

    with open(log_path, 'a') as f:
        if suspicious:
            f.write(f"[⚠️ ATTACK DETECTED] [{now}]\n")
        else:
            f.write(f"[GENERAL NOTE SAVED] [{now}]\n")
        f.write(f"Filename: {filename}\n")
        f.write(f"Content Preview: {content[:100]}...\n")
        f.write("-" * 60 + "\n")
        f.write(f"[{now}] IP: {ip} | GEO: {geo} | METHOD: {method} | URL: {url} | UA: {user_agent} | REFERER: {referer}\n")
        f.write("=" * 60 + "\n\n")
