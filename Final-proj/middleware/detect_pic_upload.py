import re
import os
import requests
from datetime import datetime
from flask import request

ATTACK_LOG = 'logs/attacks.log'
GENERAL_LOG = 'logs/general.log'

# Suspicious patterns to catch attacks
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
    # Preferred order of IP headers (most to least accurate)
    for header in ['CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP']:
        ip = request.headers.get(header)
        if ip:
            return ip.split(',')[0].strip()
    return request.remote_addr or "Unknown"

def get_geo_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "GeoLookup Failed"

def log_content(content, filename):
    now = datetime.now()
    ip = get_real_ip()
    geo = get_geo_location(ip)
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
        f.write(f"[{now}] IP: {ip} | GEO: {geo} | METHOD: {method} | URL: {url}\n")
        f.write(f"UA: {user_agent} | REFERER: {referer}\n")
        f.write("=" * 60 + "\n\n")
