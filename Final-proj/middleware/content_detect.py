# notepad content
import re
import os
from datetime import datetime
from flask import request

ATTACK_LOG = 'logs/attacks.log'
GENERAL_LOG = 'logs/general.log'

# Patterns to detect common attack content (basic XSS for now)
suspicious_patterns = [
    r"<script.*?>.*?</script>",     # <script> tags
    r"on\w+\s*=",                   # Event handlers like onerror=
    r"javascript:",                # javascript: URLs
    r"<iframe.*?>",                # iframe injections
    r"<img\s+.*?onerror\s*=.*?>",  # image tag with onerror
]

def is_suspicious_content(content):
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False

def log_content(content, filename):
    now = datetime.now()
    ip = request.remote_addr or "Unknown"
    user_agent = request.headers.get("User-Agent", "Unknown")
    referer = request.headers.get("Referer", "Unknown")
    method = request.method
    url = request.url

    extension = os.path.splitext(filename)[-1].lower()
    suspicious_filetype = extension in ['.php', '.html', '.js']

    suspicious = is_suspicious_content(content) or suspicious_filetype

    log_path = ATTACK_LOG if suspicious else GENERAL_LOG

    # Create log entry
    with open(log_path, 'a') as f:
        if suspicious:
            f.write(f"[⚠️ ATTACK DETECTED] [{now}]\n")
        else:
            f.write(f"[GENERAL NOTE SAVED] [{now}]\n")
        f.write(f"Filename: {filename}\n")
        f.write(f"Content Preview: {content[:100]}...\n")
        f.write("-" * 60 + "\n")
        f.write(f"[{now}] IP: {ip} | GEO: Geolocation not available | METHOD: {method} | URL: {url} | UA: {user_agent} | REFERER: {referer}\n")
        f.write("=" * 60 + "\n\n")
