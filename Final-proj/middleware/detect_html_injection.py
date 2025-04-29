import re
import logging
from flask import request
import requests
import ipaddress

# Attack logger setup
attack_logger = logging.getLogger("html_injection_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# Cloudflare IP Ranges (Sample)
CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/13", "131.0.72.0/22", "104.24.0.0/14"
]

# Suspicious patterns for HTML injection
SUSPICIOUS_HTML_TAGS = re.compile(r"<\s*(script|iframe|object|embed|form|img|svg|style|link)[^>]*>", re.IGNORECASE)
SUSPICIOUS_XSS = re.compile(r"(on\w+\s*=|javascript:|alert\s*\(|document\.cookie|<\s*script[^>]*>)", re.IGNORECASE)
SUSPICIOUS_PHP = re.compile(r"<\?php|<\?=|\?>", re.IGNORECASE)

# Check if a file is binary
def is_binary_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk:  # null byte => likely binary
                return True
        return False
    except Exception:
        return True  # If error reading, assume binary for safety

def get_real_ip():
    """Extract the real client IP considering proxy headers, and verify Cloudflare IP ranges."""
    # If the request is behind a proxy, the X-Forwarded-For header will contain the real IP
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()  # Get the first IP in the chain
        # Check if the IP is within Cloudflare's known IP ranges
        if is_ip_in_cloudflare_range(ip):
            return ip
        else:
            return "Invalid Proxy IP"
    else:
        return request.remote_addr or "Unknown"

def is_ip_in_cloudflare_range(ip):
    """Check if the provided IP is within Cloudflare's known IP ranges."""
    ip_obj = ipaddress.ip_address(ip)
    for cloudflare_range in CLOUDFLARE_IP_RANGES:
        if ip_obj in ipaddress.ip_network(cloudflare_range):
            return True
    return False

def detect_html_injection(file_path):
    # Get the real IP of the client
    ip = get_real_ip()
    print(f"Real IP: {ip}")  # Optionally log the real IP for debugging purposes

    if is_binary_file(file_path):
        return False  # Skip scan for binary files

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        alerts = []

        # Check for suspicious HTML tags
        if SUSPICIOUS_HTML_TAGS.search(content):
            alerts.append("HTML tag detected")
        # Check for potential XSS patterns
        if SUSPICIOUS_XSS.search(content):
            alerts.append("Potential XSS pattern detected")
        # Check for PHP code injections
        if SUSPICIOUS_PHP.search(content):
            alerts.append("PHP code detected")

        # If suspicious patterns are found, log and return True
        if alerts:
            msg = f"Injection Detected in {file_path} | Issues: {', '.join(alerts)} | IP: {ip}"
            attack_logger.warning(msg)
            print(f"[!] {msg}")
            return True

        return False

    except Exception as e:
        attack_logger.error(f"Error analyzing {file_path}: {e}")
        return False
