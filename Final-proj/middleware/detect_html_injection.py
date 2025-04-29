import re
import logging
import ipaddress
import requests
from flask import request

# ========== LOGGER SETUP ========== #
attack_logger = logging.getLogger("html_injection_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

# Prevent duplicate handler attachment
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# ========== CLOUDFLARE RANGES ========== #
CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/13", "131.0.72.0/22", "104.24.0.0/14"
]

# ========== PATTERN DEFINITIONS ========== #
SUSPICIOUS_HTML_TAGS = re.compile(r"<\s*(script|iframe|object|embed|form|img|svg|style|link)[^>]*>", re.IGNORECASE)
SUSPICIOUS_XSS = re.compile(r"(on\w+\s*=|javascript:|alert\s*\(|document\.cookie|<\s*script[^>]*>)", re.IGNORECASE)
SUSPICIOUS_PHP = re.compile(r"<\?php|<\?=|\?>", re.IGNORECASE)

# ========== GEOLOCATION API ========== #
GEO_API = "http://ip-api.com/json/"

# ========== UTIL FUNCTIONS ========== #
def is_binary_file(file_path):
    """Check if a file is binary by scanning for null bytes."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk:
                return True
        return False
    except Exception:
        return True  # Be paranoid — treat as binary if unreadable

def is_ip_in_cloudflare_range(ip):
    """Check if IP is in known Cloudflare proxy ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except Exception:
        return False
    return False

def get_real_ip():
    """Extract real client IP even if behind Cloudflare proxy."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    remote_ip = request.remote_addr or "Unknown"

    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
        if is_ip_in_cloudflare_range(remote_ip):  # Check proxy IP is valid
            return ip
        else:
            return f"Invalid Proxy IP: {remote_ip}"
    else:
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

# ========== CORE FUNCTION ========== #
def detect_html_injection(file_path):
    """Main detection logic."""
    ip = get_real_ip()
    location = get_geolocation(ip)
    print(f"[*] Real IP: {ip} | Location: {location}")

    if is_binary_file(file_path):
        attack_logger.info(f"Skipped binary file scan: {file_path} | IP: {ip} | Location: {location}")
        return False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        alerts = []

        if SUSPICIOUS_HTML_TAGS.search(content):
            alerts.append("HTML tag detected")
        if SUSPICIOUS_XSS.search(content):
            alerts.append("Potential XSS pattern detected")
        if SUSPICIOUS_PHP.search(content):
            alerts.append("PHP code detected")

        if alerts:
            alert_summary = ', '.join(alerts)
            msg = f"[Injection Alert] File: {file_path} | Issues: {alert_summary} | IP: {ip} | Location: {location}"
            attack_logger.warning(msg)
            print(f"[!] {msg}")
            return True

        attack_logger.info(f"Clean Scan: {file_path} | IP: {ip} | Location: {location}")
        return False

    except Exception as e:
        attack_logger.error(f"[Error] Analyzing {file_path} failed: {e} | IP: {ip} | Location: {location}")
        return False
