import re
import logging
from flask import request
import requests
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import ipaddress

# ========== CONFIGURATION ========== #
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
ALERT_EMAIL = "your_email@example.com"
EMAIL_PASSWORD = "your_email_password"
TO_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# ========== LOGGER SETUP ========== #
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# ========== TRUSTED PROXIES ========== #
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# ========== UTILITY FUNCTIONS ========== #
def is_ip_in_trusted_proxy(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except Exception:
        return False
    return False

def get_real_ip():
    if "X-Forwarded-For" in request.headers:
        forwarded_for = request.headers.get("X-Forwarded-For")
        ip = forwarded_for.split(",")[0].strip()
        if is_ip_in_trusted_proxy(request.remote_addr):
            return ip
        else:
            return f"Invalid Proxy IP: {request.remote_addr}"
    return request.remote_addr or "Unknown"

def get_geo_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "GeoLookup Failed"

def send_discord_alert(message):
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
    except Exception:
        pass

def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = ALERT_EMAIL
        msg["To"] = TO_EMAIL
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ALERT_EMAIL, EMAIL_PASSWORD)
        server.sendmail(ALERT_EMAIL, TO_EMAIL, msg.as_string())
        server.quit()
    except Exception:
        pass

# ========== MAIN DETECTION FUNCTION ========== #
def detect_malicious_upload(filename, content_type, user_info):
    ip = get_real_ip()
    geo = get_geo_location(ip)
    alerts = []

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

    if alerts:
        issues = ', '.join(alerts)
        log_msg = (
            f"[⚠️ File Upload Detection] IP: {ip} | Geo: {geo} | "
            f"User: {user_info.get('name')} | Email: {user_info.get('email')} | "
            f"Filename: {filename} | Type: {content_type} | Issues: {issues}"
        )
        attack_logger.warning(log_msg)
        send_discord_alert(log_msg)
        send_email_alert("🚨 File Upload Attack Detected", log_msg)
        return True

    return False
