import re
import os
import logging
import requests
import smtplib
from flask import request
from datetime import datetime
from threading import Thread
from email.mime.text import MIMEText

# ============================
# Email & Discord alert settings
# ============================
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "okihsbwykagksikr")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL")

# ============================
# Logging setup
# ============================
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# ============================
# Trusted proxies like Cloudflare
# ============================
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

# ============================
# Utility functions
# ============================
def get_real_ip():
    if "X-Forwarded-For" in request.headers:
        forwarded_for = request.headers.get("X-Forwarded-For")
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.remote_addr or "Unknown"
    return ip

def get_geo_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "GeoLookup Failed"

def send_discord_alert(message):
    def _send():
        try:
            requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
        except Exception:
            pass
    Thread(target=_send).start()

def send_email_alert(subject, message):
    def _send():
        try:
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = SENDER_EMAIL
            msg["To"] = ", ".join(RECEIVER_EMAILS)

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(SENDER_EMAIL, EMAIL_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        except Exception:
            pass
    Thread(target=_send).start()

# ============================
# Malicious Upload Detection
# ============================
def detect_malicious_upload(filename, content_type, user_info):
    ip = get_real_ip()
    geo = get_geo_location(ip)
    alerts = []

    # Checks for bad patterns
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
        alert_msg = (
            f"[⚠️ File Upload Detection]\n"
            f"IP: {ip} | Geo: {geo}\n"
            f"User: {user_info.get('name')} | Email: {user_info.get('email')}\n"
            f"Filename: {filename} | MIME Type: {content_type}\n"
            f"Issues: {', '.join(alerts)}"
        )

        # Log to file
        attack_logger.warning(alert_msg)

        # Notify via Discord and Email
        send_discord_alert(alert_msg)
        send_email_alert("🚨 Suspicious File Upload Detected", alert_msg)

        return True  # Threat detected
    return False  # No issues found
