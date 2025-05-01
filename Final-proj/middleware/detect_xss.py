import re
import requests
import logging
import os
from datetime import datetime
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============================
# Email & Discord alert settings
# ============================
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "okihsbwykagksikr")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL")

# ----------------- Attack Logger Setup -----------------
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
handler = logging.FileHandler("logs/attacks.log")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
attack_logger.addHandler(handler)

# ----------------- XSS Detection -----------------
def log_xss_attack(ip, field, value):
    log_message = (
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [XSS ATTEMPT DETECTED] "
        f"IP: {ip} | Field: {field} | Payload: {value}\n"
    )
    with open("logs/attacks.log", "a") as log:
        log.write(log_message)

# ----------------- Send Alerts -----------------
def send_alerts(ip, field, value):
    # Email Alert
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECEIVER_EMAILS)
        msg["Subject"] = "XSS Attack Detected"
        
        body = f"XSS attempt detected from IP: {ip}\nField: {field}\nPayload: {value}\n\nCheck your system for potential vulnerabilities."
        msg.attach(MIMEText(body, "plain"))
        
        with SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
    except Exception as e:
        print(f"Error sending email alert: {e}")

    # Discord Alert
    try:
        discord_data = {
            "content": f"XSS Attack Detected\nIP: {ip}\nField: {field}\nPayload: {value}\nCheck your system for vulnerabilities."
        }
        requests.post(DISCORD_WEBHOOK_URL, json=discord_data)
    except Exception as e:
        print(f"Error sending Discord alert: {e}")

# ----------------- XSS Detection Logic -----------------
def detect_xss(*args, ip="unknown"):
    # Expanded and more strict XSS patterns
    xss_patterns = [
        r"<script\b[^>]*>(.*?)</script>",                     # classic <script>
        r"(?i)<.*?on\w+\s*=\s*['\"].*?['\"]",                 # onerror, onclick etc.
        r"(?i)javascript\s*:",                                # javascript: pseudo protocol
        r"(?i)document\.(cookie|location|write|domain)",      # JS DOM access
        r"(?i)window\.(location|name|onload|onerror)",        # window object abuse
        r"(?i)<iframe\b.*?>.*?</iframe>",                     # iframe injection
        r"(?i)<img\b.*?src\s*=\s*['\"].*?['\"].*?>",          # malicious <img>
        r"(?i)<svg\b.*?>.*?</svg>",                           # SVG-based XSS
        r"(?i)src\s*=\s*['\"]data:text/html.*?['\"]",         # data URI abuse
        r"(?i)fetch\s*\(",                                    # JS fetch-based data exfiltration
        r"(?i)axios\s*\(",                                    # axios-based payload
        r"(?i)new\s+XMLHttpRequest",                          # manual exfil via XHR
        r"(?i)<body\b.*?onload\s*="                           # <body onload=...>
    ]

    for field, value in args:
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                log_xss_attack(ip, field, value)
                send_alerts(ip, field, value)
                return True  # Found XSS payload

    return False

