import re
import logging
import os
import requests
import smtplib
import ipaddress
from flask import request
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

# ----------------- Email & Discord alert settings -----------------
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "okihsbwykagksikr")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367935673419694290/ZsrM2jsXscoda4GrJoPNYRNScJkW8tfa_FmlW5lfEp86VR4n_-AoDtbsRNizvaerRDvN")

# ----------------- Trusted Proxies -----------------
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

# ----------------- Logging -----------------
LOG_DIR = os.path.join(os.path.dirname(__file__), "../logs")
ATTACK_LOG = os.path.join(LOG_DIR, "attacks.log")
GENERAL_LOG = os.path.join(LOG_DIR, "general.log")
os.makedirs(LOG_DIR, exist_ok=True)

attack_logger = logging.getLogger("shellcode_attack_logger")
attack_logger.setLevel(logging.INFO)
if not attack_logger.hasHandlers():
    handler = logging.FileHandler(ATTACK_LOG)
    handler.setFormatter(logging.Formatter('%(asctime)s - Shellcode Alert - %(message)s'))
    attack_logger.addHandler(handler)

general_logger = logging.getLogger("shellcode_general_logger")
general_logger.setLevel(logging.INFO)
if not general_logger.hasHandlers():
    handler = logging.FileHandler(GENERAL_LOG)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    general_logger.addHandler(handler)

# ----------------- Utility: Geolocation -----------------
def basic_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if res.status_code == 200:
            data = res.json()
            return f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}"
    except:
        pass
    return "Unknown"

# ----------------- Utility: Real IP extraction -----------------
def get_real_ip():
    route = request.access_route + [request.remote_addr]
    for addr in route:
        try:
            ip_obj = ipaddress.ip_address(addr)
            if not any(ip_obj in ipaddress.ip_network(proxy) for proxy in TRUSTED_PROXIES):
                return addr
        except ValueError:
            continue
    return request.remote_addr

# ----------------- Utility: Email Alert -----------------
def send_email_alert(subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECEIVER_EMAILS)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
    except Exception as e:
        general_logger.error(f"Failed to send email alert: {e}")

# ----------------- Utility: Discord Alert -----------------
def send_discord_alert(message):
    try:
        data = {"content": f"🚨 **Shellcode Detected!**\n{message}"}
        headers = {"Content-Type": "application/json"}
        requests.post(DISCORD_WEBHOOK_URL, headers=headers, data=json.dumps(data), timeout=5)
    except Exception as e:
        general_logger.error(f"Failed to send Discord alert: {e}")

# ----------------- Suspicious Patterns -----------------
SUSPICIOUS_PATTERNS = [
    r"\s*;\s*", r"\|\|", r"\|\s*", r"&", r"\$\(.*\)", r"`.*`",
    r"\.py$", r"\.php$", r"\.sh$", r"\.pl$", r"\.rb$", r"\.exe$", r"\.bat$",
    r"eval\(", r"exec\(",
    r"import\s+os", r"import\s+sys", r"import\s+subprocess",
    r"os\.system", r"subprocess\.Popen",
    r"bash\s+-i", r"nc\s+-e", r"ncat\s+-e", r"perl\s+-e", r"python\s+-c",
    r"curl\s+", r"wget\s+", r"http[s]?://",
    r"base64\s+-d", r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d",
    r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*bash",
    r"/etc/passwd", r"id\s*;", r"whoami\s*;", r"uname\s*-a",
    r"sudo\s+", r"su\s+", r"chmod\s+777", r"chown\s+.*root",
    r"reverse shell", r"shellcode", r"payload", r"bind shell",
    r"backdoor", r"malware", r"exploit", r"privilege escalation"
]

# ----------------- Main Detection -----------------
def detect_shellcode(command: str, user_info=None) -> bool:
    if not user_info:
        user_info = {}

    name = user_info.get("name", "Unknown")
    email = user_info.get("email", "Unknown")
    ip = user_info.get("ip") or get_real_ip()
    geo = user_info.get("geolocation") or basic_geolocation(ip)

    general_logger.info(f"User: {name} | IP: {ip} | Command: {command}")

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            alert_msg = (
                f"Name: {name}\nEmail: {email}\nIP: {ip}\nGeolocation: {geo}\n"
                f"Suspicious Command: {command}\nHeaders: {dict(request.headers)}\n"
                f"User-Agent: {request.headers.get('User-Agent')}\nReferrer: {request.referrer}"
            )

            attack_logger.info(alert_msg)
            send_email_alert("🚨 Shellcode Detected", alert_msg)
            send_discord_alert(alert_msg)
            return True

    return False
