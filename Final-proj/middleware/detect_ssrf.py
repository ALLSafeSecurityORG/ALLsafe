import re
import requests
import ipaddress
import logging
import os
from datetime import datetime
from flask import Flask, request
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests as req

app = Flask(__name__)

# ============================
# Email & Discord alert settings
# ============================
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "okihsbwykagksikr")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367935673419694290/ZsrM2jsXscoda4GrJoPNYRNScJkW8tfa_FmlW5lfEp86VR4n_-AoDtbsRNizvaerRDvN")

# ----------------- Attack Logger Setup -----------------
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
handler = logging.FileHandler("logs/attacks.log")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
attack_logger.addHandler(handler)

# ----------------- Trusted Proxies (Cloudflare + Custom) -----------------
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# ----------------- IP Utilities -----------------
def is_trusted_proxy(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        return False
    return False

def get_real_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    x_real_ip = request.headers.get("X-Real-IP")
    remote_ip = request.remote_addr

    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    else:
        return remote_ip

# ----------------- Geolocation -----------------
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

# ----------------- SSRF Detection -----------------
SSRF_PATTERNS = [
    r"http[s]?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d{1,3}\.\d{1,3})",
    r"http[s]?://(?:internal|metadata|169\.254\.169\.254)",
    r"http[s]?://(?:.*):\d{1,5}",
    r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}",
    r"http[s]?://(?:[a-zA-Z0-9\-_]+\.)*internal(?:\..*)?",
]

def detect_ssrf(*inputs):
    for value in inputs:
        if isinstance(value, str):
            for pattern in SSRF_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    log_ssrf_attack(value)
                    send_alerts(value)
                    return True
    return False

# ----------------- Attack Logger -----------------
def log_ssrf_attack(payload):
    real_ip = get_real_ip()
    geo = get_geolocation(real_ip)
    log_entry = (
        f"[⚠️ SSRF Detected]\n"
        f"REAL_IP: {real_ip} | PROXY_IP: {request.remote_addr} | GEO: {geo}\n"
        f"X-Real-IP: {request.headers.get('X-Real-IP')} | "
        f"X-Forwarded-For: {request.headers.get('X-Forwarded-For')}\n"
        f"Payload: {payload}\n"
        f"Method: {request.method} | URL: {request.url}\n"
        f"User-Agent: {request.headers.get('User-Agent')} | Referer: {request.referrer}\n"
        f"{'-'*80}\n"
    )
    attack_logger.warning(log_entry)

# ----------------- Send Alerts -----------------
def send_alerts(payload):
    # Email Alert
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECEIVER_EMAILS)
        msg["Subject"] = "SSRF Attack Detected"
        
        body = f"SSRF attempt detected with payload:\n{payload}\n\nCheck your system for potential vulnerabilities."
        msg.attach(MIMEText(body, "plain"))
        
        with SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
    except Exception as e:
        print(f"Error sending email alert: {e}")

    # Discord Alert
    try:
        discord_data = {
            "content": f"SSRF Attack Detected\nPayload: {payload}\nCheck your system for vulnerabilities."
        }
        req.post(DISCORD_WEBHOOK_URL, json=discord_data)
    except Exception as e:
        print(f"Error sending Discord alert: {e}")

# ----------------- Flask Route Example -----------------
@app.before_request
def before():
    detect_ssrf(request.args.get("url"))

@app.route("/", methods=["GET", "POST"])
def index():
    return "Welcome to the SSRF-hardened zone."

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
