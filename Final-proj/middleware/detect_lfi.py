import re
import requests
import ipaddress
import os
import smtplib
from flask import Flask, request
from datetime import datetime
from urllib.parse import unquote, unquote_plus
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

ATTACK_LOG = "logs/attacks.log"
GENERAL_LOG = "logs/general.log"
GEO_API = "http://ip-api.com/json/"

# Email & Discord alert settings
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "SuperSecure@123")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/123/abc")

# ----------------- Trusted Proxies -----------------
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECEIVER_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[!] Email alert error: {e}")

def send_discord_notification(message):
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[!] Discord webhook error: {e}")

# ----------------- Utility -----------------
def get_real_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    x_real_ip = request.headers.get("X-Real-IP")
    remote_ip = request.remote_addr

    def is_trusted_proxy(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in TRUSTED_PROXIES:
                if ip_obj in ipaddress.ip_network(net):
                    return True
        except ValueError:
            return False
        return False

    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    else:
        return remote_ip

def get_geolocation(ip):
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

def log_general_activity():
    real_ip = get_real_ip()
    proxy_ip = request.remote_addr
    geo = get_geolocation(real_ip)

    data = (
        f"[{datetime.now()}] REAL_IP: {real_ip} | PROXY_IP: {proxy_ip} | GEO: {geo} | "
        f"X-Real-IP: {request.headers.get('X-Real-IP')} | "
        f"X-Forwarded-For: {request.headers.get('X-Forwarded-For')} | "
        f"METHOD: {request.method} | URL: {request.url} | "
        f"UA: {request.headers.get('User-Agent')} | "
        f"REFERER: {request.referrer}\n"
    )
    with open(GENERAL_LOG, "a") as f:
        f.write(data)

# ----------------- LFI Detection -----------------
def normalize_payload(value):
    for _ in range(2):
        value = unquote_plus(unquote(value))
    return value

def detect_lfi():
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return

    log_general_activity()

    lfi_patterns = [
        r"(\.\./)+", r"etc/passwd", r"boot\.ini", r"win\.ini", r"proc/self/environ",
        r"input_wrapper", r"data://", r"php://", r"expect://",
        r"log/(apache|nginx|access|error)", r"(\%2e){2,}", r"(\%252e)+",
        r"(?i)(\.\./)+.*(passwd|boot|win|log)"
    ]

    # Check path
    raw_path = request.full_path or request.path
    decoded_path = normalize_payload(raw_path)
    for pattern in lfi_patterns:
        if re.search(pattern, decoded_path, re.IGNORECASE):
            log_attack("PATH", decoded_path)
            print(f"[!] LFI DETECTED in PATH: {decoded_path}")
            return

    # Check parameters
    combined = request.args.to_dict()
    combined.update(request.form.to_dict())

    if request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if json_data:
                combined.update(json_data)
        except Exception:
            pass

    for key, value in combined.items():
        normalized_value = normalize_payload(str(value))
        for pattern in lfi_patterns:
            if re.search(pattern, normalized_value, re.IGNORECASE):
                log_attack("PARAM", f"{key}={normalized_value}")
                print(f"[!] LFI DETECTED in PARAM: {key}={normalized_value}")
                return

# ----------------- Attack Logger -----------------
def log_attack(source, data_value):
    now = datetime.now()
    real_ip = get_real_ip()
    proxy_ip = request.remote_addr
    geo = get_geolocation(real_ip)
    method = request.method
    ua = request.headers.get("User-Agent")
    ref = request.referrer or "None"
    url = request.url

    attack_info = (
        f"[{now}] [LFI DETECTED - {source}] "
        f"REAL_IP: {real_ip} | PROXY_IP: {proxy_ip} | GEO: {geo} | "
        f"{source}: {data_value} | URL: {url} | "
        f"UA: {ua} | REFERER: {ref}\n"
    )

    with open(ATTACK_LOG, "a") as f:
        f.write(attack_info)

    # 🔔 Send alerts
    subject = "[Locater Alert] LFI Attack Detected"
    message = (
        f"⚠️ **LFI DETECTED** ({source})\n"
        f"Time: {now}\n"
        f"IP: {real_ip}\n"
        f"GEO: {geo}\n"
        f"{source}: {data_value}\n"
        f"Method: {method}\n"
        f"URL: {url}\n"
        f"User-Agent: {ua}\n"
        f"Referer: {ref}"
    )
    
    send_discord_notification(message)
    send_email(subject, message)

# ----------------- Flask Hooks & Routes -----------------
@app.before_request
def before():
    detect_lfi()

@app.route("/", methods=["GET", "POST"])
def index():
    return "Welcome to the LFI-hardened zone."

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

