import re
import requests
from flask import request
from datetime import datetime
from urllib.parse import unquote, unquote_plus

ATTACK_LOG = "logs/attacks.log"
GENERAL_LOG = "logs/general.log"
GEO_API = "http://ip-api.com/json/"

# Optional: List of trusted proxies (e.g., Pella, Cloudflare IPs)
TRUSTED_PROXIES = ["159.69.217.205"]  # Add more if needed

# ----------------- Utility: Get Real IP -----------------
def get_real_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    x_real_ip = request.headers.get("X-Real-IP")
    remote_ip = request.remote_addr

    # Trust X-Forwarded-For only if request came through trusted proxy
    if remote_ip in TRUSTED_PROXIES and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    else:
        return remote_ip

# ----------------- Geolocation -----------------
def get_geolocation(ip):
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

# ----------------- General Logger -----------------
def log_general_activity():
    ip = get_real_ip()
    geo = get_geolocation(ip)

    x_real_ip = request.headers.get("X-Real-IP")
    x_forwarded_for = request.headers.get("X-Forwarded-For")

    data = (
        f"[{datetime.now()}] IP: {ip} | GEO: {geo} | "
        f"X-Real-IP: {x_real_ip} | X-Forwarded-For: {x_forwarded_for} | "
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
        r"(\.\./)+",
        r"etc/passwd",
        r"boot\.ini",
        r"win\.ini",
        r"proc/self/environ",
        r"input_wrapper",
        r"data://", r"php://", r"expect://",
        r"log/(apache|nginx|access|error)",
        r"(\%2e){2,}",
        r"(\%252e)+",
        r"(?i)(\.\./)+.*(passwd|boot|win|log)",
    ]

    # 1. Check path
    raw_path = request.full_path or request.path
    decoded_path = normalize_payload(raw_path)
    for pattern in lfi_patterns:
        if re.search(pattern, decoded_path, re.IGNORECASE):
            log_attack("PATH", decoded_path)
            print(f"[!] LFI DETECTED in PATH: {decoded_path}")
            return

    # 2. Check parameters
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
    ip = get_real_ip()
    geo = get_geolocation(ip)
    attack_info = (
        f"[{datetime.now()}] [LFI DETECTED - {source}] "
        f"IP: {ip} | GEO: {geo} | {source}: {data_value} "
        f"| URL: {request.url} | UA: {request.headers.get('User-Agent')} "
        f"| REFERER: {request.referrer}\n"
    )
    with open(ATTACK_LOG, "a") as f:
        f.write(attack_info)
