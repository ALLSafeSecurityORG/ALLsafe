import re
import os
import requests
from flask import request
from datetime import datetime
from urllib.parse import unquote, unquote_plus

ATTACK_LOG = "logs/attacks.log"
GENERAL_LOG = "logs/general.log"
GEO_API = "http://ip-api.com/json/"

# ----------------- Geolocation -----------------
def get_geolocation(ip):
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except:
        pass
    return "Geolocation not available"

# ----------------- General Logger -----------------
def log_general_activity():
    ip = request.remote_addr
    geo = get_geolocation(ip)
    data = f"[{datetime.now()}] IP: {ip} | GEO: {geo} | METHOD: {request.method} | URL: {request.url} | UA: {request.headers.get('User-Agent')} | REFERER: {request.referrer}\n"
    with open(GENERAL_LOG, "a") as f:
        f.write(data)

# ----------------- LFI Detection -----------------
def normalize_payload(value):
    """Decode multiple times (URL decoding, etc.)"""
    for _ in range(2):  # Double decode
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

    # ✅ 1. Check path itself
    raw_path = request.full_path or request.path
    decoded_path = normalize_payload(raw_path)

    for pattern in lfi_patterns:
        if re.search(pattern, decoded_path, re.IGNORECASE):
            ip = request.remote_addr
            geo = get_geolocation(ip)
            attack_info = (
                f"[{datetime.now()}] [LFI DETECTED - PATH] "
                f"IP: {ip} | GEO: {geo} | PATH: {decoded_path} "
                f"| URL: {request.url} | UA: {request.headers.get('User-Agent')} "
                f"| REFERER: {request.referrer}\n"
            )
            with open(ATTACK_LOG, "a") as f:
                f.write(attack_info)
            print(f"[!] LFI DETECTED in PATH: {decoded_path}")
            return

    # ✅ 2. Check parameters
    combined = request.args.to_dict()
    combined.update(request.form.to_dict())

    if request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if json_data:
                combined.update(json_data)
        except:
            pass

    for key, value in combined.items():
        normalized_value = normalize_payload(str(value))
        for pattern in lfi_patterns:
            if re.search(pattern, normalized_value, re.IGNORECASE):
                ip = request.remote_addr
                geo = get_geolocation(ip)
                attack_info = (
                    f"[{datetime.now()}] [LFI DETECTED - PARAM] "
                    f"IP: {ip} | GEO: {geo} | PARAM: {key}={normalized_value} "
                    f"| URL: {request.url} | UA: {request.headers.get('User-Agent')} "
                    f"| REFERER: {request.referrer}\n"
                )
                with open(ATTACK_LOG, "a") as f:
                    f.write(attack_info)
                print(f"[!] LFI DETECTED in PARAM: {key}={normalized_value}")
                return
