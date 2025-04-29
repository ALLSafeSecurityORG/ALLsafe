import re
import requests
import ipaddress
from datetime import datetime
from flask import Flask, request

app = Flask(__name__)

# ----------------- Constants -----------------
ATTACK_LOG = "logs/attacks.log"
GENERAL_LOG = "logs/general.log"
GEO_API = "http://ip-api.com/json/"

# ----------------- Trusted Proxies (Cloudflare + Custom) -----------------
TRUSTED_PROXIES = [
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # Add your own proxy IPs if needed
]

# ----------------- Utility: Get Real IP -----------------
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

# ----------------- SSRF Detection -----------------
SSRF_PATTERNS = [
    r"http[s]?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d{1,3}\.\d{1,3})",  # loopbacks
    r"http[s]?://(?:internal|metadata|169\.254\.169\.254)",  # cloud metadata endpoints
    r"http[s]?://(?:.*):\d{1,5}",  # port access
    r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}",  # direct IP access
    r"http[s]?://(?:[a-zA-Z0-9\-_]+\.)*internal(?:\..*)?",  # subdomains like `internal.example.com`
]

def detect_ssrf(*inputs):
    """
    Scans input parameters for signs of SSRF payloads.
    """
    for value in inputs:
        if isinstance(value, str):
            for pattern in SSRF_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    log_ssrf_attempt(value)
                    return True
    return False

# ----------------- SSRF Attack Logger -----------------
def log_ssrf_attempt(payload):
    real_ip = get_real_ip()
    geo = get_geolocation(real_ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    attack_info = (
        f"[{timestamp}] SSRF DETECTED | REAL_IP: {real_ip} | GEO: {geo} | "
        f"Payload: {payload} | URL: {request.url} | "
        f"UA: {request.headers.get('User-Agent')} | "
        f"REFERER: {request.referrer}\n"
    )
    
    with open(ATTACK_LOG, "a") as f:
        f.write(attack_info)

# ----------------- General Logger -----------------
def log_general_activity():
    real_ip = get_real_ip()
    geo = get_geolocation(real_ip)

    data = (
        f"[{datetime.now()}] REAL_IP: {real_ip} | GEO: {geo} | "
        f"X-Real-IP: {request.headers.get('X-Real-IP')} | "
        f"X-Forwarded-For: {request.headers.get('X-Forwarded-For')} | "
        f"METHOD: {request.method} | URL: {request.url} | "
        f"UA: {request.headers.get('User-Agent')} | "
        f"REFERER: {request.referrer}\n"
    )
    
    with open(GENERAL_LOG, "a") as f:
        f.write(data)

# ----------------- Flask Route Example -----------------
@app.before_request
def before():
    log_general_activity()
    detect_ssrf(request.args.get("url"))

@app.route("/", methods=["GET", "POST"])
def index():
    return "Welcome to the SSRF-hardened zone."

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
