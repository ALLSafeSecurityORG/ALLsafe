import re
import os
import requests
import logging
import ipaddress
from datetime import datetime
from flask import request
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

ATTACK_LOG = "logs/attacks.log"
GENERAL_LOG = "logs/general.log"
GEO_API = "http://ip-api.com/json/"

# Email and Discord
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "okihsbwykagksikr")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL")

# Trusted proxies
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

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

    log_data = (
        f"[{datetime.now()}] REAL_IP: {real_ip} | PROXY_IP: {proxy_ip} | GEO: {geo} | "
        f"X-Real-IP: {request.headers.get('X-Real-IP')} | "
        f"X-Forwarded-For: {request.headers.get('X-Forwarded-For')} | "
        f"METHOD: {request.method} | URL: {request.url} | "
        f"UA: {request.headers.get('User-Agent')} | REFERER: {request.referrer}\n"
    )
    with open(GENERAL_LOG, "a") as f:
        f.write(log_data)

def log_xss_attack(field, value):
    now = datetime.now()
    real_ip = get_real_ip()
    proxy_ip = request.remote_addr
    geo = get_geolocation(real_ip)
    ua = request.headers.get("User-Agent", "N/A")
    ref = request.referrer or "None"
    url = request.url

    headers = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    log_entry = (
        f"[{now}] [⚠️ XSS ATTACK DETECTED]\n"
        f"REAL_IP     : {real_ip}\n"
        f"PROXY_IP    : {proxy_ip}\n"
        f"GEOLOCATION : {geo}\n"
        f"X-Real-IP   : {request.headers.get('X-Real-IP')}\n"
        f"X-Forwarded : {request.headers.get('X-Forwarded-For')}\n"
        f"METHOD      : {request.method}\n"
        f"URL         : {url}\n"
        f"REFERRER    : {ref}\n"
        f"USER-AGENT  : {ua}\n"
        f"FIELD       : {field}\n"
        f"PAYLOAD     : {value}\n"
        f"HEADERS     : \n{headers}\n"
        f"------------------------------------------------------------\n\n"
    )

    with open(ATTACK_LOG, "a") as log:
        log.write(log_entry)

    send_email_alert(now, real_ip, geo, field, value, url, ua, ref)
    send_discord_alert(now, real_ip, geo, field, value, url)


def send_email_alert(time, ip, geo, field, payload, url, ua, ref):
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECEIVER_EMAILS)
        msg["Subject"] = "⚠️ XSS Attack Detected"

        body = (
            f"⚠️ **XSS Detected**\n\n"
            f"Time: {time}\n"
            f"IP: {ip}\n"
            f"Geo: {geo}\n"
            f"Field: {field}\n"
            f"Payload: {payload}\n"
            f"URL: {url}\n"
            f"User-Agent: {ua}\n"
            f"Referer: {ref}"
        )
        msg.attach(MIMEText(body, "plain"))

        with SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
    except Exception as e:
        print(f"[!] Email alert error: {e}")

def send_discord_alert(time, ip, geo, field, payload, url):
    try:
        message = (
            f"🚨 **XSS Attack Detected**\n"
            f"**Time:** {time}\n"
            f"**IP:** {ip}\n"
            f"**Geo:** {geo}\n"
            f"**Field:** `{field}`\n"
            f"**Payload:** `{payload}`\n"
            f"**URL:** {url}"
        )
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        if response.status_code != 204:
            print(f"[!] Discord webhook error: {response.status_code}")
    except Exception as e:
        print(f"[!] Discord webhook error: {e}")

def detect_xss(*args):
    log_general_activity()

    xss_patterns = [
        r"<script\b[^>]*>(.*?)</script>",
        r"(?i)<.*?on\w+\s*=\s*['\"].*?['\"]",
        r"(?i)javascript\s*:",
        r"(?i)document\.(cookie|location|write|domain)",
        r"(?i)window\.(location|name|onload|onerror)",
        r"(?i)<iframe\b.*?>.*?</iframe>",
        r"(?i)<img\b.*?src\s*=\s*['\"].*?['\"].*?>",
        r"(?i)<svg\b.*?>.*?</svg>",
        r"(?i)src\s*=\s*['\"]data:text/html.*?['\"]",
        r"(?i)fetch\s*\(",
        r"(?i)axios\s*\(",
        r"(?i)new\s+XMLHttpRequest",
        r"(?i)<body\b.*?onload\s*="
    ]

    for field, value in args:
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                log_xss_attack(field, value)
                return True
    return False
