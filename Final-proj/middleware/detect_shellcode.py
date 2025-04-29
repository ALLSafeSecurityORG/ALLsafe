import re
import logging
import os
import requests
from datetime import datetime

# Paths
LOG_DIR = os.path.join(os.path.dirname(__file__), "../logs")
ATTACK_LOG = os.path.join(LOG_DIR, "attacks.log")
GENERAL_LOG = os.path.join(LOG_DIR, "general.log")

os.makedirs(LOG_DIR, exist_ok=True)

# Attack Logger
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler(ATTACK_LOG)
attack_handler.setFormatter(logging.Formatter('%(asctime)s - Shellcode Alert - %(message)s'))
attack_logger.addHandler(attack_handler)

# General Logger
general_logger = logging.getLogger("general_logger")
general_logger.setLevel(logging.INFO)
general_handler = logging.FileHandler(GENERAL_LOG)
general_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
general_logger.addHandler(general_handler)

# 🌐 Basic Geolocation Lookup
def basic_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if res.status_code == 200:
            data = res.json()
            return f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}"
    except:
        pass
    return "Unknown"

# 🚩 Suspicious Pattern Matchers
SUSPICIOUS_PATTERNS = [
    # 🔁 Command chaining, pipelining, and substitution
    r"\s*;\s*", r"\|\|", r"\|\s*", r"&", r"\$\(.*\)", r"`.*`",

    # 💣 Dangerous file extensions
    r"\.py$", r"\.php$", r"\.sh$", r"\.pl$", r"\.rb$", r"\.exe$", r"\.bat$",

    # 🐍 Python-based execution or shell abuse
    r"eval\(", r"exec\(",
    r"import\s+os", r"import\s+sys", r"import\s+subprocess",
    r"os\.system", r"subprocess\.Popen",

    # 📡 Common remote payload tools
    r"bash\s+-i", r"nc\s+-e", r"ncat\s+-e", r"perl\s+-e", r"python\s+-c",
    r"curl\s+", r"wget\s+", r"http[s]?://",

    # 🧬 Base64 decoding and code injection
    r"base64\s+-d", r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d",
    r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*bash",

    # 🔓 Sensitive access attempts
    r"/etc/passwd", r"id\s*;", r"whoami\s*;", r"uname\s*-a",
    r"sudo\s+", r"su\s+", r"chmod\s+777", r"chown\s+.*root",

    # 🧨 Suspicious keywords
    r"reverse shell", r"shellcode", r"payload", r"bind shell",
    r"backdoor", r"malware", r"exploit", r"privilege escalation"
]

# 🧠 Main Detection Function
def detect_shellcode(command: str, user_info=None) -> bool:
    # Log to general log (This will still show in the general log file)
    general_logger.info(f"User: {user_info.get('name', 'Unknown')} | Command: {command}")

    # Detect suspicious command
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            name = user_info.get("name", "Unknown")
            email = user_info.get("email", "Unknown")
            ip = user_info.get("ip", "Unknown")
            geo = user_info.get("geolocation") or basic_geolocation(ip)

            # Log the suspicious activity in the attack log (No terminal print)
            alert_msg = (
                f"Name: {name} | Email: {email} | IP: {ip} | "
                f"Geolocation: {geo} | Suspicious Command: {command}"
            )
            attack_logger.info(alert_msg)
            
            # Do NOT print or alert in the terminal - Only log to files.
            return True

    return False
