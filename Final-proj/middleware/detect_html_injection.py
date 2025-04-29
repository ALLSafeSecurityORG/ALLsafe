import re
import logging

# Attack logger
attack_logger = logging.getLogger("html_injection_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# Suspicious patterns
SUSPICIOUS_HTML_TAGS = re.compile(r"<\s*(script|iframe|object|embed|form|img|svg|style|link)[^>]*>", re.IGNORECASE)
SUSPICIOUS_XSS = re.compile(r"(on\w+\s*=|javascript:|alert\s*\(|document\.cookie|<\s*script[^>]*>)", re.IGNORECASE)
SUSPICIOUS_PHP = re.compile(r"<\?php|<\?=|\?>", re.IGNORECASE)

# Check for binary file
def is_binary_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk:  # null byte => likely binary
                return True
        return False
    except Exception:
        return True  # If error reading, assume binary for safety

def detect_html_injection(file_path):
    if is_binary_file(file_path):
        return False  # Skip scan for binary files

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        alerts = []

        if SUSPICIOUS_HTML_TAGS.search(content):
            alerts.append("HTML tag detected")
        if SUSPICIOUS_XSS.search(content):
            alerts.append("Potential XSS pattern detected")
        if SUSPICIOUS_PHP.search(content):
            alerts.append("PHP code detected")

        if alerts:
            msg = f"Injection Detected in {file_path} | Issues: {', '.join(alerts)}"
            attack_logger.warning(msg)
            print(f"[!] {msg}")
            return True

        return False

    except Exception as e:
        attack_logger.error(f"Error analyzing {file_path}: {e}")
        return False
