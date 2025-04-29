import re
from datetime import datetime

def log_xss_attack(ip, field, value):
    log_message = (
        f"[{datetime.now()}] [XSS ATTEMPT DETECTED] "
        f"IP: {ip} | Field: {field} | Payload: {value}\n"
    )
    with open("logs/attacks.log", "a") as log:
        log.write(log_message)

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
                return True  # Found XSS payload

    return False
