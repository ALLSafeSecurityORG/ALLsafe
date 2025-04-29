# middleware/detect_sql.py

import re
from datetime import datetime

def detect_sql_injection(email, password, ip):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # ' or -- or #
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",      # OR 1=1, AND 1=1
        r"(\bUNION\b.*\bSELECT\b)",         # UNION SELECT
        r"(\bSELECT\b.*\bFROM\b)",          # SELECT * FROM users
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",  # INSERT/UPDATE/DELETE
        r"(\bDROP\b\s+\bTABLE\b)"           # DROP TABLE
    ]

    combined = f"{email} {password}"
    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, ip, combined)
            return True
    return False

def log_attack(email, ip, payload):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] [SQL INJECTION DETECTED] IP: {ip} | Email: {email} | Payload: {payload}\n"
    with open("logs/attacks.log", "a") as f:
        f.write(log_message)
