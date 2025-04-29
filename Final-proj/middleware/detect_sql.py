# middleware/detect_sql.py

import re
from datetime import datetime

def detect_sql_injection(email, password, ip):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bSLEEP\s*\(\s*\d+\s*\))",
        r"(\bWAITFOR\s+DELAY\b)",
        r"(\bEXEC(\s+|UTE)\b)",
        r"(\bINFORMATION_SCHEMA\b)",
        r"(\bCAST\s*\()",
        r"(\bCONVERT\s*\()",
        r"(\bHAVING\b\s+\d+=\d+)",
        r"(\bLIKE\s+['\"]?%\w+%['\"]?)",
        r"(\bBENCHMARK\s*\(\s*\d+\,)",
        r"(\bOUTFILE\b|\bDUMPFILE\b|\bINTO\b\s+\bFILE\b)",
        r"(\bLOAD_FILE\s*\()",
        r"(\bGROUP\s+BY\b\s+[\w\W]*\()",
        r"(\bXPATH\b\s*\()",
        r"(\bCHAR\s*\(\d+\))"
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
