import re
import datetime

# List of patterns commonly used in SSRF attacks
SSRF_PATTERNS = [
    r"http[s]?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d{1,3}\.\d{1,3})",  # loopbacks
    r"http[s]?://(?:internal|metadata|169\.254\.169\.254)",  # cloud metadata endpoints
    r"http[s]?://(?:.*):\d{1,5}",  # port access
    r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}",  # direct IP access
    r"http[s]?://(?:[a-zA-Z0-9\-_]+\.)*internal(?:\..*)?",  # subdomains like `internal.example.com`
]

def detect_ssrf(*inputs, ip=None):
    """
    Scans input parameters for signs of SSRF payloads.
    
    Args:
        *inputs (str): Any number of input strings to check.
        ip (str): IP address of the client (for logging purposes).
    
    Returns:
        bool: True if SSRF is detected, else False.
    """
    for value in inputs:
        if isinstance(value, str):
            for pattern in SSRF_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    log_ssrf_attempt(value, ip)
                    return True
    return False

def log_ssrf_attempt(payload, ip):
    """
    Logs details of the SSRF attack attempt.
    
    Args:
        payload (str): The suspicious input.
        ip (str): IP address of the attacker.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("attacks.log", "a") as log:
        log.write(
            f"[{timestamp}] SSRF Detected | IP: {ip} | Payload: {payload}\n"
        )
