import re
import os
from datetime import datetime
from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Define trusted proxies (Cloudflare ranges)
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", 
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# Apply ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_port=1, x_proto=1)

# Patterns to detect common attack content (basic XSS and more)
suspicious_patterns = [
    r"<script.*?>.*?</script>",        # <script> tags
    r"on\w+\s*=",                      # Event handlers like onerror=
    r"javascript:",                   # javascript: URLs
    r"<iframe.*?>",                   # iframe injections
    r"<img\s+.*?onerror\s*=.*?>",      # image tag with onerror
    r"\.\./",                          # Path traversal attempts
    r"eval\(",                         # Potential RCE (Remote Code Execution) attempts
    r"base64,",                        # Possible encoded payloads
    r"<\?php",                         # PHP injection attempts
]

def get_real_ip():
    # Get the real IP address from the headers
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # The first IP in the X-Forwarded-For header is usually the real IP
        ip = x_forwarded_for.split(',')[0]
    else:
        # If no X-Forwarded-For header, use the remote address
        ip = request.remote_addr
    return ip

def is_suspicious_content(content):
    # Check if the content matches any suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False

def log_content(content, filename):
    now = datetime.now()
    ip = get_real_ip()  # Get the real IP
    user_agent = request.headers.get("User-Agent", "Unknown")
    referer = request.headers.get("Referer", "Unknown")
    method = request.method
    url = request.url

    extension = os.path.splitext(filename)[-1].lower()
    suspicious_filetype = extension in ['.php', '.html', '.js', '.sh', '.py']  # More dangerous file types

    suspicious = is_suspicious_content(content) or suspicious_filetype

    log_path = ATTACK_LOG if suspicious else GENERAL_LOG

    # Create log entry with more advanced details
    with open(log_path, 'a') as f:
        if suspicious:
            f.write(f"[⚠️ ATTACK DETECTED] [{now}]\n")
        else:
            f.write(f"[GENERAL NOTE SAVED] [{now}]\n")
        f.write(f"Filename: {filename}\n")
        f.write(f"Content Preview: {content[:100]}...\n")
        f.write(f"File Size: {len(content)} bytes\n")  # Log file size as well
        f.write("-" * 60 + "\n")
        f.write(f"[{now}] IP: {ip} | GEO: Geolocation not available | METHOD: {method} | URL: {url} | UA: {user_agent} | REFERER: {referer}\n")
        f.write("=" * 60 + "\n\n")

        # Log file upload information specifically
        if suspicious_filetype:
            f.write("[⚠️ MALICIOUS FILE UPLOAD DETECTED] WARNING: Potential PHP file uploaded\n")
            f.write(f"File Type: {extension}\n")
            f.write("-" * 60 + "\n\n")

# Sample usage in your Flask app (this would be in a route handler that handles file uploads)
@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']
    if uploaded_file:
        filename = uploaded_file.filename
        content = uploaded_file.read().decode(errors='ignore')  # Read content, ignoring errors
        log_content(content, filename)
        # Further processing like saving the file
        return "File uploaded", 200
    return "No file uploaded", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
