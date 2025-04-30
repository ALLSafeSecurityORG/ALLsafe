import smtplib
import discord
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Email setup
SENDER_EMAIL = 'allsafeallsafe612@gmail.com'
SENDER_PASSWORD = 'SuperSecure@123'  # Use App Password if 2FA is enabled
RECEIVER_EMAILS = ['unknownzero51@gmail.com', 'aryanbhandari2431@gmail.com']
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Discord setup
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL"

# Log file path
LOG_FILE_PATH = 'Final-proj/logs/attacks.log'

# Email function
def send_email(subject, body):
    try:
        # Set up email server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECEIVER_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        server.quit()
        logging.info(f"Email sent to {', '.join(RECEIVER_EMAILS)}")
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")

# Discord function
def send_discord_message(message):
    try:
        # Send message to Discord webhook
        data = {"content": message}
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code == 204:
            logging.info("Message sent to Discord successfully.")
        else:
            logging.error(f"Failed to send message to Discord. Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending Discord message: {str(e)}")

# Monitor log file for new attacks
def monitor_logs(line):
    logging.info(f"New log entry detected: {line.strip()}")
    
    # Check for attack patterns (e.g., SQL Injection)
    if 'SQL INJECTION' in line:
        subject = "SQL Injection Attack Detected"
        body = f"An SQL injection attempt was detected:\n\n{line}"
        send_email(subject, body)
        send_discord_message(f"**SQL Injection Attack Detected!**\n\n{line}")
    elif 'XSS' in line:
        subject = "XSS Attack Detected"
        body = f"An XSS attack attempt was detected:\n\n{line}"
        send_email(subject, body)
        send_discord_message(f"**XSS Attack Detected!**\n\n{line}")
    # Add more attack checks as needed

# Watchdog event handler to detect changes in the log file
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == LOG_FILE_PATH:
            with open(LOG_FILE_PATH, 'r') as file:
                # Read the last line of the log file
                lines = file.readlines()
                last_line = lines[-1]
                # Call monitor_logs function with the new line
                monitor_logs(last_line)

# Run the watcher to monitor the log file
def start_log_watcher():
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path='Final-proj/logs', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Run the script
if __name__ == '__main__':
    start_log_watcher()
