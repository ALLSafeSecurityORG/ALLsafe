import smtplib
import time
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Email and Discord details
SENDER_EMAIL = 'allsafeallsafe612@gmail.com'  # Replace with your sender email
RECEIVER_EMAILS = ['unknownzero51@gmail.com', 'aryanbhandari2431@gmail.com']  # Replace with receiver emails
EMAIL_PASSWORD = 'SuperSecure@123'  # Replace with your email password (or app password)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Discord webhook URL
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL'  # Replace with your actual webhook URL

# Path to the attack logs
LOG_FILE_PATH = 'logs/attacks.log'

def send_email(subject, body):
    try:
        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECEIVER_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Setup the server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, text)
        server.quit()
        print(f'Email sent to {", ".join(RECEIVER_EMAILS)}')
    except Exception as e:
        print(f"Error sending email: {e}")

def send_discord_notification(message):
    try:
        data = {
            "content": message
        }
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code == 204:
            print("Discord notification sent successfully!")
        else:
            print(f"Failed to send Discord notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending Discord notification: {e}")

def read_last_line():
    with open(LOG_FILE_PATH, 'r') as f:
        lines = f.readlines()
    return lines[-1] if lines else None

def monitor_log():
    last_line = None

    while True:
        try:
            # Read the last line of the log file
            current_line = read_last_line()

            if current_line and current_line != last_line:
                # If a new line is found (i.e., new attack detected)
                last_line = current_line
                print(f"New attack detected: {current_line.strip()}")

                # Prepare the message
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                attack_details = f"New attack detected at {timestamp}:\n{current_line.strip()}"

                # Send email and Discord notifications
                send_email('Attack Detected', attack_details)
                send_discord_notification(attack_details)

            # Wait for some time before checking again
            time.sleep(5)
        except Exception as e:
            print(f"Error in monitoring log: {e}")
            time.sleep(10)

if __name__ == '__main__':
    monitor_log()
