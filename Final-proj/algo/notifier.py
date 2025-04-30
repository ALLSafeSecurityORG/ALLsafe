import smtplib
import os
import discord
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from discord import Webhook, RequestsWebhookAdapter
import time

# Email setup
SENDER_EMAIL = "allsafeallsafe612@gmail.com"
SENDER_PASSWORD = "SuperSecure@123"  # You should secure this in environment variables or use app-specific passwords
RECIPIENT_EMAILS = ["unknownzero51@gmail.com", "aryanbhandari2431@gmail.com"]

# Discord webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1367134586965987379/8Ajs4az4SC0RAiDdqBNOcWxge_bgjs3-kB8PuUo0zeZrgeNvQbHFBOFeEICM2MEV6-vL"

# Log file path (adjusted as per your provided path)
LOG_FILE = os.path.join(os.path.dirname(__file__), "Final-proj", "logs", "attacks.log")

# Email and Discord message formats
def send_email(subject, body):
    """Send an email with the attack details."""
    try:
        # Setting up the MIME
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECIPIENT_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connecting to Gmail's SMTP server
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())

        print("Email sent successfully!")

    except Exception as e:
        print(f"Error sending email: {e}")


def send_discord_message(message):
    """Send a message to the Discord webhook."""
    try:
        webhook = Webhook.from_url(DISCORD_WEBHOOK_URL, adapter=RequestsWebhookAdapter())
        webhook.send(message)
        print("Discord notification sent successfully!")

    except Exception as e:
        print(f"Error sending Discord notification: {e}")


def check_for_new_attack():
    """Check the log file for new attack entries and send notifications."""
    try:
        with open(LOG_FILE, 'r') as file:
            lines = file.readlines()
        
        # Read the last line for the most recent attack
        if lines:
            latest_attack = lines[-1].strip()
            send_email("New Attack Detected", latest_attack)
            send_discord_message(f"```{latest_attack}```")  # Send as a code block for better formatting
    except Exception as e:
        print(f"Error reading log file: {e}")


if __name__ == "__main__":
    while True:
        check_for_new_attack()
        # Wait for a while before checking again
        time.sleep(10)  # Adjust sleep time as needed (e.g., every 10 seconds)
