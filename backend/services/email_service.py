import logging
import os
#preffering Gmail for now
# For SendGrid: from sendgrid import SendGridAPIClient
#               from sendgrid.helpers.mail import Mail
# For Gmail API: from google.oauth2.credentials import Credentials 
#                from google_auth_oauthlib.flow import InstalledAppFlow
#                from googleapiclient.discovery import build
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_email(subject: str, body: str, to_email: str):
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME", "kaaamgar.sahayak@gmail.com")
    smtp_password = os.getenv("SMTP_PASSWORD", None)
    sender_email = os.getenv("SENDER_EMAIL", smtp_username)

    logger.info(f"Preparing to send email via {smtp_server}:{smtp_port} as {smtp_username} to {to_email}")
    if not smtp_password:
        logger.error("SMTP_PASSWORD not set in environment variables.")
        return False

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}", exc_info=True)
        return False

logger = logging.getLogger(__name__)

# --- Configuration for Email Service ---
# EMAIL_API_KEY = os.getenv("SENDGRID_API_KEY") # Example for SendGrid
# ADMIN_EMAIL_RECEIVER = os.getenv("ADMIN_EMAIL_RECEIVER", "admin@example.com")
# SENDER_EMAIL = os.getenv("SENDER_EMAIL", "chatbot@yourdomain.com")