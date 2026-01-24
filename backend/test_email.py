import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load .env if running locally, though inside docker it will use env vars
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email_test")

def verify_email():
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM_EMAIL", smtp_user)
    to_email = "samyukthajagannath@gmail.com"

    print(f"--- SMTP Diagnostic ---")
    print(f"Host: {smtp_host}")
    print(f"Port: {smtp_port}")
    print(f"User: {smtp_user}")
    print(f"From: {smtp_from}")
    print(f"To:   {to_email}")
    print(f"Password: {'****' if smtp_password else 'NOT SET'}")
    print(f"-----------------------")

    if not all([smtp_host, smtp_user, smtp_password]):
        print("❌ ERROR: Missing SMTP configuration.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = to_email
        msg['Subject'] = "🧪 CloudGuard SMTP Test Connection"

        body = "<h3>CloudGuard SMTP Connection Test</h3><p>If you are reading this, the <b>HTML</b> email delivery is working correctly.</p>"
        msg.attach(MIMEText(body, 'html'))

        print(f"Connecting to {smtp_host}...")
        
        # Enable SMTP debug output
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)
        
        print("Starting TLS...")
        server.starttls()
        
        print(f"Logging in as {smtp_user}...")
        server.login(smtp_user, smtp_password)
        
        print(f"Sending message to {to_email}...")
        server.send_message(msg)
        
        print("Closing connection...")
        server.quit()
            
        print("✅ SUCCESS: Test email sent successfully.")

    except Exception as e:
        print(f"❌ FAILED: {str(e)}")

if __name__ == "__main__":
    verify_email()
