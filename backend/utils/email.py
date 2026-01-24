import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List

logger = logging.getLogger("email_utils")

def send_scan_notification(to_email: str, scan_ids: List[int]):
    """
    Sends an email notification with scan results summary.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM_EMAIL", smtp_user)

    if not all([smtp_host, smtp_user, smtp_password]):
        logger.warning("📩 Email NOT sent: SMTP credentials or host not configured in environment.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = to_email
        msg['Subject'] = f"🛡️ CloudVulnerability Scan Complete - ID: {', '.join(map(str, scan_ids))}"

        body = f"""
        <h2>Cloud Security Scan Complete</h2>
        <p>A scheduled security scan has finished successfully.</p>
        <p><b>Scan IDs:</b> {', '.join(map(str, scan_ids))}</p>
        <p>You can view the detailed report on your dashboard: <a href="http://localhost:8000/dashboard?scan_ids={','.join(map(str, scan_ids))}">View Results</a></p>
        <br>
        <p><i>This is an automated notification from CloudGuard Security Scanner.</i></p>
        """
        msg.attach(MIMEText(body, 'html'))

        logger.info(f"📩 Attempting to send scan notification to {to_email} via {smtp_host}...")
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.set_debuglevel(1)  # Enable debug output to see the full SMTP transaction in logs
            server.starttls()  # Upgrade the connection to secure
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            
        logger.info(f"✅ Scan notification sent successfully to {to_email}")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to send scan notification: {e}")
        return False
