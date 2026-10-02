import smtplib
from email.mime.text import MIMEText
import logging

logger = logging.getLogger(__name__)

class EmailChannel:
    def __init__(self, cfg):
        self.smtp_host = cfg.get('smtp_host')
        self.smtp_port = cfg.get('smtp_port', 587)
        self.username = cfg.get('username')
        self.password = cfg.get('password')
        self.from_addr = cfg.get('from')
        self.to_addr = cfg.get('to')

    def send(self, title, message, severity, **kwargs):
        logger.info(f"Sending Email notification: {title}")
        if not all([self.smtp_host, self.username, self.password, self.from_addr, self.to_addr]):
            logger.warning("Email config incomplete")
            return
        msg = MIMEText(message)
        msg['Subject'] = f'[{severity.upper()}] {title}'
        msg['From'] = self.from_addr
        msg['To'] = self.to_addr
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
