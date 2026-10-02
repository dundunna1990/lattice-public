import httpx
import logging

logger = logging.getLogger(__name__)

class WebhookChannel:
    def __init__(self, cfg):
        self.url = cfg.get('url')
        self.method = cfg.get('method', 'POST')
        self.headers = cfg.get('headers', {})

    def send(self, title, message, severity, **kwargs):
        logger.info(f"Sending Webhook notification: {title}")
        if not self.url:
            logger.warning("Webhook URL not configured")
            return
        data = {'title': title, 'message': message, 'severity': severity, **kwargs}
        if self.method.upper() == 'POST':
            httpx.post(self.url, json=data, headers=self.headers, timeout=10)
        else:
            httpx.get(self.url, params=data, headers=self.headers)
