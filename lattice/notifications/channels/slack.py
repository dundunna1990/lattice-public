import httpx
import logging

logger = logging.getLogger(__name__)

class SlackChannel:
    def __init__(self, cfg):
        self.webhook_url = cfg.get('webhook_url')

    def send(self, title, message, severity, **kwargs):
        logger.info(f"Sending Slack notification: {title}")
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return
        httpx.post(self.webhook_url, json={'text': f'*{title}*\n{message}'}, timeout=10)
