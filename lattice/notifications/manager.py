
import logging
from typing import List, Dict, Any
from lattice.core.config import load_config
from lattice.notifications.channels.slack import SlackChannel
from lattice.notifications.channels.email import EmailChannel
from lattice.notifications.channels.webhook import WebhookChannel
from lattice.notifications.telegram import TelegramBot
logger = logging.getLogger(__name__)
class NotificationManager:
    def __init__(self):
        self.channels = []
        self._load_channels()
    def _load_channels(self):
        config = load_config()
        bot = TelegramBot.from_config()
        if bot.token and bot.chat_id:
            self.channels.append(bot)
        for ch in (config.notifications.channels if hasattr(config, "notifications") else []):
            if ch.get("enabled", True):
                t = ch.get("type")
                if t == "slack":
                    self.channels.append(SlackChannel(ch.get("config", {})))
                elif t == "email":
                    self.channels.append(EmailChannel(ch.get("config", {})))
                elif t == "webhook":
                    self.channels.append(WebhookChannel(ch.get("config", {})))
    def send(self, title, message, severity="info", **kwargs):
        for ch in self.channels:
            try:
                ch.send(title, message, severity, **kwargs)
            except Exception as e:
                logger.error(f"Failed via {ch.__class__.__name__}: {e}")
_manager = None
def get_manager():
    global _manager
    if _manager is None:
        _manager = NotificationManager()
    return _manager
