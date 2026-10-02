"""
Telegram bot integration for alerts (Decision 8 – self‑serve bot).
Sends notifications and handles inline button callbacks.
"""
import logging
import json
import asyncio
from typing import Optional, Dict, Any

import httpx
from lattice.core.config import load_config
from lattice.core.db import get_db_connection

logger = logging.getLogger(__name__)

class TelegramBot:
    def __init__(self, token: Optional[str] = None, chat_id: Optional[str] = None):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}" if token else None

    @classmethod
    def from_config(cls):
        """Create a TelegramBot instance from the config."""
        config = load_config()
        try:
            token = getattr(config.master, 'telegram_token', None)
            chat_id = getattr(config.master, 'telegram_chat_id', None)
            # Only accept non-empty string values (filter out Mock objects, None, etc.)
            if not isinstance(token, str) or not token:
                token = None
            if not isinstance(chat_id, str) or not chat_id:
                chat_id = None
            if not token or not chat_id:
                logger.warning("Telegram token or chat_id not configured")
                return cls()
            return cls(token, chat_id)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
            return cls()

    def send_alert(self, title: str, message: str, alert_id: int, worker_hostname: str) -> bool:
        """Send an alert notification via Telegram with inline buttons."""
        if not self.token or not self.chat_id:
            logger.warning("Telegram not configured, skipping notification")
            return False
        # Build inline keyboard buttons
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔍 View", "callback_data": json.dumps({"action": "view", "alert_id": alert_id})},
                    {"text": "✅ Acknowledge", "callback_data": json.dumps({"action": "ack", "alert_id": alert_id})}
                ],
                [
                    {"text": "⏸ Pause 4h", "callback_data": json.dumps({"action": "pause", "alert_id": alert_id})},
                    {"text": "🔧 Run heal", "callback_data": json.dumps({"action": "heal", "alert_id": alert_id})}
                ]
            ]
        }

        alert_text = f"⚠️ *{title}*\n\n{message}\n\nWorker: `{worker_hostname}`\nAlert ID: `{alert_id}`"

        payload = {
            "chat_id": self.chat_id,
            "text": alert_text,
            "parse_mode": "Markdown",
            "reply_markup": json.dumps(keyboard)
        }

        try:
            response = httpx.post(f"{self.base_url}/sendMessage", json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Telegram alert sent for alert {alert_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        """Implement the common notification-channel interface."""
        alert_id = kwargs.get("alert_id")
        worker = kwargs.get("worker")
        if not isinstance(alert_id, int) or not isinstance(worker, str):
            logger.error("Telegram notification is missing a valid alert ID or worker")
            return False
        return self.send_alert(title, message, alert_id, worker)

    def handle_callback(self, callback_data: dict, callback_query: dict = None) -> None:
        """Handle Telegram inline button callbacks.

        Bulletproofness:
        - Validates callback_data shape; bails with a clear reply if malformed.
        - Uses answerCallbackQuery so the loading spinner stops immediately.
        - Retries on transient errors (timeout, 5xx, 429) with backoff.
        - Doesn't crash if the original message or callback_query is missing.
        - Idempotent: acknowledging an already-resolved alert just replies "OK".

        Function-local imports: the test suite patches lattice.core.events.acknowledge_alert
        and lattice.core.config.set_config_value, and patch() only works if these names
        are looked up at call time (not at module import time). So we import them here.
        """
        from datetime import datetime, timedelta, timezone
        from lattice.core.events import acknowledge_alert
        from lattice.core.config import set_config_value

        action = callback_data.get("action")
        alert_id = callback_data.get("alert_id")
        if not alert_id:
            self._reply(callback_query, "⚠️ Callback missing alert_id")
            return

        if action == "ack":
            result = acknowledge_alert(alert_id)
            if result:
                self._reply(callback_query, f"✅ Alert {alert_id} acknowledged.")
            else:
                # Idempotent: it may already be resolved by someone else
                self._reply(callback_query, f"ℹ️ Alert {alert_id} already resolved.")

        elif action == "pause":
            pause_until = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
            try:
                set_config_value("auto_heal.pause_until", pause_until)
                self._reply(callback_query, f"⏸️ Auto-heal paused until {pause_until}")
            except Exception as e:
                self._reply(callback_query, f"❌ Could not pause auto-heal: {e}")

        elif action == "heal":
            conn = get_db_connection()
            try:
                row = conn.execute("SELECT worker_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            finally:
                conn.close()
            if not row or row[0] is None:
                self._reply(callback_query, f"⚠️ Alert {alert_id} has no worker to recheck.")
                return
            set_config_value(f"health.recheck.{row[0]}", "true")
            self._reply(callback_query, f"🔧 Immediate health recheck scheduled for alert {alert_id}.")

        elif action == "view":
            from lattice.core.db import get_db_connection
            try:
                conn = get_db_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT worker_id FROM alerts WHERE id = ?", (alert_id,))
                    row = cursor.fetchone()
                    if row:
                        config = load_config()
                        self._reply(
                            callback_query,
                            f"🔍 View alerts: https://{config.master.ip}:{config.master.api_port}/alerts",
                        )
                    else:
                        self._reply(callback_query, f"⚠️ Alert {alert_id} not found")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            except Exception as e:
                self._reply(callback_query, f"❌ Could not look up alert {alert_id}: {e}")

        else:
            self._reply(callback_query, f"⚠️ Unknown action: {action}")

    def _reply(self, callback_query, text: str, show_alert: bool = False) -> None:
        """Call Telegram answerCallbackQuery so the spinner stops.

        Retries on transient errors (timeout, 5xx, 429) with exponential backoff.
        Never raises — we don't want a callback handler to crash the webhook.
        """
        if not callback_query or not self.token:
            # No callback_query (we're being called directly) or no token — just log.
            logger.info(f"Telegram reply: {text}")
            return
        callback_id = callback_query.get("id")
        if not callback_id:
            logger.info(f"Telegram reply (no callback id): {text}")
            return

        import time as _time
        url = f"{self.base_url}/answerCallbackQuery"
        payload = {
            "callback_query_id": callback_id,
            "text": text,
            "show_alert": show_alert,
        }
        max_attempts = 3
        backoff = 0.5
        for attempt in range(1, max_attempts + 1):
            try:
                response = httpx.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    return
                if response.status_code == 429:
                    # Rate limited — wait the suggested time if provided
                    retry_after = response.json().get("parameters", {}).get("retry_after", 1)
                    _time.sleep(min(retry_after, 10))
                    continue
                if 500 <= response.status_code < 600:
                    # Server error — retry
                    if attempt < max_attempts:
                        _time.sleep(backoff)
                        backoff = min(backoff * 2, 5.0)
                        continue
                # Client error (other) or exhausted retries — log and give up
                logger.warning(f"answerCallbackQuery returned {response.status_code}: {response.text[:200]}")
                return
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                if attempt < max_attempts:
                    _time.sleep(backoff)
                    backoff = min(backoff * 2, 5.0)
                    continue
                logger.warning(f"answerCallbackQuery network error after {attempt} attempts: {e}")
                return
            except Exception as e:
                logger.warning(f"answerCallbackQuery unexpected error: {e}")
                return



# --------------------------------------------------------------------------
# Module-level convenience functions — preserve the public API.
# webhooks.py and tests import these directly.
# --------------------------------------------------------------------------
def send_alert_notification(alert_id: int, title: str, message: str, worker_hostname: str) -> bool:
    """Send an alert notification via Telegram (sync).

    Module-level convenience wrapper. Returns the result of TelegramBot.send_alert.
    """
    bot = TelegramBot.from_config()
    return bot.send_alert(title, message, alert_id, worker_hostname)


def handle_callback(callback_data, callback_query=None):
    """Standalone wrapper for TelegramBot.handle_callback.

    Module-level convenience so `from lattice.notifications.telegram import handle_callback`
    continues to work (used by webhooks.py and tests).
    """
    bot = TelegramBot.from_config()
    return bot.handle_callback(callback_data, callback_query)
