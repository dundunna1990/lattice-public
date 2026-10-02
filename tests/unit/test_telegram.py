"""
Unit tests for Telegram bot integration.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from lattice.notifications.telegram import TelegramBot, send_alert_notification

def test_telegram_send_alert_success():
    """Test that send_alert returns True on success."""
    bot = TelegramBot(token="fake-token", chat_id="fake-chat")
    with patch("httpx.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        result = bot.send_alert("Test Title", "Test Message", 123, "worker1")
        assert result is True
        mock_post.assert_called_once()

def test_telegram_send_alert_failure():
    """Test that send_alert returns False on failure."""
    bot = TelegramBot(token="fake-token", chat_id="fake-chat")
    with patch("httpx.post") as mock_post:
        mock_post.side_effect = Exception("Network error")
        result = bot.send_alert("Test Title", "Test Message", 123, "worker1")
        assert result is False

def test_telegram_implements_notification_manager_send_interface():
    bot = TelegramBot(token="fake-token", chat_id="fake-chat")
    with patch.object(bot, "send_alert", return_value=True) as send_alert:
        assert bot.send("Title", "Message", "error", alert_id=9, worker="worker-one") is True
    send_alert.assert_called_once_with("Title", "Message", 9, "worker-one")

def test_telegram_from_config_missing():
    """When config missing, should return a dummy bot."""
    with patch("lattice.notifications.telegram.load_config") as mock_load:
        mock_config = MagicMock()
        # Delete attributes so getattr returns None
        del mock_config.telegram_token
        del mock_config.telegram_chat_id
        mock_load.return_value = mock_config
        bot = TelegramBot.from_config()
        assert bot.token is None
        assert bot.chat_id is None

def test_telegram_callback_handling():
    """Handle callback should call the appropriate actions."""
    bot = TelegramBot(token="fake", chat_id="fake")
    # Mock acknowledge_alert to avoid hitting the DB
    with patch("lattice.core.events.acknowledge_alert") as mock_ack:
        # Mock set_config_value too, but it's not called for 'ack' action
        bot.handle_callback({"action": "ack", "alert_id": 123})
        mock_ack.assert_called_once_with(123)
    # Test other actions without DB calls
    with patch("lattice.core.config.set_config_value") as mock_set:
        bot.handle_callback({"action": "pause", "alert_id": 123})
        mock_set.assert_called_once()
    # 'view' action uses the DB, so we mock it
    with patch("lattice.core.db.get_db_connection") as mock_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)  # simulate a worker_id
        mock_conn.cursor.return_value = mock_cursor
        mock_db.return_value = mock_conn
        bot.handle_callback({"action": "view", "alert_id": 123})
        mock_cursor.execute.assert_called_once()
