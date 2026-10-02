import asyncio
import signal
from unittest.mock import patch

import lattice.daemon.main as daemon_main


class FakeNotifier:
    def __init__(self):
        self.messages = []

    def notify(self, message):
        self.messages.append(message)


class FakeServer:
    def __init__(self):
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.close()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class FakeHealthLoop:
    instance = None

    def __init__(self, interval_seconds):
        self.interval_seconds = interval_seconds
        self.stopped = False
        FakeHealthLoop.instance = self

    async def start(self):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise

    def stop(self):
        self.stopped = True


async def test_master_sigterm_stops_background_tasks_cleanly(monkeypatch):
    real_loop = asyncio.get_running_loop()
    fake_signal_handlers = {}

    class SignalLoop:
        def add_signal_handler(self, sig, callback):
            fake_signal_handlers[sig] = callback
            if sig == signal.SIGTERM:
                real_loop.call_soon(callback)

        def remove_signal_handler(self, sig):
            fake_signal_handlers.pop(sig, None)
            return True

    notifier = FakeNotifier()
    servers = [FakeServer(), FakeServer()]

    async def fake_start_unix_server(*_args, **_kwargs):
        return servers.pop(0)

    async def forever_monitor():
        await asyncio.Event().wait()

    async def forever_web(started_event):
        started_event.set()
        await asyncio.Event().wait()

    config = type("Config", (), {
        "daemon": type("Daemon", (), {"poll_interval": 10})()
    })()

    monkeypatch.setattr(daemon_main.asyncio, "get_running_loop", lambda: SignalLoop())
    monkeypatch.setattr(daemon_main.asyncio, "start_unix_server", fake_start_unix_server)
    monkeypatch.setattr(daemon_main, "_bootstrap_master_sync", lambda: config)
    monkeypatch.setattr(daemon_main, "_apply_master_log_level", lambda _config: None)
    monkeypatch.setattr(daemon_main, "HealthCheckLoop", FakeHealthLoop)
    monkeypatch.setattr(daemon_main, "run_monitor_async", forever_monitor)
    monkeypatch.setattr(daemon_main, "run_web_server", forever_web)
    monkeypatch.setattr(daemon_main.sdnotify, "SystemdNotifier", lambda: notifier)
    monkeypatch.setattr(daemon_main.os, "unlink", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_main.os, "chmod", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_main.os, "chown", lambda *_args, **_kwargs: None)

    await asyncio.wait_for(daemon_main.main_loop(), timeout=1.0)

    assert FakeHealthLoop.instance is not None
    assert FakeHealthLoop.instance.stopped is True
    assert "READY=1" in notifier.messages
    assert "STOPPING=1" in notifier.messages
    assert signal.SIGTERM not in fake_signal_handlers
