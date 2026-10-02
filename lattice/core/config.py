import os
import logging

logger = logging.getLogger(__name__)
import sys
from pydantic import BaseModel, Field, model_validator

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from lattice.core.db import get_db_connection
import time

CONFIG_PATH = os.environ.get("LATTICE_CONFIG_PATH", "/etc/lattice/lattice.toml")

_CONFIG_CACHE: dict[str, tuple[str | None, float]] = {}
_CONFIG_CACHE_TTL_SECONDS = 1.0

# SQLite stores only mutable runtime state. Static configuration, credentials,
# tokens, webhook secrets, and future config fields remain exclusively in the
# protected TOML/token/key stores unless they are explicitly added here.
_DB_RUNTIME_KEYS = {
    "autoheal.mode",
    "auto_heal.pause_until",
}
_DB_RUNTIME_PREFIXES = (
    "autoheal.enabled.",
    "health.recheck.",
)


def _is_db_runtime_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    if key in _DB_RUNTIME_KEYS:
        return True
    for prefix in _DB_RUNTIME_PREFIXES:
        if key.startswith(prefix):
            suffix = key[len(prefix):]
            return suffix.isdigit() and int(suffix) > 0
    return False


def _require_db_runtime_key(key: str) -> str:
    if not _is_db_runtime_key(key):
        raise ValueError(f"Config key is not permitted in runtime SQLite state: {key}")
    return key


class MasterConfig(BaseModel):
    master_key: str = Field(default="", description="Master key for destructive operations")
    telegram_secret: str = Field(default="", description="Static secret for Telegram webhook auth")
    ip: str = Field(default="127.0.0.1", description="Master node IP address")
    port: int = Field(default=8000, ge=1, le=65535)
    api_token: str = Field(default="", description="Bearer token for API auth")
    api_port: int = Field(default=8080, ge=1, le=65535, description="Master API + web UI port")
    telegram_token: str = Field(default="", description="Telegram bot token (self-serve bot)")
    telegram_chat_id: str = Field(default="", description="Telegram chat ID for alert delivery")

class DaemonConfig(BaseModel):
    poll_interval: int = Field(default=10, ge=1, description="Health check interval in seconds")
    dry_run: bool = Field(default=True, description="If True, auto-heal actions are logged but not executed")
    log_level: str = Field(default="INFO")

class WireFormatConfig(BaseModel):
    port: int = Field(default=9999, ge=1, le=65535)
    connect_timeout_seconds: int = Field(default=2, ge=1)
    request_timeout_seconds: int = Field(default=30, ge=1)
    idle_timeout_seconds: int = Field(default=60, ge=1)
    # Reserved for a future hard connection-age policy. It is intentionally
    # not exposed in the operator Settings UI until the transport enforces it.
    max_connection_lifetime_seconds: int = Field(default=300, ge=1)
    max_retry_attempts: int = Field(default=3, ge=1)
    retry_initial_backoff_ms: int = Field(default=100, ge=1)
    retry_max_backoff_ms: int = Field(default=2000, ge=1)
    ufw_subnet: str = Field(default="auto", description="Local firewall subnet is detected at setup time")

    @model_validator(mode="after")
    def _validate_retry_backoff(self):
        if self.retry_initial_backoff_ms > self.retry_max_backoff_ms:
            raise ValueError("Initial network backoff cannot exceed maximum network backoff")
        return self

class FileAccessConfig(BaseModel):
    enabled: bool = Field(default=True)
    port: int = Field(default=22022, ge=1, le=65535)
    probe_interval_seconds: int = Field(default=15, ge=5)
    persistent_alert_seconds: int = Field(default=300, ge=30)
    retry_initial_seconds: float = Field(default=2.0, gt=0)
    retry_max_seconds: int = Field(default=300, ge=10)
    key_rotation_days: int = Field(default=90, ge=1)
    lan_only: bool = Field(default=True)

    @model_validator(mode="after")
    def _validate_retry_delay(self):
        if self.retry_initial_seconds > self.retry_max_seconds:
            raise ValueError("Initial file retry delay cannot exceed maximum file retry delay")
        return self


class ShellAccessConfig(BaseModel):
    enabled: bool = Field(default=True)
    port: int = Field(default=22023, ge=1, le=65535)
    key_rotation_days: int = Field(default=90, ge=1)
    reconnect_seconds: int = Field(default=5, ge=1)
    persistent_alert_seconds: int = Field(default=300, ge=30)
    lan_only: bool = Field(default=True)


class BackupConfig(BaseModel):
    enabled: bool = Field(default=True)
    schedule_hour: int = Field(default=2, ge=0, le=23)
    retention_daily: int = Field(default=30, ge=1, le=3650)
    retention_weekly: int = Field(default=26, ge=1, le=520)
    retention_monthly: int = Field(default=12, ge=1, le=120)
    free_space_reserve_percent: int = Field(default=20, ge=5, le=50)
    deep_verification_days: int = Field(default=7, ge=1, le=90)
    persistent_alert_seconds: int = Field(default=86400, ge=300)
    bandwidth_limit_kib: int = Field(default=0, ge=0, le=10_000_000)
    lan_only: bool = Field(default=True)


class CareConfig(BaseModel):
    enabled: bool = Field(default=True)
    battery_defer_percent: int = Field(default=30, ge=5, le=80)
    disk_warning_percent: int = Field(default=80, ge=50, le=95)
    disk_critical_percent: int = Field(default=90, ge=60, le=99)
    security_updates: bool = Field(default=True)
    apt_autoclean: bool = Field(default=True)
    journal_vacuum: bool = Field(default=True)
    stale_crash_cleanup: bool = Field(default=True)
    flatpak_unused_cleanup: bool = Field(default=True)
    old_kernel_cleanup: bool = Field(default=True)

    @model_validator(mode="after")
    def _validate_disk_thresholds(self):
        if self.disk_warning_percent >= self.disk_critical_percent:
            raise ValueError("Care disk warning threshold must be below critical threshold")
        return self


class NotificationsConfig(BaseModel):
    channels: list = Field(default_factory=list)

class LatticeConfig(BaseModel):
    master: MasterConfig = Field(default_factory=MasterConfig)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    wire_format: WireFormatConfig = Field(default_factory=WireFormatConfig)
    file_access: FileAccessConfig = Field(default_factory=FileAccessConfig)
    shell_access: ShellAccessConfig = Field(default_factory=ShellAccessConfig)
    backup: BackupConfig = Field(default_factory=BackupConfig)
    care: CareConfig = Field(default_factory=CareConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)


def get_config_value(key: str) -> str:
    _require_db_runtime_key(key)
    # These values live in SQLite and may be changed by another CLI process.
    # A short time cache avoids stale safety policy without hammering the DB.
    now = time.monotonic()
    if key in _CONFIG_CACHE:
        value, cached_at = _CONFIG_CACHE[key]
        if now - cached_at < _CONFIG_CACHE_TTL_SECONDS:
            return value
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    value = row[0] if row else None
    _CONFIG_CACHE[key] = (value, now)
    return value

def set_config_value(key: str, value: str) -> None:
    _require_db_runtime_key(key)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
        (key, value)
    )
    conn.commit()
    conn.close()
    # M8 fix: invalidate cache so next read sees the new value
    _CONFIG_CACHE.pop(key, None)

def load_config(path: str = CONFIG_PATH) -> LatticeConfig:
    if not os.path.exists(path):
        return LatticeConfig()
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
            return LatticeConfig(**data)
        except Exception as e:
            logger.error(f"CRITICAL: Failed to parse {path}: {e}")
            raise

def _flatten(obj, prefix=""):
    items = []
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump()
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_prefix = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                items.extend(_flatten(v, new_prefix))
            else:
                items.append((new_prefix, str(v) if v is not None else ""))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            items.extend(_flatten(item, f"{prefix}.{i}"))
    else:
        items.append((prefix, str(obj) if obj is not None else ""))
    return items

def reconcile_config(config: LatticeConfig):
    """Purge legacy/static config copies from the runtime SQLite store.

    Runtime state is created only by explicit set_config_value() callers.
    The parsed TOML object is intentionally not flattened or mirrored here.
    """
    del config  # Reconciliation is a purge boundary, not a TOML mirror.
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT key FROM config").fetchall()
        stale_keys = [row[0] for row in rows if not _is_db_runtime_key(row[0])]
        if stale_keys:
            conn.executemany("DELETE FROM config WHERE key = ?", [(key,) for key in stale_keys])
        conn.commit()
    finally:
        conn.close()
    _CONFIG_CACHE.clear()

def save_config(config: LatticeConfig, path: str = CONFIG_PATH):
    import tomli_w
    import tempfile
    destination = os.path.abspath(path)
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{os.path.basename(path)}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            tomli_w.dump(config.model_dump(), handle)
            handle.flush()
            os.fsync(handle.fileno())
        production_path = os.path.abspath(CONFIG_PATH)
        if destination == production_path and os.geteuid() == 0:
            import grp
            lattice_gid = grp.getgrnam("lattice").gr_gid
            os.chown(temporary, 0, lattice_gid)
            os.chmod(temporary, 0o640)
        elif os.path.exists(destination):
            os.chmod(temporary, os.stat(destination).st_mode & 0o777)
        else:
            os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

if __name__ == "__main__":
    cfg = load_config()
    reconcile_config(cfg)
    print("Configuration loaded and reconciled to database successfully.")
