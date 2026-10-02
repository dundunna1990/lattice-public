import logging
import os
import sqlite3

import aiosqlite


logger = logging.getLogger(__name__)

SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_CONNECT_TIMEOUT_SECONDS = 5.0


def is_sqlite_busy_error(exc: BaseException) -> bool:
    """Return True only for SQLite writer-contention errors."""
    return (
        isinstance(exc, sqlite3.OperationalError)
        and any(token in str(exc).lower() for token in ("locked", "busy"))
    )


def _database_path() -> str:
    db_path = os.environ.get("LATTICE_DB_PATH")
    if not db_path:
        raise RuntimeError(
            "LATTICE_DB_PATH environment variable is not set. "
            "Please set it to a valid database file path."
        )
    return db_path


def get_db_connection():
    """Return a configured synchronous SQLite connection."""
    conn = sqlite3.connect(
        _database_path(),
        timeout=SQLITE_CONNECT_TIMEOUT_SECONDS,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}"
    )
    return conn


async def get_async_db_connection():
    """Return a configured aiosqlite connection for asyncio runtime paths."""
    conn = await aiosqlite.connect(
        _database_path(),
        timeout=SQLITE_CONNECT_TIMEOUT_SECONDS,
    )
    conn.row_factory = sqlite3.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.execute(
        f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}"
    )
    return conn
