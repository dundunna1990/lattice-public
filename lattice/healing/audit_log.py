"""
Append‑only hash‑chained audit log for heal actions.
Each entry includes the hash of the previous entry, making tampering detectable.
"""
import os
import json
import hashlib
import logging
import stat
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)

# Process-local trusted audit heads. Startup verify_chain() populates this,
# and each successful append advances it. Unexpected inode/size/mtime/hash
# changes force a full chain verification before another append is allowed.
_VERIFIED_HEADS = {}

# Default log file path
DEFAULT_LOG_PATH = Path(os.environ.get("LATTICE_HEAL_AUDIT_LOG_PATH", "/var/log/lattice/heal_audit.log"))

class AuditLog:
    def __init__(self, log_path: Path = DEFAULT_LOG_PATH):
        self.log_path = log_path if isinstance(log_path, Path) else Path(log_path)

        self._ensure_dir()

    def log_entry(self, worker_id=None, service=None, action=None, params=None, result=None, error=None, **kwargs) -> bool:
        """Convenience wrapper: build a dict from kwargs and call append()."""
        entry = {
            "worker_id": worker_id,
            "service": service,
            "action": action,
            "params": params or {},
            "result": result,
        }
        if error:
            entry["error"] = error
        entry.update(kwargs)
        return self.append(entry)

    def _ensure_dir(self):
        """Ensure the log directory exists."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _read_last_entry(self) -> Optional[Dict[str, Any]]:
        """Read the last entry to get its hash."""
        if not self.log_path.exists():
            return None
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                if not lines:
                    return None
                last_line = lines[-1].strip()
                return json.loads(last_line)
        except Exception as e:
            logger.error(f"Failed to read last audit entry: {e}")
            return None

    def _cache_key(self) -> str:
        return os.path.abspath(str(self.log_path))

    @staticmethod
    def _entry_hash_valid(entry: Dict[str, Any]) -> bool:
        if (
            not isinstance(entry, dict)
            or "timestamp" not in entry
            or "data" not in entry
            or "hash" not in entry
        ):
            return False

        hash_data = {
            "timestamp": entry["timestamp"],
            "data": entry["data"],
        }

        if "prev_hash" in entry:
            hash_data["prev_hash"] = entry["prev_hash"]

        computed = hashlib.sha256(
            json.dumps(
                hash_data,
                sort_keys=True,
            ).encode()
        ).hexdigest()

        return entry.get("hash") == computed

    @staticmethod
    def _read_tail_entries_fd(
        fd: int,
        count: int = 2,
    ) -> List[Dict[str, Any]]:
        """Read only the final few JSON lines from an already-locked file."""
        size = os.fstat(fd).st_size
        if size == 0:
            return []

        position = size
        data = b""

        # Read backwards in chunks until enough complete lines are present.
        while (
            position > 0
            and data.count(b"\n") < count + 1
        ):
            amount = min(4096, position)
            position -= amount
            os.lseek(fd, position, os.SEEK_SET)
            data = os.read(fd, amount) + data

        lines = data.splitlines()

        # If we did not reach byte zero, the first line may be partial.
        if position > 0 and lines:
            lines = lines[1:]

        lines = [
            raw.strip()
            for raw in lines
            if raw.strip()
        ][-count:]

        entries = []

        for raw in lines:
            entries.append(
                json.loads(
                    raw.decode("utf-8")
                )
            )

        return entries

    def _cache_head(
        self,
        metadata,
        last_entry: Optional[Dict[str, Any]],
    ) -> None:
        if not last_entry:
            _VERIFIED_HEADS.pop(
                self._cache_key(),
                None,
            )
            return

        _VERIFIED_HEADS[self._cache_key()] = {
            "dev": metadata.st_dev,
            "ino": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "hash": last_entry["hash"],
        }

    def append(
        self,
        entry_data: Dict[str, Any],
    ) -> bool:
        """Append one hash-chained entry without rescanning trusted history.

        Normal operation:
        - acquire exclusive flock
        - validate the final one/two entries
        - confirm they match the process's last fully verified head
        - append + fsync
        - advance trusted head

        If the file changed outside this process, a complete chain verification
        is performed before any further repair record is accepted.
        """
        import fcntl

        self._ensure_dir()

        entry = {
            "timestamp": (
                datetime.now(timezone.utc).isoformat()
                + "Z"
            ),
            "data": entry_data,
        }

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        try:
            fd = os.open(
                str(self.log_path),
                flags,
                0o600,
            )
        except OSError as exc:
            logger.error(
                "Failed to open audit log %s: %s",
                self.log_path,
                exc,
            )
            return False

        try:
            fcntl.flock(
                fd,
                fcntl.LOCK_EX,
            )

            metadata = os.fstat(fd)

            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                logger.error(
                    "Audit log is not a single regular file; "
                    "refusing to append"
                )
                return False

            if metadata.st_size > 100 * 1024 * 1024:
                logger.error(
                    "Audit log is too large to verify safely; "
                    "refusing to append"
                )
                return False

            last_entry = None

            if metadata.st_size:
                try:
                    tail = self._read_tail_entries_fd(
                        fd,
                        count=2,
                    )
                except Exception as exc:
                    logger.error(
                        "Could not read audit log tail: %s",
                        exc,
                    )
                    return False

                if not tail:
                    logger.error(
                        "Audit log is non-empty but has "
                        "no valid tail entry"
                    )
                    return False

                for tail_entry in tail:
                    if not self._entry_hash_valid(
                        tail_entry
                    ):
                        logger.error(
                            "Audit log tail hash is invalid; "
                            "refusing to append"
                        )
                        return False

                if (
                    len(tail) >= 2
                    and tail[-1].get("prev_hash")
                    != tail[-2].get("hash")
                ):
                    logger.error(
                        "Audit log tail chain is broken; "
                        "refusing to append"
                    )
                    return False

                last_entry = tail[-1]

                cached = _VERIFIED_HEADS.get(
                    self._cache_key()
                )

                trusted = (
                    cached is not None
                    and cached["dev"]
                    == metadata.st_dev
                    and cached["ino"]
                    == metadata.st_ino
                    and cached["size"]
                    == metadata.st_size
                    and cached["mtime_ns"]
                    == metadata.st_mtime_ns
                    and cached["hash"]
                    == last_entry.get("hash")
                )

                if not trusted:
                    # File is new to this process or changed unexpectedly.
                    # Pay the O(n) verification cost once to re-establish trust.
                    os.lseek(fd, 0, os.SEEK_SET)
                    content = b""

                    while (
                        len(content)
                        < metadata.st_size
                    ):
                        chunk = os.read(
                            fd,
                            min(
                                1024 * 1024,
                                metadata.st_size
                                - len(content),
                            ),
                        )

                        if not chunk:
                            break

                        content += chunk

                    try:
                        lines = (
                            content
                            .decode("utf-8")
                            .splitlines()
                        )
                    except UnicodeDecodeError as exc:
                        logger.error(
                            "Audit log is not valid UTF-8: %s",
                            exc,
                        )
                        return False

                    valid, full_last = (
                        self._verify_lines(lines)
                    )

                    if not valid:
                        logger.error(
                            "Audit chain is damaged; "
                            "refusing to append or run a repair"
                        )
                        _VERIFIED_HEADS.pop(
                            self._cache_key(),
                            None,
                        )
                        return False

                    last_entry = full_last
                    self._cache_head(
                        metadata,
                        last_entry,
                    )

            if (
                last_entry
                and last_entry.get("hash")
            ):
                entry["prev_hash"] = (
                    last_entry["hash"]
                )

            hash_data = {
                "timestamp": entry["timestamp"],
                "data": entry["data"],
            }

            if "prev_hash" in entry:
                hash_data["prev_hash"] = (
                    entry["prev_hash"]
                )

            hash_string = json.dumps(
                hash_data,
                sort_keys=True,
            )

            entry["hash"] = hashlib.sha256(
                hash_string.encode()
            ).hexdigest()

            os.lseek(
                fd,
                0,
                os.SEEK_END,
            )

            payload = (
                json.dumps(entry) + "\n"
            ).encode()

            written = 0

            while written < len(payload):
                amount = os.write(
                    fd,
                    payload[written:],
                )

                if amount <= 0:
                    raise OSError(
                        "audit log write made no progress"
                    )

                written += amount

            os.fsync(fd)

            self._cache_head(
                os.fstat(fd),
                entry,
            )

            logger.debug(
                "Audit log entry written "
                "(hash: %s...)",
                entry["hash"][:8],
            )

            return True

        except Exception as exc:
            logger.error(
                "Failed to write audit log: %s",
                exc,
            )
            return False

        finally:
            try:
                fcntl.flock(
                    fd,
                    fcntl.LOCK_UN,
                )
            except OSError:
                pass

            os.close(fd)

    def _verify_lines(self, lines: List[str]) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Verify parsed log lines and return the final trusted entry."""
        previous_hash = None
        last_entry = None
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                logger.error(f"Invalid JSON in audit log: {exc}")
                return False, None
            if not isinstance(entry, dict) or "timestamp" not in entry or "data" not in entry:
                logger.error("Audit log entry has an invalid structure")
                return False, None
            if previous_hash is None:
                if "prev_hash" in entry:
                    logger.error("First audit entry unexpectedly has a previous hash")
                    return False, None
            elif entry.get("prev_hash") != previous_hash:
                logger.error(
                    f"Chain broken: expected prev_hash {previous_hash}, "
                    f"got {entry.get('prev_hash')}"
                )
                return False, None
            hash_data = {"timestamp": entry["timestamp"], "data": entry["data"]}
            if "prev_hash" in entry:
                hash_data["prev_hash"] = entry["prev_hash"]
            computed = hashlib.sha256(
                json.dumps(hash_data, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("hash") != computed:
                logger.error(f"Hash mismatch in audit log entry: {entry.get('timestamp')}")
                return False, None
            previous_hash = entry["hash"]
            last_entry = entry
        return True, last_entry

    def verify_chain(self) -> bool:
        """Fully verify the entire hash chain and establish a trusted head."""
        if not self.log_path.exists():
            _VERIFIED_HEADS.pop(
                self._cache_key(),
                None,
            )
            return True

        try:
            with open(
                self.log_path,
                "r",
            ) as handle:
                lines = handle.readlines()

                if not lines:
                    _VERIFIED_HEADS.pop(
                        self._cache_key(),
                        None,
                    )
                    return True

                valid, last_entry = (
                    self._verify_lines(lines)
                )

                if valid:
                    self._cache_head(
                        os.fstat(handle.fileno()),
                        last_entry,
                    )
                else:
                    _VERIFIED_HEADS.pop(
                        self._cache_key(),
                        None,
                    )

                return valid

        except Exception as exc:
            _VERIFIED_HEADS.pop(
                self._cache_key(),
                None,
            )
            logger.error(
                "Audit log verification failed: %s",
                exc,
            )
            return False

    def read_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Read the last N entries."""
        if not self.log_path.exists():
            return []
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                entries = []
                for line in lines[-limit:]:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
                return entries
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")
            return []
