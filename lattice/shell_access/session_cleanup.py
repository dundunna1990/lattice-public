"""Terminate authenticated sessions owned by the dedicated Lattice shell sshd."""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time

from lattice.core.config import load_config

_PID_RE = re.compile(r"pid=(\d+)")


def _session_pids(port: int) -> set[int]:
    result = subprocess.run(
        ["ss", "-Htnp", f"sport = :{int(port)}"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError((result.stderr or result.stdout or "ss failed").strip())
    return {
        int(match.group(1))
        for match in _PID_RE.finditer(result.stdout)
        if int(match.group(1)) != os.getpid()
    }


def terminate_dedicated_shell_sessions(port: int) -> int:
    pids = _session_pids(port)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if pids:
        time.sleep(0.2)
    survivors = _session_pids(port) & pids
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return len(pids)


def main() -> int:
    terminate_dedicated_shell_sessions(load_config().shell_access.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
