#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/venv/bin/python}"
PIP_COMPILE="${PIP_COMPILE:-$ROOT/venv/bin/pip-compile}"
[[ -x "$PIP_COMPILE" ]] || { echo "ERROR: install pip-tools in the development venv first" >&2; exit 1; }
cd "$ROOT"
"$PYTHON" - <<'PY'
try:
    import tomllib
except ImportError:
    import tomli as tomllib
from pathlib import Path
with open("pyproject.toml", "rb") as handle:
    deps = tomllib.load(handle)["project"]["dependencies"]
Path("requirements.in").write_text("\n".join(deps) + "\n")
PY
"$PIP_COMPILE" requirements.in --generate-hashes --output-file=requirements.lock
"$PIP_COMPILE" requirements-build.in --generate-hashes --output-file=requirements-build.lock
