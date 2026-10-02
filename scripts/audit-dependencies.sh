#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pick_python() {
    local candidate
    for candidate in "${PYTHON:-}" "$ROOT/.test-venv/bin/python" "$ROOT/venv/bin/python" "$(command -v python3 2>/dev/null || true)"; do
        [[ -n "$candidate" && -x "$candidate" ]] || continue
        if "$candidate" -c 'import pip_audit' >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    echo "ERROR: pip-audit is not installed in an available Lattice development Python." >&2
    echo "Install the test extra first: python3 -m pip install -e '.[test]'" >&2
    return 1
}

PYTHON="$(pick_python)"
cd "$ROOT"
"$PYTHON" -m pip_audit -r requirements.lock
"$PYTHON" -m pip_audit -r requirements-build.lock
