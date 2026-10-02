#!/bin/bash
# Smoke test: verify the selected Lattice role and restricted recovery permissions.
set -uo pipefail
PASS=0
FAIL=0
ROLE_FILE=/etc/lattice/role
LATTICE_USER=lattice

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run this smoke test as root so lattice-account permissions are tested accurately" >&2
    exit 2
fi

fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }

run_as_lattice() {
    if [[ "$(id -u)" -eq 0 ]]; then
        runuser -u "$LATTICE_USER" -- "$@"
    else
        "$@"
    fi
}

echo "=== Lattice smoke test ==="

echo "--- selected role ---"
if [[ ! -r "$ROLE_FILE" ]]; then
    fail "$ROLE_FILE is missing or unreadable"
    ROLE=""
else
    ROLE=$(tr -d '[:space:]' < "$ROLE_FILE")
    [[ "$ROLE" == "master" || "$ROLE" == "worker" ]] && pass "role is $ROLE" || fail "invalid role '$ROLE'"
fi

echo ""
echo "--- systemd service states ---"
if systemctl is-active --quiet lattice-init.service; then
    pass "lattice-init.service is active (successful preparation retained)"
else
    fail "lattice-init.service is NOT active"
fi

if [[ "$ROLE" == "master" ]]; then
    SELECTED=lattice-master.service
    OPPOSITE=lattice-worker.service
elif [[ "$ROLE" == "worker" ]]; then
    SELECTED=lattice-worker.service
    OPPOSITE=lattice-master.service
else
    SELECTED=""
    OPPOSITE=""
fi

if [[ -n "$SELECTED" ]]; then
    systemctl is-active --quiet "$SELECTED" && pass "$SELECTED is active" || fail "$SELECTED is NOT active"
    if systemctl is-active --quiet "$OPPOSITE"; then
        fail "$OPPOSITE is active but must be inactive for role '$ROLE'"
    else
        pass "$OPPOSITE is inactive as required"
    fi
fi

echo ""
echo "--- operator command ---"
if [[ -L /usr/local/bin/lattice \
      && "$(readlink /usr/local/bin/lattice 2>/dev/null || true)" == "/opt/lattice/venv/bin/lattice" ]]; then
    pass "/usr/local/bin/lattice is the managed Lattice launcher"
    if /usr/local/bin/lattice --version >/dev/null 2>&1; then
        pass "lattice operator command starts successfully"
    else
        fail "lattice operator command could not start"
    fi
else
    fail "/usr/local/bin/lattice is missing or not Lattice-managed"
fi

echo ""
echo "--- sudoers rule ---"
if [[ -f /etc/sudoers.d/lattice-action-exec ]]; then
    pass "/etc/sudoers.d/lattice-action-exec exists"
    if visudo -c -f /etc/sudoers.d/lattice-action-exec >/dev/null 2>&1; then
        pass "sudoers rule is syntactically valid"
    else
        fail "sudoers rule is INVALID"
    fi
else
    fail "/etc/sudoers.d/lattice-action-exec MISSING"
fi

echo ""
echo "--- lattice-action-exec permissions ---"
HELPER=/opt/lattice/bin/lattice-action-exec
if [[ -x "$HELPER" ]]; then
    pass "$HELPER is executable"

    OUTPUT=$(run_as_lattice sudo -n "$HELPER" status lattice-worker.service 2>&1 || true)
    if echo "$OUTPUT" | grep -qE "OK: |active|inactive"; then
        pass "restricted helper status command is allowed for lattice"
    else
        fail "restricted helper status command failed (got: $OUTPUT)"
    fi

    OUTPUT=$(run_as_lattice sudo -n "$HELPER" restart sshd 2>&1 || true)
    if echo "$OUTPUT" | grep -q "REFUSED"; then
        pass "restricted helper refuses hard-no target sshd"
    else
        fail "restricted helper did NOT refuse sshd (got: $OUTPUT)"
    fi

    # Harmless negative test: direct systemctl via sudo must be denied for lattice.
    if run_as_lattice sudo -n /usr/bin/systemctl is-active lattice-worker.service >/dev/null 2>&1; then
        fail "broad sudo is allowed for lattice - security regression"
    else
        pass "broad sudo is blocked for lattice"
    fi
else
    fail "$HELPER is missing or not executable"
fi

echo ""
echo "--- runtime directories ---"
for dir in /var/lib/lattice /var/log/lattice /run/lattice /etc/lattice; do
    [[ -d "$dir" ]] && pass "$dir exists" || fail "$dir MISSING"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
