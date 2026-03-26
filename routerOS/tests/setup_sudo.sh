#!/bin/bash
# One-time privileged setup for e2e tests.
# Run ONCE with: sudo ./routerOS/tests/setup_sudo.sh
#
# After this, tests run without sudo forever (survives reboots).
set -euo pipefail

USER_HOME="${SUDO_USER:+$(eval echo ~$SUDO_USER)}"
REPO="${USER_HOME:-$HOME}/Zag"
VENV_PYTHON="$REPO/routerOS/tests/.venv/bin/python3"
REAL_USER="${SUDO_USER:-$USER}"

echo "=== RouterOS E2E sudo setup ==="

# ── Create persistent LAN test namespace ────────────────────────────
# systemd-networkd style: /etc/netns persists across reboots
ip netns del lan_test 2>/dev/null || true
echo "Creating lan_test namespace..."
ip netns add lan_test
ip netns exec lan_test ip link set lo up

# Make it survive reboots via a systemd service
cat > /etc/systemd/system/zag-lan-netns.service <<EOF
[Unit]
Description=Zag RouterOS test namespace (lan_test)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/ip netns add lan_test
ExecStart=/usr/bin/ip netns exec lan_test ip link set lo up
ExecStop=/usr/bin/ip netns del lan_test

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable zag-lan-netns.service
echo "Installed systemd service for persistent namespace"

# ── Set capabilities on venv Python ─────────────────────────────────
if [ -f "$VENV_PYTHON" ]; then
    setcap 'cap_net_raw,cap_net_bind_service,cap_net_admin=+ep' "$VENV_PYTHON"
    echo "Set capabilities on $VENV_PYTHON"
else
    echo "Warning: $VENV_PYTHON not found — create the venv first"
fi

# ── Allow user to run privileged network commands without password ───
SUDOERS_FILE="/etc/sudoers.d/zag-e2e-tests"
cat > "$SUDOERS_FILE" <<EOF
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/ip *
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/ping *
EOF
chmod 0440 "$SUDOERS_FILE"
echo "Added sudoers rules for ip and ping"

echo ""
echo "=== Setup complete ==="
echo "This is a one-time setup. Tests now run without sudo:"
echo "  routerOS/tests/.venv/bin/pytest routerOS/tests/ -v"
