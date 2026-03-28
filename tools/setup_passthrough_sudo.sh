#!/usr/bin/env bash
set -euo pipefail

# Add sudoers rules for passthrough testing without password prompts.
# Run once with: sudo tools/setup_passthrough_sudo.sh

USER="${SUDO_USER:-$USER}"
RULES_FILE="/etc/sudoers.d/zag-passthrough"

cat > "$RULES_FILE" <<EOF
# Zag x550 passthrough testing
$USER ALL=(root) NOPASSWD: /home/$USER/Zag/tools/vfio-bind.sh
$USER ALL=(root) NOPASSWD: /home/$USER/Zag/tools/vfio-unbind.sh
$USER ALL=(root) NOPASSWD: /home/$USER/Zag/tools/test_passthrough.sh
$USER ALL=(root) NOPASSWD: /usr/bin/qemu-system-x86_64
$USER ALL=(root) NOPASSWD: /usr/bin/tcpdump
$USER ALL=(root) NOPASSWD: /usr/bin/ip
$USER ALL=(root) NOPASSWD: /usr/bin/kill
$USER ALL=(root) NOPASSWD: /usr/bin/cat
$USER ALL=(root) NOPASSWD: /usr/bin/tail
$USER ALL=(root) NOPASSWD: /usr/bin/grep
$USER ALL=(root) NOPASSWD: /usr/bin/timeout
$USER ALL=(root) NOPASSWD: /usr/bin/rm
$USER ALL=(root) NOPASSWD: /home/$USER/Zag/tools/passthrough_tests/.venv/bin/python3
EOF

chmod 0440 "$RULES_FILE"
visudo -cf "$RULES_FILE"
echo "Sudoers rules installed at $RULES_FILE"
echo "You can now run: ./test.sh passthrough (without password prompts)"
