#!/usr/bin/env bash
set -euo pipefail

X550_LAN="enp5s0f0"
X550_WAN="enp5s0f1"
REALTEK="eno1"

echo "=== Tearing down physical test network ==="

sudo ip addr del 192.168.1.50/24 dev "$X550_LAN" 2>/dev/null || true
sudo ip addr del 10.0.2.15/24 dev "$X550_WAN" 2>/dev/null || true
sudo ip addr del 10.0.2.1/24 dev "$REALTEK" 2>/dev/null || true

sudo ip rule del from 10.0.2.15 table 100 2>/dev/null || true
sudo ip route flush table 100 2>/dev/null || true
sudo ip rule del from 10.0.2.1 table 101 2>/dev/null || true
sudo ip route flush table 101 2>/dev/null || true

echo "Done. IPs and routing rules removed from $X550_LAN, $X550_WAN, $REALTEK"

