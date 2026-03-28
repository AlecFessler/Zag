#!/usr/bin/env bash
set -euo pipefail

# Intel x550-T2 dual port NIC
X550_LAN="enp5s0f0"   # Port 1: connected to dumb switch with Pis
X550_WAN="enp5s0f1"   # Port 2: loopback cable to Realtek

# Built-in Realtek NIC (ISP gateway simulator)
REALTEK="eno1"

echo "=== Setting up physical test network ==="

# LAN side: x550 port 1 on the same subnet as the Pis
sudo ip addr add 192.168.1.50/24 dev "$X550_LAN" 2>/dev/null || echo "  $X550_LAN already has 192.168.1.50/24"
sudo ip link set "$X550_LAN" up

# WAN side: x550 port 2 as the router's WAN interface
sudo ip addr add 10.0.2.15/24 dev "$X550_WAN" 2>/dev/null || echo "  $X550_WAN already has 10.0.2.15/24"
sudo ip link set "$X550_WAN" up

# ISP simulator: Realtek acts as the default gateway on WAN
sudo ip addr add 10.0.2.1/24 dev "$REALTEK" 2>/dev/null || echo "  $REALTEK already has 10.0.2.1/24"
sudo ip link set "$REALTEK" up

# Both x550 WAN and Realtek are on the same host on the same subnet (10.0.2.0/24).
# Without separate routing tables, the kernel routes locally and never sends packets
# out the wire. Policy routing forces each interface to use the physical link.
sudo ip rule add from 10.0.2.15 table 100 2>/dev/null || true
sudo ip route replace 10.0.2.0/24 dev "$X550_WAN" table 100
sudo ip rule add from 10.0.2.1 table 101 2>/dev/null || true
sudo ip route replace 10.0.2.0/24 dev "$REALTEK" table 101

# Disable reverse path filtering so packets arriving on the "wrong" interface aren't dropped
sudo sysctl -q -w net.ipv4.conf."$X550_WAN".rp_filter=0
sudo sysctl -q -w net.ipv4.conf."$REALTEK".rp_filter=0
sudo sysctl -q -w net.ipv4.conf.all.rp_filter=0

echo ""
echo "=== Verifying LAN segment (Pis) ==="
ping -c 2 -W 2 -I "$X550_LAN" 192.168.1.101 && echo "  Pi 1 OK" || echo "  Pi 1 unreachable"
ping -c 2 -W 2 -I "$X550_LAN" 192.168.1.102 && echo "  Pi 2 OK" || echo "  Pi 2 unreachable"
ping -c 2 -W 2 -I "$X550_LAN" 192.168.1.103 && echo "  Pi 3 OK" || echo "  Pi 3 unreachable"

echo ""
echo "=== Verifying WAN loopback ==="
ping -c 2 -W 2 -I 10.0.2.15 10.0.2.1 && echo "  Realtek loopback OK" || echo "  Realtek loopback unreachable"

echo ""
echo "=== To monitor UDP traffic from Pis ==="
echo "  sudo tcpdump -i $X550_LAN udp port 9999"
