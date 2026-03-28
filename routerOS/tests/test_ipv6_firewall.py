"""IPv6 firewall and connection tracking tests.

The IPv6 firewall (firewall6.zig) tracks outbound connections and only allows
inbound traffic that matches a tracked connection. ICMPv6 errors, echo, and
NDP are always allowed.
"""

import socket
import struct
import time

import pytest

from conftest import LAN_IFACE


# Router MACs
ROUTER_WAN_MAC = b"\x52\x54\x00\x12\x34\x56"
ROUTER_LAN_MAC = b"\x52\x54\x00\x12\x34\x57"

# Router link-locals (EUI-64 from MAC)
ROUTER_WAN_LL = b"\xfe\x80" + b"\x00" * 6 + b"\x50\x54\x00\xff\xfe\x12\x34\x56"
ROUTER_LAN_LL = b"\xfe\x80" + b"\x00" * 6 + b"\x50\x54\x00\xff\xfe\x12\x34\x57"

# Test host link-locals
HOST_WAN_MAC = b"\x02\x00\x00\x00\x00\x10"
HOST_WAN_LL = b"\xfe\x80" + b"\x00" * 6 + b"\x00\x00\x00\xff\xfe\x00\x00\x10"

HOST_LAN_MAC = b"\x02\x00\x00\x00\x00\x50"
HOST_LAN_LL = b"\xfe\x80" + b"\x00" * 6 + b"\x00\x00\x00\xff\xfe\x00\x00\x50"


def raw_socket_v6(iface, timeout=3.0):
    """Create raw AF_PACKET socket for IPv6."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
    except PermissionError:
        pytest.skip("Raw socket requires CAP_NET_RAW — run with sudo")
    sock.bind((iface, 0))
    sock.settimeout(timeout)
    return sock


def compute_icmpv6_checksum(src_ip6, dst_ip6, icmpv6_data):
    """Compute ICMPv6 checksum with IPv6 pseudo-header."""
    pseudo = src_ip6 + dst_ip6 + struct.pack("!I", len(icmpv6_data)) + b"\x00\x00\x00\x3a"
    data = pseudo + icmpv6_data
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_icmpv6_echo(src_mac, src_ip6, dst_mac, dst_ip6, echo_id=0x1234, seq=1):
    """Build an ICMPv6 Echo Request."""
    eth = dst_mac + src_mac + b"\x86\xdd"
    icmpv6_body = struct.pack("!BBHHH", 128, 0, 0, echo_id, seq) + b"ping6test"
    cs = compute_icmpv6_checksum(src_ip6, dst_ip6, icmpv6_body)
    icmpv6_body = icmpv6_body[:2] + struct.pack("!H", cs) + icmpv6_body[4:]
    ipv6 = struct.pack("!IHBB", 0x60000000, len(icmpv6_body), 58, 64)
    ipv6 += src_ip6 + dst_ip6
    return eth + ipv6 + icmpv6_body


def build_ns(src_mac, src_ip6, target_ip6):
    """Build Neighbor Solicitation."""
    snm = b"\xff\x02" + b"\x00" * 9 + b"\x01\xff" + target_ip6[-3:]
    dst_mac = b"\x33\x33" + snm[-4:]
    eth = dst_mac + src_mac + b"\x86\xdd"
    icmpv6_body = struct.pack("!BBH", 135, 0, 0) + b"\x00" * 4 + target_ip6
    icmpv6_body += struct.pack("!BB", 1, 1) + src_mac
    cs = compute_icmpv6_checksum(src_ip6, snm, icmpv6_body)
    icmpv6_body = icmpv6_body[:2] + struct.pack("!H", cs) + icmpv6_body[4:]
    ipv6 = struct.pack("!IHBB", 0x60000000, len(icmpv6_body), 58, 255)
    ipv6 += src_ip6 + snm
    return eth + ipv6 + icmpv6_body


def build_udp6(src_mac, src_ip6, dst_mac, dst_ip6, src_port, dst_port, payload=b"test"):
    """Build a UDP-over-IPv6 packet."""
    eth = dst_mac + src_mac + b"\x86\xdd"
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHH", src_port, dst_port, udp_len) + b"\x00\x00" + payload
    # UDP checksum with pseudo-header
    pseudo = src_ip6 + dst_ip6 + struct.pack("!I", udp_len) + b"\x00\x00\x00\x11"
    udp_data = bytearray(struct.pack("!HHH", src_port, dst_port, udp_len) + b"\x00\x00" + payload)
    cs_data = pseudo + bytes(udp_data)
    if len(cs_data) % 2:
        cs_data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(cs_data) // 2), cs_data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    cs = (~s) & 0xFFFF
    if cs == 0:
        cs = 0xFFFF
    udp_data[6:8] = struct.pack("!H", cs)
    ipv6 = struct.pack("!IHBB", 0x60000000, len(udp_data), 17, 64)
    ipv6 += src_ip6 + dst_ip6
    return eth + ipv6 + bytes(udp_data)


class TestIpv6Firewall:
    """Test IPv6 stateful firewall."""

    def test_icmpv6_echo_always_allowed(self, router):
        """ICMPv6 echo request to router's WAN is always allowed (not filtered)."""
        sock = raw_socket_v6("tap0", timeout=3.0)
        try:
            # Resolve via NDP first
            ns = build_ns(HOST_WAN_MAC, HOST_WAN_LL, ROUTER_WAN_LL)
            sock.send(ns)
            time.sleep(0.5)

            echo = build_icmpv6_echo(HOST_WAN_MAC, HOST_WAN_LL,
                                      ROUTER_WAN_MAC, ROUTER_WAN_LL,
                                      echo_id=0xF001, seq=1)
            sock.send(echo)

            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    frame = sock.recv(1500)
                except socket.timeout:
                    break
                if len(frame) < 58:
                    continue
                if struct.unpack("!H", frame[12:14])[0] != 0x86DD:
                    continue
                if frame[20] == 58 and frame[54] == 129:  # Echo Reply
                    return  # Success
            pytest.fail("ICMPv6 echo reply not received — firewall may be blocking it")
        finally:
            sock.close()

    def test_ndp_always_allowed(self, router):
        """NDP Neighbor Solicitation is always allowed through the firewall."""
        sock = raw_socket_v6("tap0", timeout=3.0)
        try:
            ns = build_ns(HOST_WAN_MAC, HOST_WAN_LL, ROUTER_WAN_LL)
            sock.send(ns)

            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    frame = sock.recv(1500)
                except socket.timeout:
                    break
                if len(frame) < 58:
                    continue
                if struct.unpack("!H", frame[12:14])[0] != 0x86DD:
                    continue
                if frame[20] == 58 and frame[54] == 136:  # NA
                    return  # Success
            pytest.fail("NDP NA not received — firewall may be blocking NDP")
        finally:
            sock.close()

    def test_unsolicited_udp6_dropped(self, router):
        """Unsolicited inbound UDP6 on WAN should be dropped by the firewall.

        Send a UDP6 packet to the router's WAN link-local on a random port.
        The firewall should drop it since there's no matching outbound connection.
        The router must not crash.
        """
        sock = raw_socket_v6("tap0", timeout=2.0)
        try:
            # Resolve MAC first
            ns = build_ns(HOST_WAN_MAC, HOST_WAN_LL, ROUTER_WAN_LL)
            sock.send(ns)
            time.sleep(0.5)

            # Send unsolicited UDP to router
            udp = build_udp6(HOST_WAN_MAC, HOST_WAN_LL,
                              ROUTER_WAN_MAC, ROUTER_WAN_LL,
                              src_port=54321, dst_port=8888,
                              payload=b"unsolicited-udp6")
            sock.send(udp)
            time.sleep(1)
        finally:
            sock.close()

        # Router should still be responsive
        resp = router.command("version")
        assert "Zag RouterOS" in resp

    @pytest.mark.lan
    def test_icmpv6_echo_on_lan(self, router):
        """ICMPv6 echo to router's LAN link-local works (allowed by firewall)."""
        sock = raw_socket_v6(LAN_IFACE, timeout=3.0)
        try:
            ns = build_ns(HOST_LAN_MAC, HOST_LAN_LL, ROUTER_LAN_LL)
            sock.send(ns)
            time.sleep(0.5)

            echo = build_icmpv6_echo(HOST_LAN_MAC, HOST_LAN_LL,
                                      ROUTER_LAN_MAC, ROUTER_LAN_LL,
                                      echo_id=0xF002, seq=1)
            sock.send(echo)

            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    frame = sock.recv(1500)
                except socket.timeout:
                    break
                if len(frame) < 58:
                    continue
                if struct.unpack("!H", frame[12:14])[0] != 0x86DD:
                    continue
                if frame[20] == 58 and frame[54] == 129:
                    return  # Success
            pytest.fail("ICMPv6 echo reply not received on LAN")
        finally:
            sock.close()

    def test_multiple_unsolicited_packets_no_crash(self, router):
        """Multiple unsolicited IPv6 packets don't overwhelm the firewall table."""
        sock = raw_socket_v6("tap0", timeout=2.0)
        try:
            ns = build_ns(HOST_WAN_MAC, HOST_WAN_LL, ROUTER_WAN_LL)
            sock.send(ns)
            time.sleep(0.5)

            # Send several unsolicited UDP6 packets from different ports
            for port in range(50000, 50010):
                udp = build_udp6(HOST_WAN_MAC, HOST_WAN_LL,
                                  ROUTER_WAN_MAC, ROUTER_WAN_LL,
                                  src_port=port, dst_port=9999,
                                  payload=b"flood")
                sock.send(udp)
                time.sleep(0.02)
        finally:
            sock.close()

        time.sleep(1)
        resp = router.command("version")
        assert "Zag RouterOS" in resp, "Router unresponsive after IPv6 UDP flood"
