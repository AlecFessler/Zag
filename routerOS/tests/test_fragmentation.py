"""IP fragmentation tests: verify the router handles fragmented packets.

The router's frag.zig tracks fragmented packets to reconstruct source ports
for NAT. These tests send fragmented IP packets through the router and verify
they are handled correctly.
"""

import socket
import struct
import time

import pytest

from conftest import ping_host, run_in_lan_ns, ping_from_lan_ns


def raw_socket(iface, timeout=5.0):
    """Create AF_PACKET raw socket."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except PermissionError:
        pytest.skip("Raw socket requires CAP_NET_RAW — run with sudo")
    sock.bind((iface, 0))
    sock.settimeout(timeout)
    return sock


def _checksum(data):
    """Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_icmp_echo(src_mac, src_ip, dst_mac, dst_ip, icmp_id=0x1234, seq=1,
                     payload_size=56, ttl=64):
    """Build a complete ICMP echo request."""
    eth = dst_mac + src_mac + b"\x08\x00"

    icmp_data = b"\x00" * payload_size
    icmp = struct.pack("!BBHHH", 8, 0, 0, icmp_id, seq) + icmp_data
    icmp_cs = _checksum(icmp)
    icmp = struct.pack("!BBHHH", 8, 0, icmp_cs, icmp_id, seq) + icmp_data

    total_len = 20 + len(icmp)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0xABCD, 0x4000, ttl, 1, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_hdr = bytearray(ip_hdr)
    cs = _checksum(bytes(ip_hdr))
    ip_hdr[10:12] = struct.pack("!H", cs)

    return eth + bytes(ip_hdr) + icmp


def build_ip_fragment(src_mac, src_ip, dst_mac, dst_ip, ip_id, protocol,
                       payload, frag_offset, more_fragments=True, ttl=64):
    """Build a single IP fragment.

    frag_offset is in 8-byte units.
    """
    eth = dst_mac + src_mac + b"\x08\x00"

    flags_frag = (frag_offset & 0x1FFF)
    if more_fragments:
        flags_frag |= 0x2000  # MF bit

    total_len = 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, ip_id, flags_frag, ttl, protocol, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_hdr = bytearray(ip_hdr)
    cs = _checksum(bytes(ip_hdr))
    ip_hdr[10:12] = struct.pack("!H", cs)

    return eth + bytes(ip_hdr) + payload


class TestFragmentation:
    """Test IP fragment handling."""

    def test_large_ping_no_crash(self, router, router_wan_ip):
        """Large ping (with DF=0 so it may fragment) doesn't crash the router."""
        # Send a large ping that fits in one packet but exercises size handling
        from conftest import run_on_host
        result = run_on_host(
            ["ping", "-c", "1", "-W", "3", "-s", "1400", "-I", "tap0", router_wan_ip],
            timeout=10,
        )
        # Router should still be responsive
        resp = router.command("version")
        assert "Zag RouterOS" in resp

    def test_fragmented_icmp_to_router(self, router, router_wan_ip, wan_ip):
        """Send a fragmented ICMP echo to the router — it should not crash.

        The router's frag table tracks fragments. Even if reassembly isn't
        full, the router must not panic on receiving fragments.
        """
        sock = raw_socket("tap0", timeout=3.0)
        try:
            src_mac = b"\x02\x00\x00\x00\x00\x10"
            dst_mac = b"\x52\x54\x00\x12\x34\x56"
            ip_id = 0xBEEF

            # ICMP echo request header (8 bytes) + 32 bytes payload
            icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, 0x5678, 1) + b"\xAA" * 32
            icmp_cs = _checksum(icmp_hdr)
            icmp_hdr = struct.pack("!BBHHH", 8, 0, icmp_cs, 0x5678, 1) + b"\xAA" * 32

            # Fragment 1: first 24 bytes (must be multiple of 8)
            frag1 = build_ip_fragment(src_mac, wan_ip, dst_mac, router_wan_ip,
                                       ip_id, 1, icmp_hdr[:24], frag_offset=0,
                                       more_fragments=True)
            # Fragment 2: remaining 16 bytes
            frag2 = build_ip_fragment(src_mac, wan_ip, dst_mac, router_wan_ip,
                                       ip_id, 1, icmp_hdr[24:], frag_offset=3,
                                       more_fragments=False)

            sock.send(frag1)
            time.sleep(0.1)
            sock.send(frag2)
            time.sleep(0.5)
        finally:
            sock.close()

        # Router must still be responsive
        resp = router.command("version")
        assert "Zag RouterOS" in resp, f"Router unresponsive after fragments: {resp}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_frag_needed_on_oversized_df(self, router, wan_ip):
        """Oversized packet with DF bit through the router triggers ICMP frag needed
        or is silently dropped — either way the router must not crash.
        """
        result = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "3", "-M", "do", "-s", "1473", wan_ip],
            timeout=8,
        )
        # The ping may fail (frag needed or just dropped), that's fine
        # Verify router is still alive
        resp = router.command("version")
        assert "Zag RouterOS" in resp

    def test_multiple_fragment_ids(self, router, router_wan_ip, wan_ip):
        """Multiple concurrent fragmented packets with different IDs don't confuse
        the fragment table.
        """
        sock = raw_socket("tap0", timeout=3.0)
        try:
            src_mac = b"\x02\x00\x00\x00\x00\x10"
            dst_mac = b"\x52\x54\x00\x12\x34\x56"

            # Send fragments from two different "packets" (different IP IDs)
            for ip_id in [0xAAAA, 0xBBBB]:
                payload = b"\x00" * 24  # 3 * 8 bytes
                frag = build_ip_fragment(src_mac, wan_ip, dst_mac, router_wan_ip,
                                          ip_id, 17, payload, frag_offset=0,
                                          more_fragments=True)
                sock.send(frag)
                time.sleep(0.05)
        finally:
            sock.close()

        time.sleep(0.5)
        resp = router.command("version")
        assert "Zag RouterOS" in resp, "Router crashed after multiple fragment IDs"
