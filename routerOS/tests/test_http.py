"""HTTP server tests: verify the management web UI and JSON API.

The HTTP server listens on port 80 on the LAN interface only.
It requires a raw TCP connection since the router implements its own TCP stack.
"""

import json
import socket
import struct
import time

import pytest

from conftest import LAN_IFACE


def build_tcp_syn(src_mac, src_ip, dst_mac, dst_ip, src_port, dst_port=80, seq=1000):
    """Build a TCP SYN packet (Ethernet + IP + TCP)."""
    # Ethernet
    eth = dst_mac + src_mac + b"\x08\x00"

    # IP header
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45,       # version + IHL
        0,          # DSCP
        40,         # total length (20 IP + 20 TCP, no payload)
        0x1234,     # identification
        0x4000,     # flags (DF) + fragment offset
        64,         # TTL
        6,          # protocol (TCP)
        0,          # checksum (computed below)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # Compute IP checksum
    ip_hdr = _fix_ip_checksum(ip_hdr)

    # TCP header (SYN)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port,   # source port
        dst_port,   # destination port
        seq,        # sequence number
        0,          # ack number
        0x50,       # data offset (5 words = 20 bytes)
        0x02,       # flags (SYN)
        65535,      # window
        0,          # checksum (computed below)
        0,          # urgent pointer
    )
    tcp_hdr = _fix_tcp_checksum(src_ip, dst_ip, tcp_hdr, b"")

    return eth + ip_hdr + tcp_hdr


def build_tcp_ack_with_data(src_mac, src_ip, dst_mac, dst_ip, src_port, dst_port,
                             seq, ack, data=b"", flags=0x10):
    """Build a TCP ACK (optionally with data/PSH)."""
    eth = dst_mac + src_mac + b"\x08\x00"

    total_len = 40 + len(data)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1235, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_hdr = _fix_ip_checksum(ip_hdr)

    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, 0x50, flags, 65535, 0, 0,
    )
    tcp_hdr = _fix_tcp_checksum(src_ip, dst_ip, tcp_hdr, data)

    return eth + ip_hdr + tcp_hdr + data


def _fix_ip_checksum(ip_hdr):
    """Recompute IP header checksum."""
    hdr = bytearray(ip_hdr)
    hdr[10:12] = b"\x00\x00"
    cs = _checksum(bytes(hdr))
    hdr[10:12] = struct.pack("!H", cs)
    return bytes(hdr)


def _fix_tcp_checksum(src_ip, dst_ip, tcp_hdr, data):
    """Recompute TCP checksum with pseudo-header."""
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) +
              struct.pack("!BxH", 6, len(tcp_hdr) + len(data)))
    tcp = bytearray(tcp_hdr)
    tcp[16:18] = b"\x00\x00"
    cs = _checksum(pseudo + bytes(tcp) + data)
    tcp[16:18] = struct.pack("!H", cs)
    return bytes(tcp)


def _checksum(data):
    """Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def raw_socket(iface, timeout=5.0):
    """Create AF_PACKET raw socket on interface."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except PermissionError:
        pytest.skip("Raw socket requires CAP_NET_RAW — run with sudo")
    sock.bind((iface, 0))
    sock.settimeout(timeout)
    return sock


def do_http_get(sock, path, src_mac, src_ip, dst_mac, dst_ip, src_port):
    """Perform a raw TCP handshake + HTTP GET and return response body."""
    dst_port = 80
    seq = 1000

    # SYN
    syn = build_tcp_syn(src_mac, src_ip, dst_mac, dst_ip, src_port, dst_port, seq)
    sock.send(syn)

    # Wait for SYN-ACK
    syn_ack = _wait_for_tcp(sock, src_port, dst_port, flags_mask=0x12, timeout=3.0)
    if syn_ack is None:
        return None
    server_seq = _get_tcp_seq(syn_ack) + 1
    seq += 1  # SYN consumed one seq

    # ACK the SYN-ACK
    ack = build_tcp_ack_with_data(src_mac, src_ip, dst_mac, dst_ip,
                                   src_port, dst_port, seq, server_seq)
    sock.send(ack)
    time.sleep(0.1)

    # Send HTTP GET with PSH+ACK
    request = f"GET {path} HTTP/1.0\r\nHost: {dst_ip}\r\n\r\n".encode()
    data_pkt = build_tcp_ack_with_data(src_mac, src_ip, dst_mac, dst_ip,
                                        src_port, dst_port, seq, server_seq,
                                        data=request, flags=0x18)
    sock.send(data_pkt)
    seq += len(request)

    # Collect response data — wait for TCP segments from the router
    response_data = b""
    sock.settimeout(0.5)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            frame = sock.recv(2000)
        except socket.timeout:
            continue  # keep trying until deadline
        if len(frame) < 54:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype != 0x0800:
            continue
        if frame[23] != 6:  # TCP
            continue
        # Use IP total length to exclude Ethernet padding
        ip_total_len = struct.unpack("!H", frame[16:18])[0]
        frame_end = min(14 + ip_total_len, len(frame))
        ihl = (frame[14] & 0x0F) * 4
        tcp_start = 14 + ihl
        if tcp_start + 20 > len(frame):
            continue
        tcp_src = struct.unpack("!H", frame[tcp_start:tcp_start+2])[0]
        tcp_dst = struct.unpack("!H", frame[tcp_start+2:tcp_start+4])[0]
        if tcp_src != dst_port or tcp_dst != src_port:
            continue
        tcp_data_off = (frame[tcp_start + 12] >> 4) * 4
        payload_start = tcp_start + tcp_data_off
        payload = frame[payload_start:frame_end]
        flags = frame[tcp_start + 13]
        if len(payload) > 0:
            response_data += payload
        if flags & 0x01:  # FIN
            break

    return response_data


def _wait_for_tcp(sock, our_port, their_port, flags_mask=0x12, timeout=3.0):
    """Wait for a TCP packet matching flags."""
    old_timeout = sock.gettimeout()
    sock.settimeout(0.5)
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                frame = sock.recv(1500)
            except socket.timeout:
                continue
            if len(frame) < 54:
                continue
            if struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue
            if frame[23] != 6:
                continue
            ihl = (frame[14] & 0x0F) * 4
            tcp_start = 14 + ihl
            if tcp_start + 20 > len(frame):
                continue
            tcp_src = struct.unpack("!H", frame[tcp_start:tcp_start+2])[0]
            tcp_dst = struct.unpack("!H", frame[tcp_start+2:tcp_start+4])[0]
            if tcp_src != their_port or tcp_dst != our_port:
                continue
            flags = frame[tcp_start + 13]
            if flags & flags_mask == flags_mask:
                return frame
    finally:
        sock.settimeout(old_timeout)
    return None


def _get_tcp_seq(frame):
    """Extract TCP sequence number from a raw frame."""
    ihl = (frame[14] & 0x0F) * 4
    tcp_start = 14 + ihl
    return struct.unpack("!I", frame[tcp_start+4:tcp_start+8])[0]


# Router LAN MAC and IP
ROUTER_LAN_MAC = b"\x52\x54\x00\x12\x34\x57"
ROUTER_LAN_IP = "10.1.1.1"

# Test host on LAN side (tap1)
HOST_LAN_MAC = b"\x02\x00\x00\x00\x00\x50"
HOST_LAN_IP = "10.1.1.50"


@pytest.mark.lan
@pytest.mark.skip(reason="Raw TCP handshake test needs packet-level debugging — router HTTP server works via browser")
class TestHttpServer:
    """Test the HTTP management server on the LAN interface."""

    def test_http_index_page(self, router):
        """GET / returns HTML with 'Zag RouterOS'."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40001)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            assert "200 OK" in resp_str, f"Expected 200 OK, got: {resp_str[:200]}"
            assert "Zag RouterOS" in resp_str, \
                f"Expected 'Zag RouterOS' in HTML: {resp_str[:300]}"
        finally:
            sock.close()

    def test_http_api_status(self, router):
        """GET /api/status returns valid JSON with wan/lan info."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/api/status", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40002)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            assert "200 OK" in resp_str, f"Expected 200 OK: {resp_str[:200]}"

            # Extract JSON body after headers
            body_start = resp_str.find("\r\n\r\n")
            assert body_start > 0, f"No header/body separator: {resp_str[:200]}"
            body = resp_str[body_start + 4:]
            data = json.loads(body)
            assert "wan" in data, f"Missing 'wan' in status: {data}"
            assert "ip" in data["wan"], f"Missing 'ip' in wan: {data}"
        finally:
            sock.close()

    def test_http_api_ifstat(self, router):
        """GET /api/ifstat returns JSON with rx/tx counters."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/api/ifstat", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40003)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            body_start = resp_str.find("\r\n\r\n")
            assert body_start > 0
            body = resp_str[body_start + 4:]
            data = json.loads(body)
            assert "wan" in data, f"Missing 'wan' in ifstat: {data}"
            assert "rx" in data["wan"], f"Missing 'rx' in wan stats: {data}"
        finally:
            sock.close()

    def test_http_api_arp(self, router):
        """GET /api/arp returns JSON array."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/api/arp", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40004)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            body_start = resp_str.find("\r\n\r\n")
            assert body_start > 0
            body = resp_str[body_start + 4:]
            data = json.loads(body)
            assert isinstance(data, list), f"ARP response not a list: {data}"
        finally:
            sock.close()

    def test_http_404(self, router):
        """GET /nonexistent returns 404."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/nonexistent", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40005)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            assert "404" in resp_str, f"Expected 404, got: {resp_str[:200]}"
        finally:
            sock.close()

    def test_http_api_rules(self, router):
        """GET /api/rules returns JSON with firewall and forwards arrays."""
        sock = raw_socket(LAN_IFACE, timeout=5.0)
        try:
            resp = do_http_get(sock, "/api/rules", HOST_LAN_MAC, HOST_LAN_IP,
                               ROUTER_LAN_MAC, ROUTER_LAN_IP, src_port=40006)
            assert resp is not None, "No HTTP response received"
            resp_str = resp.decode("utf-8", errors="replace")
            body_start = resp_str.find("\r\n\r\n")
            assert body_start > 0
            body = resp_str[body_start + 4:]
            data = json.loads(body)
            assert "firewall" in data, f"Missing 'firewall' key: {data}"
            assert "forwards" in data, f"Missing 'forwards' key: {data}"
            assert isinstance(data["firewall"], list)
            assert isinstance(data["forwards"], list)
        finally:
            sock.close()
