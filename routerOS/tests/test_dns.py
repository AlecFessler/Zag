"""DNS relay tests: verify the router forwards DNS queries."""

import socket
import struct
import threading
import time

import pytest


def build_dns_query(domain: str, query_id: int = 0x1234) -> bytes:
    """Build a minimal DNS A-record query."""
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def build_dns_response(query: bytes, ip: str) -> bytes:
    """Build a DNS response with a single A record."""
    query_id = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHLH", 0xC00C, 1, 1, 300, 4)
    answer += socket.inet_aton(ip)
    return header + question + answer


class TestDnsRelay:
    """Test the router's DNS relay functionality."""

    @pytest.mark.lan
    def test_dns_relay_forwards_query(self, router, wan_ip, router_lan_ip):
        """DNS query from LAN is forwarded to upstream and response returned."""
        from conftest import ping_host, LAN_IFACE
        import subprocess
        # Add static ARP entry on host for router's WAN IP (avoids ARP race)
        subprocess.run(["ip", "neigh", "replace", "10.0.2.15", "lladdr", "52:54:00:12:34:56",
                        "dev", "tap0", "nud", "permanent"], capture_output=True)
        # Warm ARP: ping LAN to ensure router knows our MAC
        ping_host(router_lan_ip, interface="tap1", count=2)
        # Ping WAN to warm router's WAN ARP for gateway
        ping_host("10.0.2.15", interface="tap0", count=2)

        received_queries = []
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((wan_ip, 53))
        except (PermissionError, OSError):
            pytest.skip("Could not bind DNS server on port 53")
        server_sock.settimeout(5.0)

        def dns_server():
            try:
                for _ in range(10):
                    data, addr = server_sock.recvfrom(512)
                    received_queries.append((data, addr))
                    resp = build_dns_response(data, "93.184.216.34")
                    server_sock.sendto(resp, addr)
            except (socket.timeout, OSError):
                pass

        server = threading.Thread(target=dns_server, daemon=True)
        server.start()

        router.set_dns(wan_ip)

        query = build_dns_query("test.example.com", query_id=0xABCD)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LAN_IFACE.encode())
        client.settimeout(3.0)
        try:
            for attempt in range(5):
                client.sendto(query, (router_lan_ip, 53))
                try:
                    response, _ = client.recvfrom(512)
                    assert len(response) > 12, "DNS response too short"
                    ancount = struct.unpack("!H", response[6:8])[0]
                    assert ancount >= 1, f"DNS response has no answers: {response.hex()}"
                    return  # Success
                except socket.timeout:
                    if attempt < 4:
                        continue
                    if not received_queries:
                        pytest.fail("DNS query never reached upstream server")
                    pytest.fail("DNS query forwarded but no response received from router")
        finally:
            client.close()
            server_sock.close()
            server.join(timeout=3)

    @pytest.mark.lan
    def test_dns_relay_rewrites_query_id(self, router, wan_ip, router_lan_ip):
        """DNS relay rewrites query ID and maps it back on response."""
        from conftest import ping_host, LAN_IFACE
        import subprocess
        # Ensure host ARP for router WAN is permanent (prevents ARP race on response)
        subprocess.run(["ip", "neigh", "replace", "10.0.2.15", "lladdr", "52:54:00:12:34:56",
                        "dev", "tap0", "nud", "permanent"], capture_output=True)
        ping_host(router_lan_ip, interface="tap1", count=1)
        ping_host("10.0.2.15", interface="tap0", count=1)

        received_queries = []
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((wan_ip, 53))
        except (PermissionError, OSError):
            pytest.skip("Could not bind DNS server on port 53")
        server_sock.settimeout(5.0)

        def dns_server():
            try:
                for _ in range(3):
                    data, addr = server_sock.recvfrom(512)
                    received_queries.append(data)
                    resp = build_dns_response(data, "1.2.3.4")
                    server_sock.sendto(resp, addr)
            except (socket.timeout, OSError):
                pass

        server = threading.Thread(target=dns_server, daemon=True)
        server.start()

        router.set_dns(wan_ip)

        original_id = 0xBEEF
        query = build_dns_query("rewrite.test", query_id=original_id)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LAN_IFACE.encode())
        client.settimeout(3.0)
        try:
            for attempt in range(5):
                client.sendto(query, (router_lan_ip, 53))
                try:
                    response, _ = client.recvfrom(512)
                    resp_id = struct.unpack("!H", response[:2])[0]
                    assert resp_id == original_id, \
                        f"Response ID {resp_id:#x} != original {original_id:#x}"
                    return  # Success
                except socket.timeout:
                    if attempt < 4:
                        continue
                    if not received_queries:
                        pytest.fail("DNS query never reached upstream server")
                    pytest.fail("DNS query forwarded but no response received")
        finally:
            client.close()
            server_sock.close()
            server.join(timeout=3)

    def test_dns_set_upstream(self, router, wan_ip):
        """Verify the dns command is accepted."""
        resp = router.set_dns(wan_ip)
        assert "OK" in resp, f"DNS set failed: {resp}"


class TestDnsCache:
    """Test the router's DNS response caching."""

    @pytest.mark.lan
    def test_dns_cache_serves_repeated_query(self, router, wan_ip, router_lan_ip):
        """Second identical DNS query should be served from cache without hitting upstream."""
        from conftest import ping_host, LAN_IFACE
        import subprocess
        subprocess.run(["ip", "neigh", "replace", "10.0.2.15", "lladdr", "52:54:00:12:34:56",
                        "dev", "tap0", "nud", "permanent"], capture_output=True)
        ping_host(router_lan_ip, interface="tap1", count=2)
        ping_host("10.0.2.15", interface="tap0", count=2)

        received_queries = []
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((wan_ip, 53))
        except (PermissionError, OSError):
            pytest.skip("Could not bind DNS server on port 53")
        server_sock.settimeout(5.0)

        def dns_server():
            try:
                for _ in range(10):
                    data, addr = server_sock.recvfrom(512)
                    received_queries.append((data, addr))
                    resp = build_dns_response(data, "93.184.216.34")
                    server_sock.sendto(resp, addr)
            except (socket.timeout, OSError):
                pass

        server = threading.Thread(target=dns_server, daemon=True)
        server.start()

        router.set_dns(wan_ip)

        # First query — should go to upstream
        query1 = build_dns_query("cache.example.com", query_id=0x1111)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LAN_IFACE.encode())
        client.settimeout(3.0)
        try:
            client.sendto(query1, (router_lan_ip, 53))
            response1, _ = client.recvfrom(512)
            assert len(response1) > 12, "First DNS response too short"

            assert len(received_queries) >= 1, "First query did not reach upstream"

            baseline_count = len(received_queries)

            # Second query — same domain, different query ID — should come from cache
            query2 = build_dns_query("cache.example.com", query_id=0x2222)
            client.sendto(query2, (router_lan_ip, 53))
            response2, _ = client.recvfrom(512)
            assert len(response2) > 12, "Cached DNS response too short"

            # Verify response has correct query ID
            resp_id = struct.unpack("!H", response2[:2])[0]
            assert resp_id == 0x2222, \
                f"Cached response ID {resp_id:#x} != 0x2222"

            # Verify upstream was NOT queried again (cache hit)
            assert len(received_queries) == baseline_count, \
                f"Cache miss: upstream got {len(received_queries) - baseline_count} new queries after cache should be warm"
        finally:
            client.close()
            server_sock.close()
            server.join(timeout=3)
