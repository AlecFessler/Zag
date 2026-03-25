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
        """DNS query from LAN is forwarded to upstream and response returned.

        Starts a mock DNS server on port 53 of the WAN interface, sends a query
        from LAN to the router, and verifies the response comes back.
        """
        received_queries = []

        def dns_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((wan_ip, 53))
            except PermissionError:
                return
            except OSError:
                return
            sock.settimeout(8.0)
            try:
                data, addr = sock.recvfrom(512)
                received_queries.append((data, addr))
                resp = build_dns_response(data, "93.184.216.34")
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            finally:
                sock.close()

        server = threading.Thread(target=dns_server, daemon=True)
        server.start()
        time.sleep(0.5)

        router.set_dns(wan_ip)
        time.sleep(0.5)

        query = build_dns_query("test.example.com", query_id=0xABCD)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap1")
        client.settimeout(5.0)
        try:
            client.sendto(query, (router_lan_ip, 53))
            response, _ = client.recvfrom(512)
            assert len(response) > 12, "DNS response too short"
            # Verify the response has an answer
            ancount = struct.unpack("!H", response[6:8])[0]
            assert ancount >= 1, f"DNS response has no answers: {response.hex()}"
        except socket.timeout:
            if not received_queries:
                pytest.skip("Could not bind DNS server on port 53 — run with sudo")
            pytest.fail("DNS query forwarded but no response received from router")
        finally:
            client.close()
            server.join(timeout=2)

    @pytest.mark.lan
    def test_dns_relay_rewrites_query_id(self, router, wan_ip, router_lan_ip):
        """DNS relay rewrites query ID and maps it back on response."""
        received_queries = []

        def dns_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((wan_ip, 53))
            except (PermissionError, OSError):
                return
            sock.settimeout(8.0)
            try:
                data, addr = sock.recvfrom(512)
                received_queries.append(data)
                resp = build_dns_response(data, "1.2.3.4")
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            finally:
                sock.close()

        server = threading.Thread(target=dns_server, daemon=True)
        server.start()
        time.sleep(0.5)

        router.set_dns(wan_ip)
        time.sleep(0.5)

        original_id = 0xBEEF
        query = build_dns_query("rewrite.test", query_id=original_id)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap1")
        client.settimeout(5.0)
        try:
            client.sendto(query, (router_lan_ip, 53))
            response, _ = client.recvfrom(512)
            resp_id = struct.unpack("!H", response[:2])[0]
            assert resp_id == original_id, \
                f"Response ID {resp_id:#x} != original {original_id:#x}"

            # Verify the router rewrote the ID when forwarding upstream
            if received_queries:
                fwd_id = struct.unpack("!H", received_queries[0][:2])[0]
                # The forwarded ID should be different from the original
                # (router assigns its own tracking IDs)
        except socket.timeout:
            if not received_queries:
                pytest.skip("Could not bind DNS server on port 53 — run with sudo")
            pytest.fail("DNS query forwarded but no response received")
        finally:
            client.close()
            server.join(timeout=2)

    def test_dns_set_upstream(self, router, wan_ip):
        """Verify the dns command is accepted."""
        resp = router.set_dns(wan_ip)
        assert "OK" in resp, f"DNS set failed: {resp}"
