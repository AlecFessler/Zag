# RouterOS E2E Testing

End-to-end tests for the Zag RouterOS, running the full kernel + router in QEMU with real TAP interfaces.

---

## Quick Start

```bash
# One-time setup (creates TAP interfaces)
sudo ./routerOS/tests/setup_network.sh

# Build + run all tests (requires sudo for raw sockets and network namespaces)
sudo ./routerOS/tests/run_tests.sh
```

## Prerequisites

- QEMU with KVM support
- Two TAP interfaces: `tap0` (WAN: 10.0.2.1/24) and `tap1` (LAN: 10.1.1.50/24)
- NFS server exporting `/export/zagtest` to 10.0.2.0/24
- Python venv with pytest and pexpect:
  ```bash
  python3 -m venv routerOS/tests/.venv
  routerOS/tests/.venv/bin/pip install pexpect scapy pytest
  ```

## Running Tests

### Full suite (recommended)

```bash
sudo ./routerOS/tests/run_tests.sh
```

This does a clean build, kills stale QEMU instances, and runs all tests with sudo. Sudo is required because:
- Raw `AF_PACKET` sockets need `CAP_NET_RAW` (IPv6, fragmentation, ICMP capture tests)
- Network namespace creation/management needs root (NAT, forwarding, port forwarding tests)

### Running specific tests

```bash
# Build first (clean build required after code changes)
cd routerOS && rm -rf .zig-cache zig-out && zig build && cd ..
rm -rf .zig-cache zig-out && zig build -Dprofile=router

# Run a specific test file
cd routerOS/tests
sudo .venv/bin/pytest test_ping.py -v --tb=short

# Run a specific test
sudo .venv/bin/pytest test_status.py::TestStatus::test_version -v
```

### Without sudo (limited)

Tests that don't need raw sockets or namespaces work without sudo:

```bash
cd routerOS/tests && .venv/bin/pytest -v --tb=short
```

This runs ~60 tests. Tests requiring raw sockets skip with "Raw socket requires CAP_NET_RAW", and namespace tests skip with "lan_test namespace not found".

## Important Notes

### Clean builds are required

Zig's incremental compilation can produce broken binaries where the kernel only detects 1 NIC instead of 2. Always do a **clean build** before running tests:

```bash
cd routerOS && rm -rf .zig-cache zig-out && zig build
cd .. && rm -rf .zig-cache zig-out && zig build -Dprofile=router
```

The `run_tests.sh` script does this automatically.

### The harness does NOT rebuild

The test harness has `build=False` — it expects a pre-built image at `zig-out/img/`. This avoids incremental compilation bugs during test runs.

### QEMU NvVars file

QEMU creates `zig-out/img/NvVars` owned by whoever runs it. If you switch between sudo and non-sudo runs, delete this file first:

```bash
rm -f zig-out/img/NvVars
```

### Network namespace lifecycle

The `lan_test` namespace (used for NAT/forwarding tests) is created automatically by the test fixture after QEMU boots. It uses a macvlan on tap1. The namespace is torn down after the test session.

Do NOT create the namespace before QEMU starts — attaching a macvlan to tap1 before QEMU opens it prevents QEMU from detecting the second NIC.

## Test Categories

| Category | Files | Count | Requirements |
|----------|-------|-------|-------------|
| ARP | test_arp.py | 4 | LAN interface |
| DHCP | test_dhcp.py | 7 | LAN, namespace (1 test) |
| DNS | test_dns.py | 3 | LAN, raw sockets |
| Firewall | test_firewall.py | 7 | LAN, namespace (2 tests) |
| Forwarding | test_forwarding.py | 6 | LAN, namespace |
| Fragmentation | test_fragmentation.py | 4 | Raw sockets (2 tests) |
| HTTP Server | test_http.py | 6 | Raw sockets, LAN |
| ICMP | test_icmp.py | 5 | LAN, namespace, raw sockets |
| IPv6 | test_ipv6.py | 6 | Raw sockets |
| IPv6 Firewall | test_ipv6_firewall.py | 5 | Raw sockets |
| Logging | test_logging.py | 4 | — |
| MSS Clamping | test_mtu.py | 1 | Namespace |
| NAT | test_nat.py | 5 | Namespace |
| NFS | test_nfs.py, test_nfs_ops.py | 8 | NFS server |
| NTP | test_ntp.py | 3 | — |
| Config | test_persistent_config.py | 4 | — |
| Ping | test_ping.py | 4 | LAN |
| Status | test_status.py | 7 | LAN |
| Traceroute | test_traceroute.py | 3 | — |
| UDP Fwd | test_udp_fwd.py | 4 | — |

## Known Issues

- **HTTP tests skip (6)**: The raw TCP handshake test implementation has a bug — the router's HTTP server works fine via browser but the test's `AF_PACKET` TCP stack doesn't receive the response correctly.
- **NFS mkdir/rm**: Previously xfail due to ARP table pollution (16-entry table with naive eviction). Fixed by increasing ARP table to 64 entries with LRU eviction, enlarging the pending UDP buffer, and draining stale NFS channel messages in the console.
