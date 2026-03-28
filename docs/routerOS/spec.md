# RouterOS Specification

Observable behavior of Zag RouterOS. This document describes what the router does from a user and network perspective, not how it is implemented internally (see [system.md](system.md) for that).

---

## 1. Overview

RouterOS is a bare-metal IPv4/IPv6 dual-stack network router running as a set of userspace processes on the Zag microkernel. It provides NAT, DHCP, DNS relay, firewall, and routing between a WAN and LAN interface.

### Network topology

```
Internet / ISP gateway
        |
   WAN (10.0.2.0/24)
        |
   [ RouterOS ]
        |
   LAN (10.1.1.0/24)
        |
   LAN clients (DHCP: 10.1.1.100-254)
```

### Interfaces

| Interface | Default IP | Subnet | Role |
|-----------|-----------|--------|------|
| WAN | 10.0.2.15 (or DHCP) | 10.0.2.0/24 | Upstream / ISP-facing |
| LAN | 10.1.1.1 | 10.1.1.0/24 | Local network |

The WAN IP can be statically configured or obtained via DHCP client. The LAN IP is always 10.1.1.1.

---

## 2. Routing and forwarding

- All packets from LAN destined outside 10.1.1.0/24 are forwarded to WAN with source NAT.
- All packets from WAN matching an active NAT entry or port forward are forwarded to LAN.
- TTL is decremented on forwarded packets. Packets with TTL=1 generate ICMP Time Exceeded.
- Packets destined for the router's own IP are handled locally (ping, DHCP, DNS, HTTP).
- TCP MSS is clamped to 1460 on SYN/SYN-ACK packets crossing the router.
- IP fragmentation is tracked (up to 32 concurrent fragment reassembly contexts).

---

## 3. NAT (Network Address Translation)

Source NAT for all outbound LAN-to-WAN traffic. The router rewrites the source IP and port, tracks the mapping, and reverses it for return traffic.

| Protocol | Timeout |
|----------|---------|
| ICMP | 60s |
| UDP (general) | 120s |
| UDP (DNS, port 53) | 30s |
| TCP SYN sent | 30s |
| TCP Established | 300s |
| TCP FIN/RST | 30s |

NAT port range: 10000+. Table size: 256 entries.

---

## 4. DHCP

### Server (LAN)

- Serves addresses from 10.1.1.100 to 10.1.1.254
- Lease time: 1 hour
- Gateway: 10.1.1.1 (router LAN IP)
- DNS server: 10.1.1.1 (router relays DNS)
- Up to 32 dynamic leases
- Up to 16 static leases (MAC-to-IP reservations)

Static leases are configured via the console (`static-lease add <mac> <ip>`) and persist across reboots when configuration is saved.

### Client (WAN)

- Obtains WAN IP, gateway, and DNS server via DHCP
- Supports T1 renewal and T2 rebind timers
- Learns upstream DNS from DHCP option 6
- Retries on 10-second timeout
- Starts via `dhcp-client` console command or automatically if configured

---

## 5. DNS relay and cache

- Relays DNS queries from LAN clients (UDP port 53) to the configured upstream DNS server
- Default upstream: 10.0.2.1 (updated by DHCP client if option 6 received)
- Configurable via `dns <ip>` console command
- Cache: 64 entries with TTL-based expiry
- Up to 32 concurrent in-flight queries tracked
- Query ID rewriting to prevent conflicts

---

## 6. Firewall

### Default policy

- WAN inbound: drop unsolicited traffic (only NAT return and port forwards allowed)
- LAN outbound: allow all
- ICMP: respond to ping on both interfaces

### Block rules

- Up to 32 IP block rules on WAN inbound
- Added via `block <ip>`, removed via `allow <ip>`
- Persisted when configuration is saved

### Port forwarding

- Up to 16 port forward rules (TCP or UDP)
- Forward WAN port to LAN IP:port
- Configured via console (`forward tcp <wport> <lip> <lport>`), UPnP, or PCP
- Dynamic forwards via UPnP/PCP have configurable lease times

---

## 7. IPv6

- DHCPv6 prefix delegation on WAN
- SLAAC (Stateless Address Autoconfiguration) on LAN using delegated prefix
- Router Advertisements sent to LAN clients
- NDP (Neighbor Discovery Protocol) on both interfaces
- ICMPv6 echo reply
- IPv6 connection tracking with stateful firewall (64 entries, 300s TCP / 120s UDP timeout)

---

## 8. UPnP IGD

- SSDP discovery (multicast 239.255.255.250:1900)
- UPnP root device descriptor at `/rootDesc.xml`
- WANIPConnection service descriptor at `/WANIPConn.xml`
- SOAP actions: AddPortMapping, DeletePortMapping, GetExternalIPAddress

---

## 9. PCP (Port Control Protocol)

- MAP opcode for creating/deleting port forwards from LAN clients
- Lifetime-based lease management
- UDP port 5351

---

## 10. ARP

- 16 entries per interface
- Entries expire after 5 minutes of inactivity
- ARP requests sent on startup for gateway and known LAN hosts

---

## 11. NFS client

NFSv3 over UDP with AUTH_UNIX. Used for persistent configuration and log storage.

| Operation | NFS Procedure |
|-----------|--------------|
| mount | MOUNTPROC_MNT |
| ls | READDIR |
| cat | LOOKUP + READ |
| put | CREATE + WRITE + COMMIT |
| mkdir | MKDIR |
| rm | REMOVE |
| mv | RENAME |
| touch | CREATE |
| stat | GETATTR |

---

## 12. NTP client

SNTPv4 over UDP port 123. Syncs system time from a configurable NTP server. Default: pool.ntp.org via DNS. The router's clock is used for log timestamps and DHCP/DNS TTL tracking.

---

## 13. HTTP management API

HTTP/1.0 server on LAN port 80. Serves a web management UI and JSON API.

| Endpoint | Returns |
|----------|---------|
| `GET /` | HTML management page (auto-refreshing dashboard) |
| `GET /api/status` | Interface IPs, MACs, gateway |
| `GET /api/ifstat` | RX/TX/drop counters per interface |
| `GET /api/arp` | ARP table entries |
| `GET /api/nat` | NAT connection tracking table |
| `GET /api/leases` | DHCP lease table |
| `GET /api/rules` | Firewall rules and port forwards |

Accessible from LAN at `http://10.1.1.1/`.

---

## 14. Logging

Structured event logging with timestamps. Events are written to:
- Serial console (always)
- NFS-backed log file at `/export/zagtest/logs/router.log` (when NFS is connected)

Log format: `[timestamp] LEVEL category : message`

Levels: INFO, WARN, ERR, DEBUG.

---

## 15. Console

Interactive CLI over serial port. See [console.md](console.md) for the full command reference.

---

## 16. Process model

RouterOS runs as multiple cooperating processes, all spawned by the root service:

| Process | Role |
|---------|------|
| root_service | Spawns all other processes, brokers IPC connections, monitors health |
| serial_driver | UART 16550 I/O |
| router | Packet processing, NAT, firewall, DHCP, DNS, IPv6 |
| nfs_client | NFSv3 client for persistent storage |
| ntp_client | Time synchronization |
| http_server | Web management API |
| console | Serial CLI, dispatches commands to router and other services |

Processes communicate via shared memory channels brokered by the root service. Each process runs with minimal capability rights. The root service monitors child processes via watchdog threads and reports crashes/restarts.

---

## 17. Persistent configuration

Router configuration (firewall rules, port forwards, static DHCP leases, DNS settings) can be saved to and loaded from NFS storage.

- `save-config`: writes current configuration to NFS
- `load-config`: restores configuration from NFS on boot
- `get-config`: displays current saved configuration
