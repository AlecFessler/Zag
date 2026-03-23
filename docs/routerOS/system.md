# RouterOS System Design

RouterOS is a userspace network router application for the Zag microkernel. All components run as separate processes communicating via shared-memory SPSC channels. No dynamic memory allocation is used anywhere in the system.

---

## 1. Architecture Overview

### 1.1 Process Hierarchy

```
root_service (broker)
├── serial_driver    (UART 16550 driver)
├── nic_wan          (Intel e1000 driver, WAN interface)
├── nic_lan          (Intel e1000 driver, LAN interface)
├── router           (packet processing, NAT, firewall, DNS, DHCP)
└── console          (serial line editor, user commands)
```

With only one NIC, the root service spawns a single `nic_driver` and the router operates in single-interface mode.

### 1.2 Communication Topology

```
Host WAN (tap0) ←→ e1000 ←→ nic_wan ←channel→ router ←channel→ console ←channel→ serial_driver ←→ UART
Host LAN (tap1) ←→ e1000 ←→ nic_lan ←channel→ router ↗
```

### 1.3 Service IDs

| ID | Name | Process |
|----|------|---------|
| 1 | SERIAL | serial_driver |
| 2 | NIC_WAN | nic_wan |
| 3 | ROUTER | router |
| 4 | CONSOLE | console |
| 5 | NIC_LAN | nic_lan |

### 1.4 Network Addressing

| Interface | IP | Subnet | MAC |
|-----------|------|--------|-----|
| WAN | 10.0.2.15 | 10.0.2.0/24 | 52:54:00:12:34:56 |
| LAN | 192.168.1.1 | 192.168.1.0/24 | 52:54:00:12:34:57 |

---

## 2. Root Service

**File:** `root_service/main.zig`

### 2.1 Startup

1. Scan perm_view for device handles (serial, NIC MMIO only)
2. Spawn children: serial_driver, nic_wan, nic_lan, router, console
3. Grant each child exactly one device handle
4. Enter broker loop for SHM connection requests

### 2.2 Permissions

| Process | Rights |
|---------|--------|
| serial_driver | grant_to, mem_reserve, device_own, restart |
| nic_wan / nic_lan | grant_to, mem_reserve, shm_create, device_own, restart |
| router | grant_to, mem_reserve, restart |
| console | grant_to, mem_reserve, restart |

---

## 3. Serial Driver

**File:** `serial_driver/main.zig`

UART 16550 driver: 115200 baud, 8N1, FIFO. Bridges serial port to SPSC channel via `ioport_read`/`ioport_write` syscalls.

---

## 4. NIC Driver

**File:** `nic_driver/main.zig`

Intel e1000 driver. Same binary for WAN and LAN — each gets a different device handle.

### 4.1 DMA Buffer Layout

```
Offset 0:      32 × RxDesc (512B)
Offset 512:    32 × TxDesc (512B)
Offset 1024:   32 × RX buffers (64KB)
Offset 66560:  32 × TX buffers (64KB)
Total: 34 pages (139264B)
```

IOMMU is required (`dma_map` syscall). Driver exits if IOMMU unavailable. After establishing the data channel, sends 6-byte MAC as the first message.

---

## 5. Router

**File:** `router/main.zig`

### 5.1 Data Structures

| Structure | Size | Description |
|-----------|------|-------------|
| ARP table | 16 per interface | `{ip, mac, valid}`, no expiration |
| NAT table | 128 entries | `{proto, lan_ip, lan_port, wan_port, timestamp}`, 2min timeout |
| DHCP leases | 32 entries | `{mac, ip, valid}`, range 192.168.1.100-231 |
| Port forwards | 16 rules | `{proto, wan_port, lan_ip, lan_port}` |
| Firewall rules | 32 rules | `{action, src_ip, src_mask, protocol, dst_port}` |
| DNS relay | 32 entries | `{client_ip, client_port, query_id, relay_id}` |
| Interface stats | 2 (WAN+LAN) | `{rx_pkts, rx_bytes, tx_pkts, tx_bytes, rx_dropped}` |

### 5.2 Packet Processing Pipeline

```
Receive from NIC channel → count stats
  ARP (0x0806):
    → learn sender IP/MAC
    → reply if targeted at us
    → resolve pending ping ARP
  IPv4 (0x0800):
    → firewall check (WAN inbound only)
    → if for us:
        UDP 67 (LAN): DHCP server
        UDP 53: DNS relay (LAN→upstream or upstream→LAN)
        ICMP echo request: reply
        ICMP echo reply: match outbound ping
    → LAN→WAN: NAT forward (SNAT)
    → WAN→LAN: port forward check, then NAT reverse (DNAT)
```

### 5.3 NAT (Source NAT / Masquerade)

**Outbound (LAN→WAN):** Rewrite source IP to WAN IP, source port to ephemeral NAT port. TCP: incremental checksum adjustment. UDP: zero checksum. ICMP: rewrite identifier.

**Inbound (WAN→LAN):** Look up NAT entry by (proto, wan_port). Rewrite destination IP/port back to original LAN values.

### 5.4 Port Forwarding (DNAT)

Checked before NAT reverse lookup for WAN→LAN traffic. Rewrites destination IP/port per the forwarding rule. TCP checksum incrementally adjusted. Configured via console `forward` command.

### 5.5 Firewall

Applied to inbound WAN IPv4 packets before any processing. Checks source IP against rule table. Matching block rules cause the packet to be dropped (counted in `rx_dropped`). Default policy: allow.

### 5.6 DNS Relay

LAN clients send DNS queries to the router's LAN IP (192.168.1.1:53). The router:
1. Records the client's IP, port, and original query ID
2. Assigns a relay ID and rewrites the query
3. Forwards to upstream DNS (default 10.0.2.1, configurable via `dns` command)
4. On response: matches by relay ID, restores original query ID, forwards to client

### 5.7 DHCP Server (LAN)

Responds to DHCPDISCOVER with DHCPOFFER and DHCPREQUEST with DHCPACK. Options: subnet mask, router, DNS, lease time (7200s). Pool: 192.168.1.100-231.

### 5.8 TCP Checksum Adjustment

For NAT and port forwarding, TCP checksums are incrementally adjusted using RFC 1624 method: subtract old IP/port contribution, add new contribution. This avoids recomputing the full pseudo-header checksum over the entire payload.

---

## 6. Console

**File:** `console/main.zig`

Line editor over serial channel. Commands are forwarded to the router as raw strings. Multi-response commands (ping, arp, nat, leases, rules) use a `"---"` prefix to signal end of output.

---

## 7. Build and Test

### 7.1 Directory Structure

```
userspace/routerOS/
  build.zig
  linker.ld
  root_service/main.zig
  serial_driver/main.zig
  nic_driver/main.zig
  router/main.zig
  console/main.zig
```

### 7.2 Host Setup

```bash
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

sudo ip tuntap add dev tap1 mode tap user $USER
sudo ip addr add 192.168.1.100/24 dev tap1
sudo ip link set tap1 up
```

### 7.3 Build + Run

```bash
cd userspace/routerOS && zig build
zig build -Dnet=tap -Duse-llvm=true -Dkvm=true -Diommu=amd \
  -Droot-service=userspace/bin/routerOS.elf
```

### 7.4 Verified Configurations

| IOMMU | Accelerator | WAN | LAN |
|-------|-------------|-----|-----|
| Intel VT-d | TCG | ✓ | ✓ |
| Intel VT-d | KVM | ✓ | ✓ |
| AMD-Vi | TCG | ✓ | ✓ |
| AMD-Vi | KVM | ✓ | ✓ |
