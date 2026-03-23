# RouterOS System Design

RouterOS is a userspace network router for the Zag microkernel. All components run as separate processes communicating via shared-memory SPSC channels. No dynamic memory allocation.

---

## 1. Architecture

### 1.1 Process Hierarchy

```
root_service (broker)
├── serial_driver    (UART 16550)
├── nic_wan          (e1000, WAN interface)
├── nic_lan          (e1000, LAN interface)
├── router           (NAT, firewall, DNS, DHCP, ARP)
└── console          (serial line editor)
```

### 1.2 Data Flow

```
Host WAN (tap0) ←→ e1000 ←→ nic_wan ←channel→ router ←channel→ console ←channel→ serial_driver ←→ UART
Host LAN (tap1) ←→ e1000 ←→ nic_lan ←channel→ router ↗
```

### 1.3 Addressing

| Interface | IP | Subnet | MAC |
|-----------|------|--------|-----|
| WAN | 10.0.2.15 (or DHCP) | 10.0.2.0/24 | 52:54:00:12:34:56 |
| LAN | 192.168.1.1 | 192.168.1.0/24 | 52:54:00:12:34:57 |

---

## 2. Root Service

**File:** `root_service/main.zig`

Scans perm_view for MMIO network devices (filters out port-IO). Spawns children in order, grants one device handle per NIC driver. Enters broker loop to mediate SHM connections.

### Permissions

| Process | Rights |
|---------|--------|
| serial_driver | grant_to, mem_reserve, device_own, restart |
| nic_wan / nic_lan | grant_to, mem_reserve, shm_create, device_own, restart |
| router | grant_to, mem_reserve, restart |
| console | grant_to, mem_reserve, restart |

---

## 3. NIC Driver

**File:** `nic_driver/main.zig`

Same binary for WAN and LAN. Each gets one MMIO device handle.

### DMA Layout (34 pages)

```
Offset 0:      32 × RxDesc (512B)
Offset 512:    32 × TxDesc (512B)
Offset 1024:   32 × RX buffers (64KB)
Offset 66560:  32 × TX buffers (64KB)
```

IOMMU required (`dma_map`). Sends 6-byte MAC announcement as first channel message.

---

## 4. Router

**File:** `router/main.zig`

### 4.1 Data Structures

| Structure | Size | Purpose |
|-----------|------|---------|
| ARP table | 16 × 2 | Per-interface IP→MAC, 5-minute expiry |
| NAT table | 128 | Connection tracking with per-protocol timeouts |
| DHCP leases | 32 | LAN DHCP server, 192.168.1.100-231 |
| Port forwards | 16 | DNAT rules (WAN port → LAN IP:port) |
| Firewall rules | 32 | Block/allow by source IP |
| DNS relay | 32 | Query ID translation for LAN→upstream |
| Fragment table | 16 | IP fragment reassembly tracking |
| Interface stats | 2 | RX/TX/drop counters per interface |

### 4.2 Packet Pipeline

```
Receive → stats → ethertype dispatch
  ARP: learn sender, reply if for us, resolve pending ping
  IPv4:
    firewall check (WAN inbound)
    if for us:
      UDP 68 (WAN): DHCP client response
      UDP 67 (LAN): DHCP server
      UDP 53: DNS relay
      ICMP echo request: reply
      ICMP echo reply: match outbound ping
    LAN→WAN: DNS intercept → NAT forward (SNAT)
    WAN→LAN: DNS response → port forward → NAT reverse
```

### 4.3 NAT

**Source NAT (LAN→WAN):**
- Rewrite src IP → WAN IP, src port → ephemeral NAT port
- TCP: incremental checksum (RFC 1624), track SYN/FIN/RST state
- UDP: zero checksum (RFC 768 optional)
- ICMP: rewrite identifier

**Reverse NAT (WAN→LAN):**
- Lookup by (protocol, wan_port)
- Rewrite dst IP/port back to original LAN values
- TCP state tracking on return path

### 4.4 TCP Connection Tracking

| State | Trigger | Timeout |
|-------|---------|---------|
| syn_sent | SYN seen | 30s |
| established | ACK seen (after SYN) | 300s |
| fin_wait | FIN or RST | 30s |
| (removed) | RST in fin_wait | immediate |

### 4.5 UDP Timeout Tuning

| Traffic | Timeout |
|---------|---------|
| DNS (port 53) | 30s |
| General UDP | 120s |
| ICMP | 60s |

### 4.6 ARP Table

- 16 entries per interface, learned from all ARP packets
- Timestamped on learn/update
- Expired every 10 seconds (5-minute TTL)
- Slot 0 evicted when full

### 4.7 DNS Relay

LAN clients → router (192.168.1.1:53) → upstream DNS (configurable, default 10.0.2.1)
- Rewrites query ID with relay ID for tracking
- 32 concurrent query slots
- Upstream learned from DHCP option 6 if DHCP client active

### 4.8 DHCP Server (LAN)

- Pool: 192.168.1.100-231 (32 leases)
- Options: subnet mask, router, DNS, lease time (7200s)
- DISCOVER → OFFER, REQUEST → ACK

### 4.9 DHCP Client (WAN)

- DISCOVER → OFFER → REQUEST → ACK
- Sets wan_ip dynamically
- Learns upstream DNS from option 6
- 10-second retry timeout
- Triggered by `dhcp-client` console command

### 4.10 Port Forwarding

- 16 rules, configured via console (`forward tcp 80 192.168.1.100 8080`)
- Checked before NAT reverse lookup for WAN→LAN traffic
- TCP: incremental checksum adjustment
- UDP: zero checksum

### 4.11 Firewall

- 32 rules, WAN inbound only
- Match by source IP (full /32 mask)
- Default policy: allow
- Blocked packets increment drop counter

### 4.12 IP Fragment Tracking

- 16 entries tracking IP ID → source port from first fragment
- Non-first fragments (fragment offset > 0) lack port numbers
- Table maps (src_ip, ip_id) → first_frag_sport for NAT lookup
- 30-second expiry

### 4.13 Connection Logging

NAT creation, DHCP events, and firewall actions logged to serial via `syscall.write`. Format:
```
nat: new tcp 192.168.1.100:49152 -> 10.0.2.1:80 (wan:10001)
dhcp-client: bound to 10.0.2.15
firewall: block rule added
```

### 4.14 Periodic Maintenance

Every 10 seconds:
- ARP table expiry (both interfaces)
- NAT table expiry (per-protocol timeouts)
- Fragment table expiry
- DHCP client retry check

---

## 5. Console

**File:** `console/main.zig`

Line editor over serial. Single-response commands use 10k-yield timeout. Multi-response commands (ping, arp, nat, leases, rules) poll for up to 8 messages with 100k-yield inter-message timeout, end on `"---"` prefix.

---

## 6. Build and Test

### 6.1 Directory Structure

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

### 6.2 Host Setup

```bash
# WAN
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

# LAN
sudo ip tuntap add dev tap1 mode tap user $USER
sudo ip addr add 192.168.1.100/24 dev tap1
sudo ip link set tap1 up

# For NAT testing: namespace with bridge
sudo ip link add br-lan type bridge
sudo ip link set tap1 master br-lan
sudo ip link set br-lan up
sudo ip link add veth-host type veth peer name veth-ns
sudo ip link set veth-host master br-lan
sudo ip link set veth-host up
sudo ip netns add lan_client
sudo ip link set veth-ns netns lan_client
sudo ip netns exec lan_client ip addr add 192.168.1.100/24 dev veth-ns
sudo ip netns exec lan_client ip link set veth-ns up
sudo ip netns exec lan_client ip route add default via 192.168.1.1

# NAT test: sudo ip netns exec lan_client ping 10.0.2.1
```

### 6.3 Build

```bash
cd userspace/routerOS && zig build
zig build -Dnet=tap -Duse-llvm=true -Dkvm=true -Diommu=amd \
  -Droot-service=userspace/bin/routerOS.elf
```

### 6.4 Verified Configurations

| IOMMU | Accel | WAN | LAN |
|-------|-------|-----|-----|
| Intel VT-d | TCG | ✓ | ✓ |
| Intel VT-d | KVM | ✓ | ✓ |
| AMD-Vi | TCG | ✓ | ✓ |
| AMD-Vi | KVM | ✓ | ✓ |
