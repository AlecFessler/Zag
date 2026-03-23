# RouterOS System Design

RouterOS is a userspace network router application for the Zag microkernel. All components run as separate processes communicating via shared-memory SPSC channels. No dynamic memory allocation is used anywhere in the system.

---

## 1. Architecture Overview

### 1.1 Process Hierarchy

The **root service** spawns child processes and brokers shared-memory connections between them. With two NICs present, the topology is:

```
root_service (broker)
├── serial_driver    (UART hardware driver)
├── nic_wan          (Intel e1000 driver, WAN interface)
├── nic_lan          (Intel e1000 driver, LAN interface)
├── router           (packet processing, ARP, ICMP, NAT, DHCP)
└── console          (serial line editor, user commands)
```

With only one NIC, the root service spawns a single `nic_driver` and the router operates in single-interface mode (no NAT/DHCP).

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

### 2.1 Startup Sequence

1. Scan the permission view for device handles (serial, NIC)
2. Filter NIC handles to MMIO-type only (port-IO handles are not used for DMA)
3. Spawn children in order: serial_driver, nic_wan, nic_lan, router, console
4. Grant each child its required device handles and minimal permissions
5. Enter the broker loop

### 2.2 Device Grant Policy

Each NIC driver receives exactly one MMIO device handle. The first MMIO network device goes to `nic_wan`, the second to `nic_lan`. This matches QEMU's PCI enumeration order where the first `-device e1000` gets a lower PCI slot number.

### 2.3 Connection Brokering

Each child has a **command channel** — a 4KB shared memory region containing a `CommandChannel` struct with a mutex, futex-based wake/reply flags, and an array of `ConnectionEntry` slots.

The root service pre-populates each child's command channel with allowed connections:
- **router**: may connect to NIC_WAN and NIC_LAN
- **console**: may connect to SERIAL and ROUTER

When a child calls `requestConnection(service_id)`, it sets the entry status to `requested` and wakes the root service via futex. The root service detects this, allocates a 16KB data SHM, initializes the channel header, grants the SHM to both endpoints, and sets the entry status to `connected`.

### 2.4 Permissions

| Process | Rights |
|---------|--------|
| serial_driver | grant_to, mem_reserve, device_own, restart |
| nic_wan / nic_lan | grant_to, mem_reserve, shm_create, device_own, restart |
| router | grant_to, mem_reserve, restart |
| console | grant_to, mem_reserve, restart |

Device handles are granted exclusively — the root service transfers ownership to the appropriate driver.

---

## 3. Serial Driver

**File:** `serial_driver/main.zig`

Bridges the UART 16550 serial port to a SPSC channel for the console.

### 3.1 Initialization

1. Finds its serial device handle in the permission view (type=port_io, class=serial)
2. Configures the UART: 115200 baud, 8N1, FIFO enabled
3. Connects to the console via the brokered data channel (opens as Side A)

### 3.2 Runtime

Polls in a loop:
- **UART → Channel**: Reads LSR for data ready, reads RBR, sends byte to channel
- **Channel → UART**: Receives from channel, writes each byte to THR after checking LSR

All UART register access uses `ioport_read` and `ioport_write` syscalls.

---

## 4. NIC Driver

**File:** `nic_driver/main.zig`

Bridges the Intel e1000 network card to a SPSC channel. The same binary is used for both WAN and LAN instances — each gets a different device handle from the root service.

### 4.1 Initialization

1. Finds NIC device handle (type=mmio, class=network)
2. Maps MMIO register space via `vm_reserve` + `mmio_map`
3. Resets the e1000 (CTRL.RST), waits for reset completion
4. Sets link up (CTRL.SLU + CTRL.ASDE), reads MAC from RAL/RAH
5. Clears multicast table array
6. Allocates DMA shared memory (34 pages = 139264 bytes) via `shm_create_with_rights` (RW, no execute)
7. Maps DMA via IOMMU (`dma_map` syscall) — **IOMMU is required**, driver exits if unavailable
8. Initializes RX and TX descriptor rings in the DMA region
9. Configures RCTL (receive) and TCTL (transmit) registers

### 4.2 DMA Buffer Layout

```
Offset 0:        32 × RxDesc (512 bytes)
Offset 512:      32 × TxDesc (512 bytes)
Offset 1024:     32 × RX packet buffers (32 × 2048 = 65536 bytes)
Offset 66560:    32 × TX packet buffers (32 × 2048 = 65536 bytes)
Total: 132096 bytes (34 pages)
```

### 4.3 MAC Announcement

After establishing the data channel, the NIC driver sends its 6-byte MAC address as the first message. The router reads this to learn each interface's hardware address.

### 4.4 Runtime

Polls in a loop:
- **RX**: Check next RX descriptor DD bit → copy to channel
- **TX**: Check channel for data → copy to TX buffer, advance TDT

---

## 5. Router

**File:** `router/main.zig`

Processes network packets, handles ARP/ICMP, performs NAT for LAN-to-WAN traffic, and serves DHCP on the LAN.

### 5.1 Per-Interface State

Each interface (WAN, LAN) has:
- **MAC address**: learned from NIC driver's MAC announcement
- **IP address**: static (WAN: 10.0.2.15, LAN: 192.168.1.1)
- **ARP table**: 16-entry fixed array of `{ip, mac, valid}` — no expiration, LRU eviction at slot 0

### 5.2 Packet Processing Pipeline

```
Receive from NIC channel
  → Parse ethertype
  → 0x0806 (ARP): learn sender, reply if targeted at us, resolve pending ping
  → 0x0800 (IPv4):
      → Destination is our IP:
          → UDP port 67: DHCP server (LAN only)
          → ICMP echo request: reply
          → ICMP echo reply: match to outbound ping
      → LAN → WAN: NAT forward (rewrite src IP/port, send on WAN)
      → WAN → LAN: NAT reverse (lookup by dst port, rewrite dst IP/port, send on LAN)
```

### 5.3 ARP

- **arpLearn**: called on every ARP packet (request or reply), updates the interface's ARP table
- **sendArpRequestOn(iface, target_ip)**: builds and sends ARP request on the specified interface
- **handleArp(iface, pkt)**: replies to ARP requests targeted at our IP, pads to 60 bytes minimum

### 5.4 Outbound Ping State Machine

```
idle ──[ping cmd]──→ arp_pending ──[ARP reply]──→ echo_sent ──[ICMP reply]──→ idle
                          │                            │
                          └──[3s timeout]──→           └──[3s timeout]──→
                          (retry or summary)           (retry or summary)
```

The ping command auto-selects the interface: LAN subnet destinations use LAN, all others use WAN.

### 5.5 NAT (Network Address Translation)

Source NAT (masquerade) for LAN-to-WAN traffic. The NAT table has 128 entries, each mapping `(protocol, lan_ip, lan_port) → wan_port`.

**Outbound (LAN → WAN):**
1. Extract protocol and source port from the LAN packet
2. Look up or create NAT entry
3. Rewrite source IP to WAN IP, source port to NAT port
4. Set destination MAC to gateway (WAN ARP lookup)
5. Recompute IP and transport checksums
6. Send on WAN channel

**Inbound (WAN → LAN):**
1. Check if destination IP matches WAN IP and protocol matches a NAT entry
2. Look up NAT entry by (protocol, wan_port)
3. Rewrite destination IP to original LAN IP, destination port to original port
4. Set destination MAC from LAN ARP table
5. Recompute checksums
6. Send on LAN channel

**Supported protocols:** ICMP (ID as port), TCP (source port), UDP (source port). For UDP, the transport checksum is zeroed (optional per RFC 768).

**Entry lifecycle:** 2-minute timeout. Ephemeral WAN ports start at 10000 and wrap around.

### 5.6 DHCP Server (LAN Side)

The router serves DHCP on the LAN interface (UDP port 67).

**Lease table:** 32 entries, maps MAC → IP. Addresses assigned from 192.168.1.100–192.168.1.231.

**Supported message types:**
- DHCPDISCOVER → DHCPOFFER
- DHCPREQUEST → DHCPACK

**Options provided:** subnet mask (255.255.255.0), router (192.168.1.1), DNS server (192.168.1.1), lease time (7200s), server identifier.

### 5.7 Console Commands

The router receives string commands from the console channel and sends back string responses:

| Command | Response pattern |
|---------|-----------------|
| `"status"` | Single message with interface info |
| `"ping X.X.X.X"` | Multiple messages: per-packet results + `"---"` summary |
| `"arp"` | Table dump + `"---"` summary |
| `"nat"` | Table dump + `"---"` summary |
| `"leases"` | Table dump + `"---"` summary |

---

## 6. Console

**File:** `console/main.zig`

Interactive serial terminal with line editing.

### 6.1 Router Communication

Commands that require the router use two patterns:

**Single-response** (`status`): Send string, poll for up to 10,000 yields.

**Multi-response** (`ping`, `arp`, `nat`, `leases`): Send string, poll for up to 8 messages with 100,000-yield timeout between each. The `"---"` prefix signals end of output.

---

## 7. Channel Protocol

All inter-process communication uses the `lib.channel` SPSC ring buffer.

### 7.1 Layout

```
ChannelHeader (56 bytes):
  magic: "ZAG_CHAN", version: 1
  ring_a_offset, ring_b_offset, ring_size

RingHeader (per direction):
  head, tail: u64 (atomic)
  wake_flag: u64 (futex)
  checksum: u32 (CRC32)
  [data bytes]
```

Side A writes ring A, reads ring B. Side B is opposite. Messages are length-prefixed `[u32 len][payload]`.

---

## 8. Network Protocols

### 8.1 Ethernet Frame

```
[0:5]  Destination MAC
[6:11] Source MAC
[12:13] EtherType (0x0806=ARP, 0x0800=IPv4)
[14:]  Payload
```

Minimum 60 bytes (excluding FCS).

### 8.2 ARP (EtherType 0x0806)

```
[14:15] Hardware Type (0x0001)
[16:17] Protocol Type (0x0800)
[18]    HW Addr Len (6)
[19]    Proto Addr Len (4)
[20:21] Opcode (1=Request, 2=Reply)
[22:27] Sender MAC
[28:31] Sender IP
[32:37] Target MAC
[38:41] Target IP
```

### 8.3 IPv4 (EtherType 0x0800)

```
[14]    Version(4) + IHL(5)
[16:17] Total Length
[22]    TTL
[23]    Protocol (1=ICMP, 6=TCP, 17=UDP)
[24:25] Header Checksum
[26:29] Source IP
[30:33] Destination IP
```

### 8.4 ICMP Echo

```
[IP+0]  Type (8=Request, 0=Reply)
[IP+1]  Code (0)
[IP+2:3] Checksum
[IP+4:5] Identifier
[IP+6:7] Sequence Number
```

### 8.5 UDP

```
[IP+0:1] Source Port
[IP+2:3] Destination Port
[IP+4:5] Length
[IP+6:7] Checksum (optional, zeroed for NAT)
```

### 8.6 DHCP (UDP ports 67/68)

The DHCP server responds to DISCOVER and REQUEST messages. Response includes: message type, subnet mask, router, DNS, lease time, and server identifier options. Magic cookie: `0x63825363`.

---

## 9. Build and Test

### 9.1 Directory Structure

```
userspace/routerOS/
  build.zig              (top-level build, compiles all programs)
  linker.ld              (shared linker script)
  root_service/main.zig
  serial_driver/main.zig
  nic_driver/main.zig
  router/main.zig
  console/main.zig
```

### 9.2 Build Commands

```bash
# Build routerOS
cd userspace/routerOS && zig build

# Build kernel + routerOS (Intel IOMMU, TCG)
zig build -Dnet=tap -Duse-llvm=true -Dkvm=false -Diommu=intel \
  -Droot-service=userspace/bin/routerOS.elf

# Build kernel + routerOS (AMD IOMMU, KVM)
zig build -Dnet=tap -Duse-llvm=true -Dkvm=true -Diommu=amd \
  -Droot-service=userspace/bin/routerOS.elf
```

### 9.3 Host Setup

```bash
# WAN interface (already exists if previously configured)
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

# LAN interface
sudo ip tuntap add dev tap1 mode tap user $USER
sudo ip addr add 192.168.1.100/24 dev tap1
sudo ip link set tap1 up
```

### 9.4 Testing

All four IOMMU configurations are verified working:

| Configuration | WAN Ping | LAN Ping |
|---------------|----------|----------|
| Intel VT-d + TCG | ✓ | ✓ |
| Intel VT-d + KVM | ✓ | ✓ |
| AMD-Vi + TCG | ✓ | ✓ |
| AMD-Vi + KVM | ✓ | ✓ |
