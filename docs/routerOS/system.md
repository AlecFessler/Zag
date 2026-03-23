# RouterOS System Design

RouterOS is a userspace network router application for the Zag microkernel. All components run as separate processes communicating via shared-memory SPSC channels. No dynamic memory allocation is used anywhere in the system.

---

## 1. Architecture Overview

### 1.1 Process Hierarchy

The **root service** spawns four child processes and brokers shared-memory connections between them:

```
root_service (broker)
├── serial_driver   (UART hardware driver)
├── nic_driver      (Intel e1000 hardware driver)
├── router          (packet processing, ARP, ICMP)
└── console         (serial line editor, user commands)
```

### 1.2 Communication Topology

```
Host (tap0) ←→ e1000 HW ←→ nic_driver ←channel→ router ←channel→ console ←channel→ serial_driver ←→ UART HW
```

Each arrow labeled `channel` is a bidirectional SPSC ring buffer in shared memory, brokered by the root service.

### 1.3 Service IDs

| ID | Name | Process |
|----|------|---------|
| 1 | SERIAL | serial_driver |
| 2 | NIC | nic_driver |
| 3 | ROUTER | router |
| 4 | CONSOLE | console |

---

## 2. Root Service

**File:** `root_service/main.zig`

### 2.1 Startup Sequence

1. Scan the permission view for device handles (serial, NIC)
2. Spawn children in order: serial_driver, nic_driver, router, console
3. Grant each child its required device handles and permissions
4. Enter the broker loop

### 2.2 Connection Brokering

Each child has a **command channel** — a 4KB shared memory region containing a `CommandChannel` struct with a mutex, futex-based wake/reply flags, and an array of `ConnectionEntry` slots.

The root service pre-populates each child's command channel with allowed connections:
- **router**: may connect to NIC
- **console**: may connect to SERIAL and ROUTER

When a child calls `requestConnection(service_id)`, it sets the entry status to `requested` and wakes the root service via futex. The root service detects this, allocates a 16KB data SHM, initializes the channel header, grants the SHM to both endpoints, and sets the entry status to `connected`.

### 2.3 Permissions

Each child receives minimal permissions:

| Process | Rights |
|---------|--------|
| serial_driver | grant_to, mem_reserve, device_own, restart |
| nic_driver | grant_to, mem_reserve, shm_create, device_own, restart |
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
- **UART → Channel**: Reads LSR for data ready, reads RBR, sends single byte to channel
- **Channel → UART**: Receives from channel, writes each byte to THR after checking LSR transmit ready

All UART register access uses `ioport_read` and `ioport_write` syscalls with the device handle.

---

## 4. NIC Driver

**File:** `nic_driver/main.zig`

Bridges the Intel e1000 network card to a SPSC channel for the router.

### 4.1 Initialization

1. Finds NIC device handle (type=mmio, class=network)
2. Maps MMIO register space via `vm_reserve` + `mmio_map`
3. Resets the e1000 (CTRL.RST), waits for reset completion
4. Sets link up (CTRL.SLU + CTRL.ASDE), reads MAC from RAL/RAH
5. Clears multicast table array
6. Allocates DMA shared memory (34 pages = 139264 bytes) via `shm_create_with_rights`
7. Maps DMA via IOMMU (`dma_map` syscall) — **IOMMU is required**, driver exits if unavailable
8. Initializes RX and TX descriptor rings
9. Configures RCTL (receive) and TCTL (transmit) registers

### 4.2 DMA Buffer Layout

```
Offset 0:        32 × RxDesc (512 bytes)
Offset 512:      32 × TxDesc (512 bytes)
Offset 1024:     32 × RX packet buffers (32 × 2048 = 65536 bytes)
Offset 66560:    32 × TX packet buffers (32 × 2048 = 65536 bytes)
Total: 132096 bytes (34 pages)
```

Each descriptor is 16 bytes containing a DMA buffer address, length, status, and command flags. The e1000 hardware reads/writes these via DMA through the IOMMU.

### 4.3 Descriptor Formats

**RxDesc:**
```
buffer_addr: u64   — DMA address of packet buffer
length: u16        — received packet length (set by hardware)
checksum: u16      — hardware checksum
status: u8         — DD bit indicates descriptor done
errors: u8         — error flags
special: u16       — VLAN tag
```

**TxDesc:**
```
buffer_addr: u64   — DMA address of packet data
length: u16        — packet length
cso: u8            — checksum offset
cmd: u8            — EOP | IFCS | RS
status: u8         — DD bit indicates transmit complete
css: u8            — checksum start
special: u16       — VLAN tag
```

### 4.4 Runtime

Polls in a loop:
- **RX**: Check next RX descriptor for DD bit. If set, copy packet data from DMA buffer to stack, send via channel, clear status, advance RDT.
- **TX**: Check channel for outbound packet. Copy to TX buffer, set descriptor length/cmd, advance TDT.

---

## 5. Router

**File:** `router/main.zig`

Processes network packets and handles console commands.

### 5.1 State

- **router_mac**: `52:54:00:12:34:56` (matches QEMU e1000 default)
- **router_ip**: `10.0.2.15`
- **ARP table**: 16-entry fixed array of `{ip: [4]u8, mac: [6]u8, valid: bool}`
- **Ping state machine**: `idle | arp_pending | echo_sent`

### 5.2 Packet Processing

All packets arrive as raw Ethernet frames from the NIC driver channel.

**ARP (ethertype 0x0806):**
- Always learn sender IP/MAC from any ARP packet (request or reply)
- If ARP request targets our IP: construct and send ARP reply
- If ping is waiting for ARP resolution: check if target MAC now known

**IPv4/ICMP (ethertype 0x0800):**
- ICMP echo request (type 8): swap addresses, recompute checksums, send reply
- ICMP echo reply (type 0): match by identifier/sequence, compute RTT, report to console

### 5.3 ARP Table

Entries are learned from all incoming ARP packets. No expiration timer. The table is a linear scan:
- `arpLookup(ip)`: returns MAC if found
- `arpLearn(ip, mac)`: updates existing entry or fills first empty slot; overwrites slot 0 when full

### 5.4 Outbound Ping State Machine

```
idle ──[ping command]──→ arp_pending ──[ARP reply]──→ echo_sent ──[ICMP reply]──→ idle
                              │                            │
                              └──[3s timeout]──→           └──[3s timeout]──→
                              (retry or summary)           (retry or summary)
```

1. Console sends `"ping X.X.X.X"` string
2. Router parses IP, checks ARP table
3. If MAC unknown: send ARP request, enter `arp_pending`, start 3s timer
4. On ARP reply: learn MAC, send ICMP echo request, enter `echo_sent`
5. On ICMP echo reply: compute RTT, send result to console, advance sequence
6. After 4 packets (or timeouts): send summary line and return to `idle`

Each result is sent as a separate string message through the console channel.

### 5.5 Console Commands

The router receives raw string commands from the console channel:

| Command | Response |
|---------|----------|
| `"status"` | Single message with IP and MAC |
| `"ping X.X.X.X"` | Multiple messages: per-packet results + summary |
| `"arp"` | Header line + one line per ARP table entry |

---

## 6. Console

**File:** `console/main.zig`

Interactive serial terminal with line editing.

### 6.1 Architecture

The console bridges two channels:
- **serial_chan**: connects to serial_driver (Side A)
- **router_chan**: connects to router (Side B)

Input characters arrive from `serial_chan.recv()`. The console echoes them back via `serial_chan.send()` and builds a line buffer. On Enter, the line is dispatched to `processCommand()`.

### 6.2 Router Communication

Commands that require the router (`status`, `ping`, `arp`) use two patterns:

**Single-response** (`status`): Send command string, poll `router_chan.recv()` for up to 10,000 yields.

**Multi-response** (`ping`, `arp`): Send command string, poll for up to 8 messages with 100,000-yield timeout between each. The summary line (starting with `"---"`) signals end of output.

---

## 7. Channel Protocol

All inter-process communication uses the `lib.channel` SPSC ring buffer.

### 7.1 Channel Layout

```
ChannelHeader (56 bytes):
  magic: u64 = "ZAG_CHAN"
  version: u16 = 1
  ring_a_offset, ring_b_offset, ring_size: u32

RingHeader (per direction):
  head: u64 (atomic, owned by reader)
  tail: u64 (atomic, owned by writer)
  wake_flag: u64 (futex)
  checksum: u32 (CRC32)
  data_size: u32
  [data bytes...]
```

Side A writes to ring A, reads from ring B. Side B writes to ring B, reads from ring A.

### 7.2 Message Format

Messages are length-prefixed:
```
[u32 length][payload bytes]
```

CRC32 checksum is computed over the written data. The ring wraps around using modulo arithmetic.

### 7.3 Synchronization

- Writers atomically store the new tail after writing
- Readers atomically store the new head after reading
- Futex wake/wait on `wake_flag` for blocking
- All channel operations are non-blocking (`send` returns false if full, `recv` returns null if empty)

---

## 8. Network Protocols

### 8.1 Ethernet Frame

```
Offset  Size  Field
0       6     Destination MAC
6       6     Source MAC
12      2     EtherType (0x0806=ARP, 0x0800=IPv4)
14      ...   Payload
```

Minimum frame size: 60 bytes (excluding FCS). The router pads ARP replies to 60 bytes.

### 8.2 ARP

```
Offset  Size  Field
14      2     Hardware Type (0x0001 = Ethernet)
16      2     Protocol Type (0x0800 = IPv4)
18      1     Hardware Address Length (6)
19      1     Protocol Address Length (4)
20      2     Operation (0x0001=Request, 0x0002=Reply)
22      6     Sender Hardware Address (MAC)
28      4     Sender Protocol Address (IP)
32      6     Target Hardware Address (MAC)
38      4     Target Protocol Address (IP)
```

### 8.3 IPv4

```
Offset  Size  Field
14      1     Version (4) + IHL (5 = 20 bytes)
15      1     DSCP/ECN
16      2     Total Length
18      2     Identification
20      2     Flags + Fragment Offset
22      1     TTL
23      1     Protocol (1 = ICMP)
24      2     Header Checksum
26      4     Source IP
30      4     Destination IP
```

### 8.4 ICMP Echo

```
Offset     Size  Field
IP+0       1     Type (8=Request, 0=Reply)
IP+1       1     Code (0)
IP+2       2     Checksum
IP+4       2     Identifier
IP+6       2     Sequence Number
IP+8       ...   Data (56 bytes of payload)
```

The router uses identifier `0x5A47` ("ZG") for outbound pings.
