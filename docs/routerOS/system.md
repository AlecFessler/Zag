# RouterOS System Design

RouterOS is a userspace network router for the Zag microkernel. The router process directly owns both NIC devices (e1000 in QEMU, x550 on bare metal) and performs all routing logic in-process with zero-copy packet forwarding.

---

## 1. Architecture

### 1.1 Process Hierarchy

```
root_service (broker)
├── serial_driver    (UART 16550)
├── router           (WAN + LAN NIC + NAT/ARP/firewall/DHCP/DNS)
├── nfs_client       (NFSv3 over UDP, connects to router)
├── ntp_client       (SNTPv4 over UDP, connects to router)
├── http_server      (web management GUI on LAN port 80)
└── console          (serial line editor, connects to router + NFS + NTP)
```

### 1.2 Thread Model

The router process runs three threads:

| Thread | Role | Core | Preemption |
|--------|------|------|------------|
| WAN thread | Poll WAN RX, route, maintenance | Core 1 (pinned) | Non-preemptible |
| LAN thread | Poll LAN RX, route, forward to WAN | Core 2 (pinned) | Non-preemptible |
| Service thread | Console commands, NFS/NTP channels | Core 0 | Preemptive |

The WAN and LAN threads are pinned exclusively to dedicated cores via `pin_exclusive`, making them non-preemptible for maximum packet processing throughput. The service thread handles all management-plane operations (console commands, NFS/NTP app messages, channel detection) on core 0 under normal preemptive scheduling, ensuring console commands never stall the data plane.

### 1.3 Data Flow

```
Host WAN (tap0) ←→ e1000e ←→ WAN thread ←→ [zero-copy DMA] ←→ LAN thread ←→ e1000e ←→ Host LAN (tap1)
                                  ↕
                           console/NFS channels
```

### 1.4 Addressing

| Interface | IP | Subnet | MAC |
|-----------|------|--------|-----|
| WAN | 10.0.2.15 (or DHCP) | 10.0.2.0/24 | 52:54:00:12:34:56 |
| LAN | 10.1.1.1 | 10.1.1.0/24 | 52:54:00:12:34:57 |

---

## 2. Zero-Copy Forwarding

### 2.1 Shared DMA Region

One SHM region mapped to both e1000e devices. Both NICs DMA to/from the same physical pages.

```
Pages   Content
0       WAN RX descriptors (32 × 16B)
1       WAN TX descriptors (32 × 16B)
2       LAN RX descriptors (32 × 16B)
3       LAN TX descriptors (32 × 16B)
4-19    WAN RX packet buffers (32 × 2KB)
20-35   LAN RX packet buffers (32 × 2KB)
36-51   WAN local TX buffers (32 × 2KB)
52-67   LAN local TX buffers (32 × 2KB)
```

### 2.2 Forwarding Path (0 copies)

1. WAN e1000e receives packet into WAN RX buffer via DMA
2. WAN thread modifies IP/TCP/UDP headers **in-place** in the DMA buffer
3. WAN thread points LAN TX descriptor at the WAN RX buffer's DMA address
4. LAN e1000e transmits from the WAN RX buffer — zero copies
5. Next iteration: WAN thread reclaims the buffer after LAN TX completes

### 2.3 Local Packet Path

For locally-generated packets (ARP replies, DHCP, ICMP echo replies):
- Main thread writes packet to a lock-free pending TX slot (atomic flag + buffer)
- Poll thread drains the slot and sends via the local TX buffer pool

---

## 3. Lock-Free Design

### 3.1 NAT Table

Open-addressing hash table with atomic entry states:
- **Insert** (LAN thread): CAS on state field (empty/expired → active)
- **Lookup** (both threads): atomic load of state, compare key fields
- **Expiry** (WAN thread): atomic store of state (active → expired)
- **Port allocation**: `@atomicRmw(.Add)` on `next_nat_port`

### 3.2 Per-Thread Ownership

| Resource | Owner | Access |
|----------|-------|--------|
| WAN RX/TX rings | WAN thread | Exclusive |
| LAN RX/TX rings | LAN thread | Exclusive |
| WAN ARP table | WAN thread | Exclusive |
| LAN ARP table | LAN thread | Exclusive |
| NAT table | Both | Lock-free atomics |
| Console/NFS channels | Service thread | Exclusive |
| Pending TX slots | Writer: any, Reader: owning poll thread | Atomic flag |

---

## 4. NIC Driver

The router supports two NIC drivers, selected at build time with `-Dnic=e1000` (QEMU) or `-Dnic=x550` (bare metal). For bare metal, also pass `-Dpassthrough=true`.

**Files:** `router/hal/e1000.zig`, `router/hal/x550.zig`

Both drivers implement the same interface. Key operations:

- **Init**: Reset, set link up, configure RX/TX descriptor rings, enable RCTL
- **RX poll**: Check DD bit on next descriptor, return buffer index
- **TX zero-copy**: Point TX descriptor at arbitrary DMA address (other NIC's RX buffer)
- **TX local**: Copy data to local TX buffer, program descriptor
- **Bus master**: Enabled via `pci_enable_bus_master` syscall after NIC reset

### PCI Enumeration

The kernel registers only the first MMIO BAR per PCI function. Bus master is enabled during PCI enumeration for network devices.

---

## 5. Web Management GUI

**File:** `router/services/http.zig`

A minimal HTTP/1.0 server running on LAN port 80. Serves an embedded HTML/CSS/JS management page that displays router status, ARP table, NAT table, DHCP leases, firewall rules, and port forwards. The page auto-refreshes every 5 seconds via AJAX.

### TCP State Machine

Single-connection HTTP server with states: closed, syn_received, established, fin_wait. Handles SYN → SYN-ACK → data → FIN handshake inline within the packet processing pipeline.

### API Endpoints

| Endpoint | Returns |
|----------|---------|
| `GET /` | HTML management page |
| `GET /api/status` | Interface IPs, MACs, gateway |
| `GET /api/ifstat` | RX/TX/drop counters |
| `GET /api/arp` | ARP table entries |
| `GET /api/nat` | NAT connection tracking |
| `GET /api/leases` | DHCP lease table |
| `GET /api/rules` | Firewall rules + port forwards |

### Access

From a LAN-side host: `http://10.1.1.1/`

---

## 6. NFS Client

**Files:** `nfs_client/main.zig`, `nfs_client/nfs3.zig`, `nfs_client/rpc.zig`, `nfs_client/xdr.zig`

NFSv3 over UDP, using AUTH_UNIX (uid=0, gid=0). Communicates with the router via SHM channel for UDP send/recv.

### Operations

| Command | NFS Procedure | Status |
|---------|--------------|--------|
| mount | MOUNTPROC_MNT | ✓ Working |
| ls | READDIR | ✓ Working |
| cat | LOOKUP + READ | ✓ Working |
| put | CREATE + WRITE + COMMIT | ✓ Working |
| mkdir | MKDIR | ✓ Working |
| rm | REMOVE | ✓ Working |

---

## 7. Build and Test

### 7.1 Directory Structure

```
routerOS/
  build.zig              — builds all child processes + root service
  linker.ld              — links .bss into .data for zero-init
  root_service/main.zig  — spawns router with NIC device handles
  serial_driver/main.zig
  router/
    main.zig             — entry point, thread spawn, WAN poll loop
    hal/e1000.zig        — e1000 NIC driver (QEMU)
    hal/x550.zig         — x550 NIC driver (bare metal)
    dma.zig              — shared DMA region layout + setup
    iface.zig            — per-interface state, zero-copy TX, lock-free pending TX
    nat.zig              — lock-free NAT hash table
    arp.zig, firewall.zig, dhcp_client.zig, dhcp_server.zig,
    dns.zig, ping.zig, udp_fwd.zig, frag.zig, util.zig
  console/main.zig
  nfs_client/main.zig, nfs3.zig, rpc.zig, xdr.zig
```

### 7.2 Host Setup

```bash
# WAN
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

# LAN
sudo ip tuntap add dev tap1 mode tap user $USER
sudo ip addr add 10.1.1.50/24 dev tap1
sudo ip link set tap1 up

# NFS server (for NFS client testing)
sudo mkdir -p /export/zagtest
sudo chmod 777 /export/zagtest
echo '/export/zagtest 10.0.2.0/24(rw,sync,no_subtree_check,no_root_squash)' | sudo tee /etc/exports
sudo exportfs -ra
sudo systemctl start nfs-server
echo "written by host" > /export/zagtest/hello.txt
```

### 7.3 Build

```bash
# Build routerOS userspace for QEMU
cd routerOS && zig build -Dnic=e1000

# Build routerOS userspace for bare metal
cd routerOS && zig build -Dnic=x550

# Build kernel for QEMU tap tests (from repo root)
zig build -Dprofile=router

# Build kernel for bare metal with AMD IOMMU (from repo root)
zig build -Dprofile=router -Diommu=amd
```

The bootloader loads `root_service.elf` from the FAT image alongside `kernel.elf`. The `-Dprofile=router` flag sets defaults for all build options (tap networking, LLVM backend, KVM, routerOS binary).

### 7.4 Testing

```bash
# Host → Router ping
ping 10.0.2.15

# NFS (via serial console)
# Commands: ls, cat <file>, put <file>, mkdir <dir>, rm <file>
```

### 7.5 Device Configuration

| Setting | Value |
|---------|-------|
| NIC model | e1000 (QEMU) / x550 (bare metal) |
| Machine | Q35 |
| IOMMU | Optional for QEMU; AMD IOMMU for bare metal (`-Diommu=amd`) |
| DMA | Contiguous physical pages via SHM |

### 7.6 Known Issues

- `cat` immediately after `put` may timeout due to serial protocol timing
- QEMU IOMMU (VT-d/AMD-Vi) breaks e1000e RX DMA; `mem_dma_map` falls back to physical addresses when no IOMMU is present
- BSS section merged into .data in linker script to ensure zero-initialization (Zig `undefined` globals)
