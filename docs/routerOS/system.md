# RouterOS System Design

RouterOS is a userspace network router for the Zag microkernel. The router process directly owns both e1000e NIC devices and performs all routing logic in-process with zero-copy packet forwarding.

---

## 1. Architecture

### 1.1 Process Hierarchy

```
root_service (broker)
├── serial_driver    (UART 16550)
├── router           (e1000e WAN + LAN + NAT/ARP/firewall/DHCP/DNS)
├── nfs_client       (NFSv3 over UDP, connects to router)
└── console          (serial line editor, connects to router + NFS)
```

### 1.2 Thread Model

The router process runs two threads:

| Thread | Role | Affinity |
|--------|------|----------|
| WAN thread | Poll WAN RX, route, channels (console/NFS), maintenance | Initial thread |
| LAN thread | Poll LAN RX, route, forward to WAN | Spawned via thread_create |

Both threads are lock-free. No mutexes anywhere in the data path.

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
| LAN | 192.168.1.1 | 192.168.1.0/24 | 52:54:00:12:34:57 |

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
| Console/NFS channels | WAN thread | Exclusive |
| Pending TX slots | Writer: any, Reader: owning poll thread | Atomic flag |

---

## 4. NIC Driver (e1000e)

**File:** `router/e1000.zig`

The e1000e Intel Gigabit Ethernet controller is driven directly from the router process. Key operations:

- **Init**: Reset, set link up, configure RX/TX descriptor rings, enable RCTL
- **RX poll**: Check DD bit on next descriptor, return buffer index
- **TX zero-copy**: Point TX descriptor at arbitrary DMA address (other NIC's RX buffer)
- **TX local**: Copy data to local TX buffer, program descriptor
- **Bus master**: Enabled via `pci_enable_bus_master` syscall after e1000e reset

### PCI Enumeration

The kernel registers only the first MMIO BAR per PCI function (e1000e has multiple BARs). Bus master is enabled during PCI enumeration for network devices.

---

## 5. NFS Client

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

## 6. Build and Test

### 6.1 Directory Structure

```
userspace/routerOS/
  build.zig              — builds all child processes + root service
  linker.ld              — links .bss into .data for zero-init
  root_service/main.zig  — spawns router with NIC device handles
  serial_driver/main.zig
  router/
    main.zig             — entry point, thread spawn, WAN poll loop
    e1000.zig            — e1000e NIC driver (parameterized, no globals)
    dma.zig              — shared DMA region layout + setup
    iface.zig            — per-interface state, zero-copy TX, lock-free pending TX
    nat.zig              — lock-free NAT hash table
    arp.zig, firewall.zig, dhcp_client.zig, dhcp_server.zig,
    dns.zig, ping.zig, udp_fwd.zig, frag.zig, util.zig
  console/main.zig
  nfs_client/main.zig, nfs3.zig, rpc.zig, xdr.zig
```

### 6.2 Host Setup

```bash
# WAN
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

# LAN
sudo ip tuntap add dev tap1 mode tap user $USER
sudo ip addr add 192.168.1.50/24 dev tap1
sudo ip link set tap1 up

# NFS server (for NFS client testing)
sudo mkdir -p /export/zagtest
sudo chmod 777 /export/zagtest
echo '/export/zagtest 10.0.2.0/24(rw,sync,no_subtree_check,no_root_squash)' | sudo tee /etc/exports
sudo exportfs -ra
sudo systemctl start nfs-server
echo "written by host" > /export/zagtest/hello.txt
```

### 6.3 Build

```bash
# Build routerOS userspace (from userspace/routerOS/)
cd userspace/routerOS && zig build

# Build kernel + run with routerOS (from repo root)
zig build run -Dprofile=router

# Or with individual flags:
zig build run -Droot-service=userspace/bin/routerOS.elf -Dnet=tap -Duse-llvm=true
```

The bootloader loads `root_service.elf` from the FAT image alongside `kernel.elf`. The `-Dprofile=router` flag sets defaults for all build options (tap networking, LLVM backend, KVM, routerOS binary).

### 6.4 Testing

```bash
# Host → Router ping
ping 10.0.2.15

# NFS (via serial console)
# Commands: ls, cat <file>, put <file>, mkdir <dir>, rm <file>
```

### 6.5 Device Configuration

| Setting | Value |
|---------|-------|
| NIC model | e1000e (QEMU) |
| Machine | Q35 |
| IOMMU | Optional (dma_map works with or without) |
| DMA | Contiguous physical pages via SHM |

### 6.6 Known Issues

- `cat` immediately after `put` may timeout due to serial protocol timing
- QEMU IOMMU (VT-d/AMD-Vi) breaks e1000e RX DMA; `dma_map` falls back to physical addresses when no IOMMU is present
- BSS section merged into .data in linker script to ensure zero-initialization (Zig `undefined` globals)
