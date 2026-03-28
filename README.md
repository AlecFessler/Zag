# Zag

A capability-based microkernel written in Zig, targeting x86-64, with a bare-metal network router (routerOS) built on top.

## Prerequisites

- Zig compiler (0.15+)
- NASM (for SMP trampoline assembly)
- QEMU with KVM support
- OVMF UEFI firmware (`/usr/share/ovmf/x64/OVMF.4m.fd`)
- Python 3 with venv (for router integration tests)

## Building

The routerOS has its own build system. Always build routerOS first, then the kernel (the kernel embeds the routerOS ELF into the boot image).

### RouterOS (QEMU with e1000 virtual NICs)

```bash
cd routerOS && zig build -Dnic=e1000
cd .. && zig build -Dprofile=router
```

### RouterOS (bare metal with Intel x550 NIC)

```bash
cd routerOS && zig build -Dnic=x550
cd .. && zig build -Dprofile=router -Diommu=amd
```

The `-Dnic` flag selects the NIC driver (e1000 for QEMU, x550 for real hardware). The `-Diommu` flag selects the IOMMU type for the QEMU guest device (intel default, amd for AMD-based systems). On bare metal the kernel auto-detects the IOMMU from ACPI tables.

### Kernel tests

```bash
zig build -Dprofile=test
```

### Build options

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `-Dprofile` | `router`, `test`, `bench` | none | Sets defaults for other flags |
| `-Dnic` | `e1000`, `x550` | `x550` | NIC driver (routerOS build) |
| `-Dpassthrough` | `true`, `false` | `false` | Skip NIC reset for VFIO passthrough (routerOS build) |
| `-Dkvm` | `true`, `false` | `true` | KVM acceleration |
| `-Diommu` | `intel`, `amd` | `intel` | QEMU guest IOMMU device |
| `-Ddisplay` | `none`, `gtk`, `sdl` | `none` | QEMU display |
| `-Dnet` | `tap`, `user`, `passthrough`, `none` | profile-dependent | QEMU network type |
| `-Duse-llvm` | `true`, `false` | profile-dependent | Force LLVM+LLD backend |

### Running in QEMU

```bash
zig build run -Dprofile=router   # boots router with tap networking
zig build run -Dprofile=test     # runs kernel test suite
```

The kernel boots via UEFI, brings up all CPU cores, enumerates PCI devices and serial ports, then launches the root service with full capabilities.

## Testing

### Quick start

```bash
./test.sh              # run kernel + router tests
./test.sh kernel       # kernel tests only
./test.sh router       # router integration tests only
./test.sh kernel-fuzz  # all kernel fuzzers
./test.sh router-fuzz  # router fuzzer
./test.sh -h           # full usage
```

### Kernel test suite

The test root service (`kernel/tests/`) exercises every syscall and validates kernel behavior against the specification. Tests reference specific spec sections (e.g., `S2.3`, `S4.vm_reserve`). 18 test modules with 9 embedded child processes.

```bash
./test.sh kernel
# or directly:
zig build run -Dprofile=test
```

The suite prints pass/fail for each test, reports total elapsed time, and calls `shutdown` to cleanly exit QEMU.

### Router integration tests (e1000, QEMU)

134 pytest-based integration tests covering ARP, DHCP (server + client), DNS relay/cache, firewall, NAT, port forwarding, IPv6, fragmentation, HTTP management API, NFS, NTP, UPnP, PCP, traceroute, and more.

**One-time setup** (requires sudo):

```bash
sudo routerOS/tests/setup_network.sh   # creates tap0/tap1 interfaces
sudo routerOS/tests/setup_sudo.sh      # sets up namespace + capabilities
```

The test runner (`test.sh router`) handles venv creation and builds automatically. Or manually:

```bash
cd routerOS/tests
python3 -m venv .venv
.venv/bin/pip install pytest pexpect
.venv/bin/pytest -v                    # all 134 tests
.venv/bin/pytest test_dns.py -v        # single test file
.venv/bin/pytest -k test_nat -v        # filter by name
```

### Bare metal (SSD boot)

For testing on real hardware with the x550 NIC:

```bash
# 1. Build routerOS and kernel
cd routerOS && zig build -Dnic=x550
cd .. && zig build -Dprofile=router -Diommu=amd

# 2. Flash to SSD (requires the SSD mounted)
sudo tools/flash_ssd.sh
```

The flash script copies `BOOTX64.EFI`, `kernel.elf`, and `routerOS.elf` to the EFI system partition. Boot the target machine from the SSD via UEFI.

### Fuzzers

```bash
./test.sh kernel-fuzz                                # all kernel fuzzers
./test.sh kernel-fuzz --iterations 50000 --seed 123  # custom params
./test.sh router-fuzz                                # router packet fuzzer
./test.sh router-fuzz --seed 42 --iterations 100000  # custom params
```

Individual fuzzers:

```bash
cd fuzzing/buddy_allocator && zig build fuzz -- -s 42 -i 100000
cd fuzzing/heap_allocator && zig build fuzz -- -s 42 -i 100000
cd fuzzing/vmm && zig build fuzz -- -s 42 -i 100000
cd fuzzing/red_black_tree && zig build fuzz -- -s 42 -i 100000
cd fuzzing/router && zig build run -- -s 42 -i 100000
```

### Kernel unit tests

```bash
zig test kernel/memory/buddy_allocator.zig
zig test kernel/containers/red_black_tree.zig
```

## Documentation

- **[Kernel Specification](docs/spec.md)** --- Observable behavior from userspace. Syscall API, capability model, error codes, device types, system limits.
- **[Kernel Systems Design](docs/systems.md)** --- Internal architecture and implementation. Data structures, algorithms, memory management, scheduling, page tables.
- **[Userspace Library](docs/userspace_lib.md)** --- Reference for libz (syscall wrappers, permissions, channels, sync primitives).
- **[RouterOS Specification](docs/routerOS/spec.md)** --- RouterOS user-facing behavior. Network protocols, DHCP, DNS, NAT, firewall, console commands.
- **[RouterOS Systems Design](docs/routerOS/system.md)** --- RouterOS internals. Zero-copy forwarding, DMA layout, lock-free data plane, NIC drivers.
- **[RouterOS Console](docs/routerOS/console.md)** --- Console command reference with examples.

## Architecture

```
kernel/           Microkernel
  arch/             Architecture-specific (x64, aarch64 placeholder)
  boot/             UEFI boot protocol
  containers/       Data structures (red-black tree)
  devices/          Device registry
  memory/           PMM, VMM, SHM, stacks, slab/buddy/heap allocators
  perms/            Capability permission types
  sched/            Scheduler, process, thread, futex, sync
  tests/            Kernel test suite (root service + child processes)

routerOS/         Bare-metal network router
  root_service/     Process broker (spawns and monitors all services)
  router/           Packet processing, NAT, firewall, DHCP, DNS, IPv6
    hal/              Hardware abstraction (e1000, x550, DMA)
    protocols/        Network protocol implementations
  console/          Serial console CLI
  serial_driver/    UART driver
  nfs_client/       NFSv3 client
  ntp_client/       SNTP client
  http_server/      HTTP management API + web UI
  tests/            Integration tests (pytest)

libz/             Userspace library (shared by all processes)
bootloader/       UEFI bootloader
fuzzing/          Fuzzers (buddy, heap, vmm, red-black tree, router)
tools/            Deployment scripts (flash_ssd.sh)
docs/             Specification and design documents
```

## Kernel capabilities

- Process isolation with capability-based access control
- Shared memory IPC with reference counting
- MMIO device mapping and port I/O syscalls for userspace drivers
- PCI device enumeration with vendor/device/class metadata
- IOMMU support (Intel VT-d and AMD-Vi) for DMA isolation
- Process restart (crash recovery) with configurable persistence
- Futex-based synchronization (cross-process via SHM)
- ASLR and stack guard pages
- SMP support (up to 64 cores) with per-core pinning
