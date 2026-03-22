# Zag

A capability-based microkernel written in Zig, targeting x86-64.

## Building

Requirements: Zig 0.15+, NASM, QEMU, OVMF firmware.

```
# Build and run in QEMU with KVM
zig build run -Darch=x64 -Duse-llvm=true -Dkvm=true

# Build and run without KVM (TCG emulation)
zig build run -Darch=x64 -Duse-llvm=true -Dkvm=false
```

The kernel boots via UEFI, brings up all CPU cores, enumerates PCI devices and serial ports, then launches the root service with full capabilities.

## Test Suite

The root service (`userspace/tests/root_service/`) is a comprehensive test suite that exercises every syscall and validates kernel behavior against the specification. Tests reference specific spec sections (e.g., `S2.3`, `S4.vm_reserve`).

```
# Build the test binary
cd userspace/tests/root_service && zig build

# Run (from repo root)
zig build run -Darch=x64 -Duse-llvm=true -Dkvm=true
```

The test suite prints pass/fail for each test, reports total elapsed time, and calls `shutdown` to cleanly exit QEMU.

## Documentation

- **[Specification](docs/spec.md)** — The kernel's observable behavior from userspace. Syscall API, capability model, error codes, device types, system limits. What you need to write a conformant implementation.

- **[Systems Design](docs/systems.md)** — Internal architecture and implementation details. Data structures, algorithms, memory management, scheduling, page table management, architecture abstraction layer.

## Architecture

```
kernel/
  arch/         Architecture-specific (x64, aarch64 placeholder)
    dispatch.zig   Portable arch wrapper API
    x64/           x86-64 implementation
  boot/         UEFI boot protocol
  containers/   Data structures (red-black tree)
  debug/        Debug info (DWARF symbols)
  devices/      Device registry
  memory/       PMM, VMM, SHM, stacks, slab/buddy/heap allocators
  perms/        Capability permission types
  sched/        Scheduler, process, thread, futex, sync
  utils/        ELF loader, range utilities

userspace/
  lib/          Userspace library (syscall wrappers, permissions, test framework)
  tests/        Test programs (root service + child processes)

bootloader/     UEFI bootloader
docs/           Specification and design documents
```

## Capabilities

The kernel provides:
- Process isolation with capability-based access control
- Shared memory IPC with reference counting
- MMIO device mapping and port I/O syscalls for userspace drivers
- PCI device enumeration with vendor/device/class metadata
- Process restart (crash recovery) with configurable persistence
- Futex-based synchronization (cross-process via SHM)
- ASLR and stack guard pages
- SMP support (up to 64 cores)
