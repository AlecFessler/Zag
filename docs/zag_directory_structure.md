# 🗂️ Zag Project Directory Structure

This document explains the structure and naming conventions of the Zag kernel project.

---

## Root-Level Layout

```
Zag/
├── build.zig         # Zig build script for building the kernel and ISO
├── linker.ld         # Linker script used to control kernel memory layout
├── docs/             # Project documentation (like this file)
├── iso/              # Build output for bootable ISO image
├── kernel/           # Kernel source code
├── zig-out/          # Zig's default build output directory
├── Zag.iso        # Final bootable ISO (copied here from `iso/`)
```

---

## kernel/ — Core Kernel Code

This directory contains all kernel source files, organized by subsystem.

---

### kernel/arch/

- Architecture-specific implementations
- Subdirectories are named after the architecture (e.g., `x86_64`)
- Files within match the names of HAL interfaces they implement

Example:
```
kernel/arch/<arch_name>/<hal_interface>.zig
```

---

### kernel/boot/

- Bootloader-related files
- Contains a generic bootloader interface
- Subdirectories for each supported bootloader (e.g., `grub/`)
- Filenames within bootloader subdirectories indicate boot protocol/version

Example:
```
kernel/boot/<bootloader_name>/<boot_protocol>.zig
```

---

### kernel/hal/

- Hardware Abstraction Layer interface definitions
- Each file defines an abstract interface for a system component (CPU, memory, TTY, etc.)
- Interfaces should be generic and architecture-agnostic

Example:
```
kernel/hal/<hal_interface>.zig
```

---

### kernel/drivers/

- Device drivers implementing HAL interfaces
- Subdirectories match HAL interface names
- Files inside are named after the device or class of device they support

Example:
```
kernel/drivers/<hal_interface>/<device_name>.zig
```

---

### kernel/containers/

- Generic container data structures (trees, lists, queues, etc.)
- Reusable across all kernel subsystems

Example:
```
kernel/containers/<data_structure>.zig
```

---

### kernel/memory/

- Memory management subsystems
- Includes physical and virtual memory managers, allocators, etc.

Example:
```
kernel/memory/<allocator_or_manager>.zig
```

---

### kernel/main.zig

- Kernel entry point and core initialization logic

---

## Expansion

Additional kernel subsystems should follow the same structure:
- One top-level directory per subsystem (e.g., `scheduler/`, `fs/`)
- Follow consistent file naming conventions
