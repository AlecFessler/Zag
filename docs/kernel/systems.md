# Zag Microkernel -- Systems Design Document

Internal implementation details. This document describes HOW the kernel is built. For the public specification (WHAT the kernel does), see `spec.md`.

---

## 1. Internal Architecture Overview

Zag is implemented in Zig, targeting x86_64 (with an aarch64 stub). The kernel is a single binary loaded by a bootloader that provides a `BootInfo` structure containing the memory map, XSDP physical address, ELF debug blob, and initial stack pointer.

### Boot Sequence

1. **Bootloader KASLR** -- Before entering the kernel, the bootloader picks a random page-aligned slide within `AddrSpacePartition.kernel_code`, patches all absolute relocations in the kernel ELF (`R_X86_64_64`, `R_X86_64_32S`) by adding the slide, maps each PT_LOAD segment at `vaddr + slide`, and passes the slide to the kernel via `BootInfo.kaslr_slide`. See §KASLR below.
2. `kEntry` -- Bootloader entry point (at relocated address). Switches to the bootloader-provided stack and jumps to `kTrampoline`.
3. `kTrampoline` -- Calls `kMain`, panics on error.
4. `kMain` executes the following in order:
   - `arch.init()` -- IDT, GDT, segment registers, CPU features (bootstrap core only).
   - `memory.init(boot_info.mmap)` -- Physmap setup, buddy allocator init, PMM init, slab allocator init for VMM nodes, tree nodes, SHM objects, device regions, processes, and threads.
   - `memory.initHeap()` -- Kernel heap allocator init.
   - `debug.info.init()` -- ELF symbol table for stack traces. Receives the KASLR slide so DWARF lookups can translate runtime PCs back to link-time addresses.
   - `arch.parseFirmwareTables(xsdp_phys)` -- ACPI parsing: MADT (cores, APIC), HPET, MCFG (PCI ECAM). PCI enumeration and serial port probing. Device registration.
   - `arch.vmInit()` -- Detect hardware virtualization support via CPUID, cache availability flag. After firmware tables (needs CPUID), before scheduler.
   - `arch.pmuInit()` -- Detect hardware PMU support via CPUID (x64) or stub (aarch64), cache `PmuInfo`, prime PMI handler vector. After firmware tables, before scheduler. See §20.
   - Wall clock offset init: `arch.readRtc()` reads the CMOS RTC (x64) and the kernel computes `wall_offset = rtc_nanos - monotonic_now`. See §22.
   - `sched.globalInit()` -- Process/thread slab allocators, idle process, run queues, root service creation with all rights, device grant to root service, enqueue root service initial thread.
   - `arch.smpInit()` -- Secondary core bringup via INIT/SIPI IPI sequence with real-mode trampoline at physical address `0x8000`.
   - `sched.perCoreInit()` -- Per-core scheduler state, preemption timer arm, `arch.vmPerCoreInit()` (per-core VMX/SVM setup), enable interrupts.
   - `arch.halt()` -- Bootstrap core enters halt loop (scheduler takes over via timer interrupt).

### Architecture Dispatch Layer

`kernel/arch/dispatch.zig` provides a portable interface. Each function dispatches at comptime via `builtin.cpu.arch` to the appropriate architecture module (x64 or aarch64). This is the boundary between architecture-independent kernel code and platform-specific implementations.

### Module Layout

```
kernel/
  main.zig              -- entry point, boot sequence
  zag.zig               -- module root (re-exports)
  panic.zig             -- kernel panic handler
  arch/
    dispatch.zig         -- architecture dispatch layer, ArchCpuContext/PageFaultContext types
    timer.zig            -- Timer vtable interface
    x64/
      init.zig           -- GDT, IDT, CPU features
      paging.zig         -- 4-level page tables
      acpi.zig           -- ACPI parsing, PCI enumeration
      apic.zig           -- LAPIC, I/O APIC, IPI
      timers.zig         -- HPET, LAPIC timer, TSC
      smp.zig            -- secondary core bringup
      serial.zig         -- debug serial output
      cpu.zig            -- MSR, port I/O, CPUID, RDTSC
      gdt.zig            -- per-core GDT/TSS
      idt.zig            -- IDT setup
      irq.zig            -- IRQ routing
      interrupts.zig     -- interrupt vectors, CpuContext
      exceptions.zig     -- fault handlers
      pmu.zig            -- PMU state, save/restore, PMI handler, event mapping
      sysinfo.zig        -- x64 hardware reads for freq, temp, C-state
      rtc.zig            -- CMOS RTC read, BCD-to-Unix conversion
      power.zig          -- ACPI power states, CPU freq/idle control
    aarch64/
      pmu.zig            -- aarch64 PMU stubs (unimplemented)
      sysinfo.zig        -- aarch64 sysinfo stubs (unimplemented)
  memory/
    init.zig             -- memory subsystem initialization
    address.zig          -- VA/PA types, address space layout constants
    fault.zig            -- page fault handler (demand paging)
    pmm.zig              -- physical memory manager with per-core page caches
    vmm.zig              -- virtual memory manager (red-black tree)
    stack.zig            -- kernel and user stack management
    shared.zig           -- shared memory objects
    device_region.zig    -- device region objects
    paging.zig           -- page size constants
    allocators/
      buddy.zig          -- buddy allocator (PMM backing)
      bump.zig           -- bump allocator (early boot, slab backing)
      slab.zig           -- generic typed slab allocator
      heap.zig           -- general-purpose kernel heap
      bitmap_freelist.zig -- bitmap-based free list
      intrusive_freelist.zig -- intrusive linked-list allocator
  proc/
    process.zig          -- process struct, creation, exit, permissions
    restart_context.zig  -- restart context struct
    futex.zig            -- futex wait queue
    message_box.zig      -- MessageBox struct (one type, two instances per Process: msg_box and fault_box)
  sched/
    scheduler.zig        -- run queues, context switch, timer handler
    thread.zig           -- thread struct, creation, deinit
    notification.zig     -- NotificationBox struct and methods (signal, wait, cleanup)
  syscall/
    dispatch.zig         -- SyscallNum enum, SyscallResult type, dispatch switch table
    errors.zig           -- syscall error code constants (E_OK, E_INVAL, etc.)
    clock.zig            -- clock_gettime, clock_getwall, clock_setwall, wall_offset
    device.zig           -- mmio_map, irq_ack, dma_map/unmap
    fault.zig            -- fault_recv, fault_reply, fault_read_mem, fault_write_mem, fault_set_thread_mode
    futex.zig            -- futex_wait, futex_wake
    ipc.zig              -- ipc_send, ipc_call, ipc_recv, ipc_reply, capability transfer
    memory.zig           -- mem_reserve, mem_perms, mem_unmap, shm_create/map
    pmu.zig              -- generic PMU syscall layer, PmuStateAllocator slab owner
    process.zig          -- proc_create, revoke_perm, disable_restart
    sysinfo.zig          -- generic sys_info syscall layer
    system.zig           -- write, getrandom, notify_wait, sys_power, sys_cpu_power
    thread.zig           -- thread_create/exit/yield, set_affinity/priority, suspend/resume/kill
    vm.zig               -- vm_create, vm_guest_map, vm_recv/reply, vcpu_set/get_state, vcpu_run/interrupt, msr_passthrough, ioapic_assert/deassert_irq
  perms/
    permissions.zig      -- rights types, permission entry, user view entry, isSubset helper
    privilege.zig        -- kernel/user privilege enum
    memory.zig           -- MemoryPerms (PTE-level permission flags)
  utils/
    sync.zig             -- SpinLock
    range.zig            -- range utilities
    elf.zig              -- ELF parsing utilities
    debug_info.zig       -- ELF symbol lookup for panic traces
    containers/
      red_black_tree.zig -- generic red-black tree
      priority_queue.zig -- 5-level priority queue (run queues, futex, IPC)
  devices/
    devices.zig          -- device module root
    registry.zig         -- device table and registration
  boot/
    protocol.zig         -- boot protocol struct (bootloader <-> kernel)
  arch/x64/kvm/         -- VM guest support (x86-specific: VT-x/AMD-V, EPT/NPT, VMCB)
    kvm.zig              -- module root (re-exports)
    vm.zig               -- Vm struct, vm_create, vm_guest_map, vm_msr_passthrough, ioapic_assert/deassert_irq
    vcpu.zig             -- VCpu struct, vm_vcpu_run, vm_vcpu_set_state, vm_vcpu_get_state, vm_vcpu_interrupt, vCPU entry loop
    exit_box.zig         -- VmExitBox, VmExitMessage, VmReplyAction, vm_recv, vm_reply
    exit_handler.zig     -- VM exit dispatch (kernel-handled vs VMM-handled classification)
    guest_memory.zig     -- guest physical address space tracking and cleanup
    lapic.zig            -- in-kernel Local APIC emulation (xAPIC, timer, IRR/ISR/TMR, EOI, ICR)
    ioapic.zig           -- in-kernel I/O APIC emulation (24-entry redirection table, level/edge)
  arch/x64/mmio_decode.zig -- x86-64 MMIO instruction decoder — shared by VM LAPIC/IOAPIC handlers and virtual BAR emulation. Exports decodeBytes (byte-buffer API) and MmioOp; GPR read/write is caller-specific
```

---

## 2. Process Internals

### Process Struct

Defined in `kernel/proc/process.zig`:

```
Process {
    pid: u64
    parent: ?*Process
    alive: bool
    restart_context: ?*RestartContext
    addr_space_root: PAddr
    vmm: VirtualMemoryManager
    threads: [MAX_THREADS]*Thread          -- fixed-size array, MAX_THREADS = 64
    num_threads: u64
    children: [MAX_CHILDREN]*Process       -- fixed-size array, MAX_CHILDREN = 64
    num_children: u64
    lock: SpinLock
    perm_table: [MAX_PERMS]PermissionEntry -- fixed-size array, MAX_PERMS = 128
    perm_count: u32
    perm_lock: SpinLock                    -- separate lock for permissions table
    handle_counter: u64                    -- monotonic, per-process
    perm_view_vaddr: VAddr
    perm_view_phys: PAddr                  -- physmap address for kernel writes
    msg_box: MessageBox                    -- encapsulates all IPC message passing state
    fault_box: FaultBox                    -- encapsulates all fault message state
    fault_handler_proc: ?*Process          -- null = self-handling
    faulted_thread_slots: u64             -- bitmask: bit i set = threads[i] in .faulted state
    suspended_thread_slots: u64           -- bitmask: bit i set = threads[i] in .suspended state
    fault_reason: FaultReason              -- reason for last fault (u5, .none if no fault)
    restart_count: u16                     -- number of restarts (wraps on overflow)
    thread_handle_rights: ThreadHandleRights -- rights mask for thread handles in this process's own perm table
    max_thread_priority: Priority           -- ceiling priority for threads in this process
    vm: ?*arch.Vm = null                     -- owned VM, if any (at most one per process; dispatched type)
    notification_box: NotificationBox       -- IRQ notification delivery (§24)
    badge_counter: u6 = 0                   -- monotonic mod-64 counter for badge bit assignment (§24)
}
```

### Constants

- `MAX_THREADS = 64` -- maximum threads per process.
- `MAX_CHILDREN = 64` -- maximum child processes.
- `MAX_PERMS = 128` -- maximum permissions table entries.
- `HANDLE_SELF = 0` -- reserved self-handle at slot 0.
- `DEFAULT_STACK_PAGES = 4` -- default user stack size.

### Allocation

Processes are allocated from a `SlabAllocator(Process, false, 0, 64)` -- a slab allocator with 64-element chunks, backed by a bump allocator over the process slab VA region.

### Locking Order

Two locks per process: `lock` (general fields, thread list, children) and `perm_lock` (permissions table). Parent's locks before child's locks. The `perm_lock` is acquired independently for permission lookups and mutations.

### Permission Table Init

`initPermTable` clears all 128 slots to the empty sentinel (`handle = U64_MAX`, `object = .empty`), then places `HANDLE_SELF` at slot 0 with the given `ProcessRights`. Calls `syncUserView` to write the initial state.

### syncUserView

Writes all 128 entries from the kernel-side `perm_table` to the user-visible view via physmap. The user view physical address (`perm_view_phys`) is converted to a kernel VA via `VAddr.fromPAddr`, cast to a `*[MAX_PERMS]UserViewEntry`, and all entries are written using `UserViewEntry.fromKernelEntry`.

`syncUserView` fires only on kernel perm-table mutations: insert, remove, `KernelObject` type change (e.g. `process → dead_process`), and content changes to existing slots (rights bit updates, `restart_count`/`fault_reason` updates on process slot 0, `exclude_oneshot`/`exclude_permanent` toggles on thread slots). Transient thread scheduling-state transitions (`.running`/`.ready`/`.blocked`) do NOT trigger `syncUserView`; syncing them would require cache bouncing across every handle holder on every scheduler dispatch. Observable thread state transitions that userspace cares about have dedicated channels: `.faulted` via `fault_recv`, `.suspended` via the `thread_suspend` syscall return code, and `.exited` via perm entry removal (which IS a mutation, so sync fires).

### Handle Counter

Per-process monotonic `u64`. Incremented on every `insertPerm`. Starts at 1 (handle 0 is `HANDLE_SELF`, populated during `initPermTable`). The counter is not a global -- each process has its own counter, so handles are unique within a process but not across processes.

### ELF Loading

ELF loading occurs during `Process.create`. The kernel parses ELF program headers from the parent's address space (the ELF binary pointer must reference committed pages). Each `PT_LOAD` segment is inserted as a kernel-internal VMM node (`handle = HANDLE_NONE`, which is `U64_MAX`).

Restart policy assignment:
- Code segment (RX): `restart_policy = .preserve`
- Read-only data (R): `restart_policy = .preserve`
- Data segment (RW, file-backed): `restart_policy = .preserve` (overwritten from ghost copy on restart)
- BSS segment (RW, zero-filled): `restart_policy = .decommit`

### Restart Context

Defined in `kernel/proc/restart_context.zig`:

```
RestartContext {
    entry_point: VAddr
    data_segment: {
        vaddr: VAddr
        size: u64
        ghost: []u8       -- heap-allocated copy of original data segment
    }
    code_range: VAddrRange { vaddr: VAddr, size: u64 }
    rodata_range: VAddrRange
    perm_view_range: VAddrRange
}
```

Allocated on the kernel heap (`memory_init.heap_allocator`). The ghost copy (`ghost: []u8`) is a heap-allocated duplicate of the original data segment content, used to restore the data segment on restart. Freed via `heap_allocator.destroy`.

### ASLR PRNG

The VMM cursor starts at a random page-aligned offset within the ASLR zone `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)`. Entropy is sourced from `arch.readTimestamp()` (RDTSC on x86_64) at process creation time. The randomized base is page-aligned.

### KASLR

Kernel Address Space Layout Randomization is applied by the bootloader before entering the kernel.

**Build prerequisite**: The kernel is built with `--emit-relocs` (`kernel.link_emit_relocs = true` in build.zig), which preserves `.rela.text` and `.rela.rodata` sections in the final ELF. The kernel retains `.code_model = .kernel` (x86_64 `-mcmodel=kernel`), so all absolute references use sign-extended 32-bit immediates (`R_X86_64_32S`) or 64-bit absolute values (`R_X86_64_64`).

**Slide computation** (`bootloader/main.zig:computeKaslrSlide`):
1. Compute kernel image size from parsed ELF sections (text + rodata + data + bss, page-aligned).
2. Available slide range = `kernel_code.end - kernel_code.start - image_size`.
3. Entropy: `arch.readTimestamp()` (RDTSC).
4. Slide = `(entropy % (range / PAGE4K)) * PAGE4K` -- page-aligned.

**Slide range**: `AddrSpacePartition.kernel_code` = `[0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_C000_0000)`. The kernel is linked at the start of this range. Maximum slide ≈ 1 GiB minus image size (≈ 18 bits of entropy at 4K granularity).

**Relocation fixup** (`bootloader/main.zig:applyKaslrRelocations`): The bootloader walks all `.rela.*` section headers. For each RELA section whose target section has `SHF_ALLOC` set (i.e., loaded into memory):
- `R_X86_64_64`: 8-byte slot at file offset += slide (wrapping add).
- `R_X86_64_32S`: 4-byte slot sign-extended to 64-bit, += slide, truncated back to 32-bit. Safe because the slide keeps values in the -2 GiB..0 canonical window.
- `R_X86_64_PC32`, `R_X86_64_PLT32`, `R_X86_64_NONE`: skipped (PC-relative; uniform slide preserves relative distances).
- Non-allocated section relocations (debug sections): skipped entirely.

Relocations are applied to `file_bytes` in place before the bootloader copies segment data to the mapped destination pages.

**Section mapping**: Each kernel section is mapped at `section.vaddr + slide` instead of `section.vaddr`.

**Entry point**: The bootloader calls `entry + slide`.

**Kernel-side integration**:
- `BootInfo.kaslr_slide` carries the slide into the kernel.
- `debug.info.kaslr_slide` stores it for DWARF symbol resolution; `panic.zig` subtracts the slide from runtime PCs before calling `getSymbolName`.
- SMP: The BSP writes relocated function addresses (taken at runtime, post-slide) into the trampoline parameter block. No special SMP handling required.

---

## 3. VMM Internals

### Red-Black Tree

The VMM uses a `RedBlackTree(*VmNode, vmNodeCmp, true)` where `vmNodeCmp` orders by `start.addr`. The third parameter (`true`) enables duplicate handling. Tree nodes are allocated from `VmTreeSlab = SlabAllocator(VmTree.Node, false, 0, 64)`. VM data nodes are allocated from `VmNodeSlab = SlabAllocator(VmNode, false, 0, 64)`.

Both slabs are initialized at boot from dedicated bump allocator regions (16 MiB each).

### VmNode Struct

```
VmNode {
    start: VAddr
    size: u64
    kind: union(enum) {
        private: void
        shared_memory: *SharedMemory
        mmio: *DeviceRegion
        virtual_bar: *DeviceRegion
    }
    rights: VmReservationRights   -- only rwx bits used at the page level
    handle: u64               -- HANDLE_NONE (U64_MAX) for kernel-internal nodes
    restart_policy: RestartPolicy { free, decommit, preserve }
}
```

`VmNode.end()` returns `start.addr + size`.

`virtual_bar` nodes get `restart_policy = .free` — cleared on restart, device handle persists.

### Sentinel Nodes

`mkSentinel(vaddr)` creates a zero-size VmNode used as a search key for tree lookups:
```
{ start: vaddr, size: 0, kind: .private, rights: {}, handle: HANDLE_NONE, restart_policy: .free }
```

### VirtualMemoryManager Struct

```
VirtualMemoryManager {
    tree: VmTree
    range_start: VAddr
    range_end: VAddr
    addr_space_root: PAddr
    lock: SpinLock
}
```

### Two-Layer Model

- **Permissions table**: holds each reservation's capability (max rights, original range). This is the authority layer.
- **VMM tree**: holds operational state (current rights per sub-region, node type, backing objects). This is the mapping layer.
- **Page tables**: sole source of truth for which physical pages are actually mapped.

### Merge Rules

Two adjacent nodes merge iff all of:
- Both `private`
- Same `handle` value
- Same `current_rights`
- Same `restart_policy`
- Contiguous (first node's end == second node's start)

Never merge across reservation boundaries (different handles). `virtual_bar` nodes never merge with anything.

### Bump Cursor

The VMM cursor (`range_start` field, advanced during allocation) advances monotonically through the ASLR zone. On `reserve` without a hint, the cursor skips past existing nodes to find a free gap. `bump(size)` advances the cursor without creating a tree node -- used during process creation to position past kernel-internal nodes (ELF segments, permissions view, stacks).

### splitNode

Splits a VmNode at a page-aligned offset into two new nodes. Both halves inherit: `kind`, `rights`, `handle`, `restart_policy`. The original node is removed from the tree and replaced with two new nodes. Used by `mem_perms`, `mem_unmap`, `mem_shm_map`, `mem_mmio_map` to operate on sub-ranges of reservations.

### mem_unmap

`mem_unmap` operates in two passes:

1. **Validation pass**: Iterates all nodes in the range. For each non-private node (SHM, MMIO, virtual BAR), verifies that the node is fully contained within the requested range. If any non-private node is only partially overlapped, the syscall returns `E_INVAL` without modifying any state. This makes the operation all-or-nothing with respect to non-private nodes.

2. **Unmap pass**: Iterates all nodes in the range. For private nodes at the boundaries, `splitNode` is used to split at the range edges (same logic as `mem_perms`). For each node in the range:
   - Private nodes: PTEs are stripped and committed pages are freed. The node reverts to demand-paged state with the reservation's max RWX rights.
   - SHM nodes: PTEs are stripped, the SHM backing is detached from the node, and the node kind is set to `private` with the reservation's max RWX rights. The SHM handle remains in the process's permissions table.
   - MMIO nodes: PTEs are stripped, the device region backing is detached, and the node kind is set to `private` with the reservation's max RWX rights. The device handle remains in the process's permissions table.
   - Virtual BAR nodes: The node kind is set to `private` with the reservation's max RWX rights (virtual BAR nodes have no PTEs to strip). The device handle remains in the process's permissions table.

After the unmap pass, adjacent private nodes that share the same handle, rights, and restart policy are merged per the standard merge rules.

### Stack Reservation

`reserveStack(num_pages)` creates three contiguous kernel-internal nodes:
1. Underflow guard: 1 page, rights = none
2. Usable region: N pages, rights = RW (first page eagerly mapped)
3. Overflow guard: 1 page, rights = none

Returns `StackResult { guard, base, top }`.

---

## 4. Permissions Table Internals

### Storage

Fixed-size array of 128 `PermissionEntry` structs per Process. Not a dynamic data structure -- every process has exactly 128 slots regardless of usage.

### PermissionEntry

```
PermissionEntry {
    handle: u64
    object: KernelObject (tagged union)
    rights: u16
    exclude_oneshot: bool     -- thread entries: next fault from this thread skips stop-all
    exclude_permanent: bool   -- thread entries: all faults from this thread skip stop-all
}
```

The `exclude_oneshot` and `exclude_permanent` fields are only semantically meaningful for thread-type entries but are present on all entries for uniform struct sizing.

`KernelObject` is a tagged union:
```
KernelObject = union(enum) {
    process: *Process
    dead_process: *Process  // struct stays alive via handle_refcount
    vm_reservation: VmReservationObject { max_rights, original_start, original_size }
    shared_memory: *SharedMemory
    device_region: *DeviceRegion
    core_pin: CorePinObject { core_id }
    thread: *Thread
    empty: void
}
```

### Dead Process Entries

When a non-restartable child process dies, `cleanupPhase2` calls `convertToDeadProcess` on the parent, which replaces the `.process` entry with `.dead_process` storing a `*Process` pointer. The Process struct stays alive via `handle_refcount` until all handle holders revoke. Fault reason and restart count are read from the Process struct fields. The kernel issues a `futex.wake` on the parent's user view field0 physical address for this entry so that watchdog threads blocked on the field are woken. Any handle holder revokes at its convenience via `revoke_perm`, which clears the slot and decrements the refcount.

### Empty Slot Sentinel

Empty slots have `handle = U64_MAX` (0xFFFFFFFFFFFFFFFF) and `object = .empty`. The `U64_MAX` sentinel ensures no valid handle matches an empty slot during lookup.

### Handle Counter

Each process has a per-process monotonic `handle_counter: u64`. On `insertPerm`, the counter is read, assigned to the new entry, and incremented. Slot 0 is always `HANDLE_SELF` (handle ID 0); the counter starts at 1 for subsequent insertions.

### Lookup

`getPermByHandle(handle_id)` acquires `perm_lock`, then linear-scans the 128-entry array for a non-empty entry with matching `handle`. Returns a copy of the entry or null.

### Insert

`insertPerm(entry)` acquires `perm_lock`, linear-scans slots 1..127 for the first empty slot, assigns `handle_counter`, increments counter, writes entry, increments `perm_count`, calls `syncUserView`. Returns the assigned handle ID. Error if all slots full.

### clearByObject

Scans all 128 slots, clears entries whose object pointer matches the given kernel object. Used when a child process is freed -- the parent's handle referencing that child is cleared.

### syncUserView

After every mutation, the kernel writes all 128 entries to the user-visible view. The view is stored in physical pages mapped into the process's address space (read-only to userspace). The kernel writes via physmap using the stored `perm_view_phys` address.

**Two wake channels.** There are two futex channels for observing permission-view changes, and they serve different roles:

1. **Self-notification — slot-0 `field1` generation counter.** `syncUserView` bumps `perm_view_gen` on every mutation and writes it into slot 0's `field1` with release ordering, then futex-wakes that address. Threads within the owning process watch this address to block until *any* slot mutates. This is a broadcast channel scoped to the owning process.

2. **Parent-observes-child — child-slot `field0`.** When a child process's state changes in a way the parent should observe (restart, death, fault — spec §2.6.27 and §2.6.29), the kernel writes the new `field0` (fault_reason / restart_count) into the parent's entry for the child and futex-wakes the parent's `field0` for that slot. Parents watch this address to block until a specific child's state changes.

The two channels coexist: a restart of a child bumps both the parent's slot-0 `field1` (the parent saw *some* mutation) and the specific child-slot `field0` (that particular child changed state). Parents that only care about one child should prefer the child-slot `field0` wake; generic "something changed" observers use the slot-0 `field1` generation counter.

### UserViewEntry

```
UserViewEntry (extern struct, 32 bytes) {
    handle: u64
    entry_type: u8
    _pad0: u8
    rights: u16
    _pad: [4]u8
    field0: u64
    field1: u64
}
```

`EMPTY` sentinel: `handle = U64_MAX, entry_type = 0xFF, rights = 0, field0 = 0, field1 = 0`.

Types: `process = 0, vm_reservation = 1, shared_memory = 2, device_region = 3, core_pin = 4, dead_process = 5, thread = 6`.

Field encoding for thread entries: `field0 = tid(u64)` (the thread's stable kernel-assigned thread id), `field1 = exclude_oneshot(bit 0) | exclude_permanent(bit 1)` reflecting the fault-handler exclude flags on the perm slot. Transient scheduling state is not exposed in the view.

### Rights Types

All rights are packed structs with bit fields:

- `ProcessRights`: packed `u16` -- `spawn_thread`(0), `spawn_process`(1), `mem_reserve`(2), `set_affinity`(3), `restart`(4), `mem_shm_create`(5), `device_own`(6), `fault_handler`(7), `pmu`(8), `set_time`(9), `power`(10), 5 bits reserved.
- `ProcessHandleRights`: packed `u16` -- `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5), `fault_handler`(6), 9 bits reserved. Used on handles to other processes (not HANDLE_SELF).
- `VmReservationRights`: packed `u8` -- `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4), 3 bits reserved.
- `SharedMemoryRights`: packed `u8` -- `read`(0), `write`(1), `execute`(2), `grant`(3), 4 bits reserved.
- `DeviceRegionRights`: packed `u8` -- `map`(0), `grant`(1), `dma`(2), `irq`(3), 4 bits reserved. The `irq` bit gates `irq_ack` (§24).
- `ThreadHandleRights`: packed `u8` -- `suspend`(0), `resume`(1), `kill`(2), `pmu`(4), 4 bits reserved. Bit 3 is reserved for alignment with the public spec layout. The `pmu` bit is checked in addition to `ProcessRights.pmu` on every PMU syscall that takes a thread handle; see §20.

---

## 5. Thread Internals

### Thread Struct

Defined in `kernel/sched/thread.zig`:

```
Thread {
    tid: u64                            -- global monotonic counter
    ctx: *ArchCpuContext                -- saved register state on kernel stack
    kernel_stack: Stack
    user_stack: ?Stack
    process: *Process
    next: ?*Thread = null               -- intrusive singly-linked list pointer
    core_affinity: ?u64 = null          -- core mask (bit per core)
    state: State = .ready               -- { running, ready, blocked, faulted, suspended, exited }
    last_in_proc: bool = false          -- true if this is the last thread in process
    on_cpu: atomic(bool) = false        -- set while thread is actively on a CPU
    slot_index: u8                      -- index of this thread in process.threads[], used for bitmask operations
    priority: Priority                  -- current scheduling priority level (idle/low/normal/high/pinned)
    pre_pin_priority: Priority          -- saved priority before core pin (restored on unpin)
    pre_pin_affinity: ?u64              -- saved affinity mask before core pin (restored on unpin)
    pmu_state: ?*arch.PmuState = null   -- arch-specific PMU counter state; null until pmu_start; freed on pmu_stop or deinit
}
```

### Allocation

Threads are allocated from `SlabAllocator(Thread, false, 0, 64)`, backed by a bump allocator over the thread slab VA region (16 MiB).

### Thread ID

Global atomic counter (`tid_counter`). Each new thread atomically increments via `@atomicRmw(.Add, 1, .monotonic)`.

### Intrusive List Pointer

Threads use a single `next: ?*Thread` pointer for intrusive list membership. A thread is in at most one list at a time (run queue or futex bucket). The spec's `prev` pointer for doubly-linked lists is simplified in the current implementation to a singly-linked `next` pointer.

### on_cpu Flag

Atomic boolean. Set to `true` when a thread is dispatched onto a CPU, set to `false` when preempted in the scheduler timer handler. Futex wake spins on this flag (`while (thread.on_cpu.load(.acquire)) spinLoopHint()`) to ensure the thread has fully saved its context before being re-enqueued.

### State Transition Table

| From | To | Trigger |
|---|---|---|
| `ready` | `running` | Dequeued by scheduler |
| `running` | `ready` | Preempted by timer, yield |
| `running` | `blocked` | Futex wait |
| `running` | `exited` | Thread exit, process kill |
| `blocked` | `ready` | Futex wake |
| `ready` | `exited` | Process kill (removed from run queue) |
| `blocked` | `exited` | Process kill (removed from futex bucket) |
| `running` | `faulted` | Thread faults; fault handler path runs; external handler or self-handler with >1 thread |
| `faulted` | `running` | `fault_reply` with `FAULT_RESUME` or `FAULT_RESUME_MODIFIED` |
| `faulted` | `exited` | `fault_reply` with `FAULT_KILL`; or process kill while thread is `.faulted` |
| `running` | `suspended` | Stop-all from external fault delivery; or `thread_suspend` syscall |
| `ready` | `suspended` | Stop-all from external fault delivery; or `thread_suspend` syscall |
| `suspended` | `ready` | `fault_reply` (any action, releases all `.suspended` threads); or `thread_resume` syscall |
| `suspended` | `exited` | Process kill while thread is `.suspended` |

### Thread Creation

`Thread.create(proc, entry, arg, num_stack_pages)`:
1. Check thread limit (`num_threads + 1 >= MAX_THREADS`).
2. Allocate Thread from slab.
3. Assign TID from global counter.
4. Allocate kernel stack (`stack_mod.createKernel`).
5. Map kernel stack pages (demand-paged, but the first page is identity-mapped for initial context).
6. Allocate user stack (`stack_mod.createUser`) via process VMM.
7. Prepare CPU context: `arch.prepareThreadContext(kstack_top, ustack_top, entry_fn, arg)`.
8. Add to process thread list under process lock.
9. Insert a thread handle into the owning process's perm table (using `insertPerm` with `ThreadHandleRights` from `process.thread_handle_rights`) and return the handle ID.
10. If `process.fault_handler_proc` is non-null, insert the thread handle into the handler's perm table with full `ThreadHandleRights`, and call `syncUserView` on the handler.

### Thread Deinit

`Thread.deinit()`:
1. Save `last_in_proc` flag.
2. If `pmu_state != null`, call `arch.pmuClearState(pmu_state)` to zero the state struct without touching any MSRs, then free the PMU state back to `PmuStateAllocator` and clear the field. The dying thread is not running on any core at this point (exit paths leave the thread off its run queue before tearing it down), so MSR writes on the caller's core would either be a no-op against stale values or clobber the PMU state of whichever thread currently owns the hardware. Real hardware teardown for the dying thread happened at its last `pmuSave` on context switch away. This is the implicit `pmu_stop` on thread exit (§2.14.9, §20).
3. Clear the thread handle entry from the owning process's perm table. If `fault_handler_proc` is non-null, also clear the thread handle entry from the handler's perm table. Call `syncUserView` on all affected tables.
4. Destroy kernel stack (unmap committed pages, recycle slot).
5. If not last thread: destroy user stack via process VMM.
6. Free Thread to slab.
7. If last thread: call `proc.exit()` (triggers restart or cleanup).

The last thread skips user stack destruction because the process exit path tears down the entire address space.

---

## 5a. arch/dispatch.zig: SavedRegs

`kernel/arch/dispatch.zig` provides a comptime dispatch for `SavedRegs`:

```zig
pub const SavedRegs = switch (builtin.cpu.arch) {
    .x86_64  => x64.SavedRegs,
    .aarch64 => aarch64.SavedRegs,
    else     => @compileError("unsupported architecture"),
};
```

`x64.SavedRegs` is defined as an `extern struct` in `kernel/arch/x64/interrupts.zig`:

```
x64.SavedRegs (extern struct) {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rsp: u64, rbp: u64,
    r8:  u64, r9:  u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    rip: u64, rflags: u64,
    cs:  u16, _pad_cs: [6]u8,
    ss:  u16, _pad_ss: [6]u8,
}
```

`aarch64.SavedRegs` is defined as an empty `extern struct` stub in `kernel/arch/aarch64/` (aarch64 fault delivery is not yet implemented; this stub prevents compile errors on the type reference).

`FaultMessage` is materialized at `fault_recv` time from `thread.ctx.regs` (the saved exception entry frame) plus `thread.fault_reason` / `fault_addr` / `fault_rip`.

---

## 6. Run Queue

### PriorityQueue

Defined in `kernel/utils/containers/priority_queue.zig`. A unified data structure used by run queues, futex buckets, and IPC wait queues.

The `PriorityQueue` has 5 per-level FIFO queues (one per priority level), each with a `head` and `tail` pointer. Enqueueing appends to the tail of the thread's level. Dequeueing scans from level 4 (pinned) down to level 0 (idle) and pops the head of the first non-empty level. FIFO order is preserved within each level. The structure has no locks — callers hold their own locks as before. It operates on `Thread.next` directly, same as the prior intrusive list approach. A thread is in at most one queue at a time, so sharing the `next` field across all three queue types (run queue, futex, IPC) remains safe.

```
PriorityQueue {
    levels: [5]struct {
        head: ?*Thread
        tail: ?*Thread
    }
}
```

Methods:
- `enqueue(thread)` — append to the tail of `levels[thread.priority]`.
- `dequeue() -> ?*Thread` — scan from level 4 down to 0, pop head of first non-empty level.
- `remove(target) -> bool` — linear scan across all levels, unlink target.
- `peekHighestStealable(core_id) -> ?*Thread` — scan levels 4→0, return the first thread whose affinity mask includes `core_id` and whose priority is not `pinned`. Called without holding a lock; the result is advisory only.

### Structure

Per-core `RunQueue` wraps `PriorityQueue`. The sentinel node approach is removed. The idle thread is a real thread at priority `idle`, re-enqueued after every timeslice when no real work exists.

```
RunQueue {
    pq: PriorityQueue
}
```

### Per-Core State

```
PerCoreState {
    rq: RunQueue
    rq_lock: SpinLock
    running_thread: ?*Thread
    pinned_thread: ?*Thread     -- thread (if any) that exclusively owns this core
    timer: Timer
    exited_thread: ?ExitedThread -- deferred thread cleanup (renamed from Zombie)
    idle_ns:      u64            -- accumulated idle nanoseconds since last sys_info read
    busy_ns:      u64            -- accumulated busy nanoseconds since last sys_info read
    last_tick_ns: u64            -- monotonic timestamp of last scheduler tick (for delta accounting)
}
```

Array of 64 `PerCoreState` structs (`MAX_CORES = 64`), aligned to `CACHE_LINE_SIZE = 64` bytes to avoid false sharing.

The `idle_ns` / `busy_ns` / `last_tick_ns` fields back the per-core scheduler accounting consumed by `sys_info` (§21). They are updated on every scheduler timer tick and read-and-reset atomically by `sys_info` when `cores_ptr != null`.

### enqueue(thread)

Delegates to `pq.enqueue(thread)`, which appends to the appropriate priority level's tail.

### dequeue() -> ?*Thread

Delegates to `pq.dequeue()`, which returns the highest-priority ready thread, or null if the queue is empty.

### Scheduler Timer Handler

`schedTimerHandler(ctx)`:
1. Clean up exited thread from previous cycle (deferred `deinit`).
2. Save preempted thread's context.
3. Clear preempted thread's `on_cpu` flag.
4. Acquire run queue lock.
5. If this core has a `pinned_thread` that is ready and not currently running: immediately preempt the current thread, attempt to migrate it to another core, and switch to the pinned thread.
6. If the current thread is the pinned thread: never preempt, just re-arm the timer.
7. Otherwise: priority-aware round-robin. If a higher priority thread is ready in the run queue, preempt current thread and switch. If same priority, re-enqueue current and switch. If current is highest, keep running.
8. Set next thread to `running`, set `on_cpu = true`.
9. If preempted thread is `exited`, store as exited_thread for deferred cleanup.
10. Release run queue lock.
11. Arm scheduler timer for next timeslice.
12. If same thread, return. Otherwise, `arch.switchTo(next)`.

### Idle/Busy Accounting Hook

At the top of `schedTimerHandler`, before any scheduling decision, the handler samples the monotonic clock and attributes the elapsed time since the previous tick to either `idle_ns` or `busy_ns` on the core's `PerCoreState`:

```
now = arch.getMonotonicClock().now()
delta = now - per_core.last_tick_ns
if (per_core.running_thread == per_core.idle_thread) {
    per_core.idle_ns += delta
} else {
    per_core.busy_ns += delta
}
per_core.last_tick_ns = now
```

`running_thread` at handler entry is the thread that actually consumed the preceding timeslice, so the attribution decision is "was the idle thread running last tick". `last_tick_ns` is seeded from `arch.getMonotonicClock().now()` in `sched.perCoreInit` before the preemption timer is first armed; until that point `idle_ns` and `busy_ns` are zero.

Each counter is atomically updated via a single `@atomicRmw(.Add, .monotonic)` from the tick hook. The scheduler does NOT hold `rq_lock` for these updates; we rely on per-counter atomicity. The pair (`idle_ns`, `busy_ns`) is therefore not a transactional snapshot for `sys_info` readers — a reader can see a tick's increment attributed to one side without yet seeing the other. This is acceptable because the drift between sides is bounded by one tick (~2 ms), which is far below any reasonable polling cadence. Because accounting is also sampled at scheduler tick granularity (`SCHED_TIMESLICE_NS = 2 ms`), the reported `idle_ns` / `busy_ns` are tick-quantized — the last partial timeslice before a `sys_info` read is attributed to whichever thread was running at the previous tick boundary, not to wall-clock time. Over any accounting window longer than a few timeslices both effects are negligible, and `sys_info` does not attempt to reconcile them.

### PMU Save/Restore Hooks

When the scheduler actually switches threads (step 12 of `schedTimerHandler` and the IPC fast-path `switchToThread`), a pair of null-guarded calls bracket the `arch.switchTo` — both on the *outgoing* side of the switch:

```
if (outgoing.pmu_state) |st| arch.pmuSave(st);
if (next.pmu_state)     |st| arch.pmuRestore(st);
arch.switchTo(next);   // never returns — jmp's into next's interrupt frame
```

Both checks are a single load-and-compare on the hot path. Threads without PMU state (the common case) pay only the null comparison and never touch the PMU hardware. Threads with PMU state round-trip their counter values through arch-specific MSRs on every context switch; this is the cost of making counts per-thread rather than per-core (§2.14.10).

`arch.switchTo` does not return to this frame — on x64 it mov's RSP to the incoming thread's interrupt frame and jmp's to `interruptStubEpilogue`, which iret's into the incoming thread. Any code placed after `switchTo` would be dead on the incoming side and would only run the next time the previously outgoing thread resumes (on its own core). PMU state is per-core MSR state, so the restore must happen *before* the switch, while the kernel is still running on the core the incoming thread will run on immediately. The save is sequenced first so hardware is quiet (the save zeroes `IA32_PERF_GLOBAL_CTRL`) before programming the incoming thread's counters.

### IPI on Thread Ready

When any thread becomes ready (futex wake, IPC delivery, thread_resume), if its priority exceeds the priority of the currently running thread on an affinity-eligible non-pinned core, the kernel sends an IPI immediately to that core rather than waiting for the next timer tick. This ensures high-priority threads are scheduled without waiting for a timeslice boundary.

### Pinned Core Scheduling Invariants

A pinned core is never a target for proactive enqueue from other cores. Threads are only placed on a pinned core's run queue via work stealing, which is initiated by the pinned core itself when it goes idle (because the pinned thread is blocked).

When a pinned thread becomes ready again after blocking, the kernel sends an IPI to the pinned core. Whatever thread is currently running on that core is preempted mid-timeslice regardless of its priority. The preempted thread is migrated to an affinity-eligible non-pinned core if one exists. If no eligible core exists, the thread remains in the pinned core's run queue and will only be scheduled again when the pinned thread next blocks.

### Timeslice

`SCHED_TIMESLICE_NS = 2_000_000` (2 ms).

### Yield

`sched.yield()` triggers a self-IPI: `arch.triggerSchedulerInterrupt(arch.coreID())`. The scheduler timer handler runs, treating it as a preemption.

### Work Stealing

When a core's run queue is empty after dequeueing, it attempts to steal work:

1. Perform a non-locking peek across all other non-pinned cores using `peekHighestStealable(my_core_id)` to find the highest priority eligible thread.
2. Once the best candidate and its home core are identified, lock that core's run queue and attempt to remove the candidate.
3. If the candidate is still there, take it and return.
4. If it was removed between peek and lock (another core stole it or it was scheduled), retry the entire scan.

Pinned cores are skipped entirely — never steal from a pinned core's queue and never identify a pinned core as a target.

Work stealing is purely reactive — it only happens when a core goes idle. There is no background balancing. NUMA and cache domain awareness are not implemented and are noted as future work.

### ExitedThread Deferred Cleanup

Exited threads cannot be freed inside the scheduler timer handler (they are running on the stack being freed). Instead, the thread is stored as an `ExitedThread { thread, last_in_proc }` and freed at the start of the next scheduler tick. (Renamed from `Zombie` to avoid confusion with the process zombie concept.)

---

## 7. Futex Internals

### Hash Table

Global array of 256 buckets, statically allocated at compile time:

```
buckets: [256]Bucket

Bucket {
    lock: SpinLock
    pq: PriorityQueue
}
```

### Hash Function

`bucketIdx(paddr) = (paddr.addr >> 3) % 256`

The shift by 3 accounts for 8-byte alignment of futex addresses. Multiple physical addresses may hash to the same bucket; wake matches on the thread's stored physical address, not just the bucket.

### pushWaiter(bucket, thread)

Enqueue thread into the bucket's priority queue: `bucket.pq.enqueue(thread)`.

### popWaiter(bucket) -> ?*Thread

Dequeue the highest-priority waiter from the bucket's priority queue: `bucket.pq.dequeue()`.

### removeWaiter(bucket, target) -> bool

Remove target from the bucket's priority queue: `bucket.pq.remove(target)`. Returns true if found and removed.

### wait(paddr, expected, timeout_ns, thread) -> i64

1. Compute bucket index from paddr.
2. Convert paddr to kernel VA via physmap (`VAddr.fromPAddr`).
3. Acquire bucket lock with IRQ save (`lockIrqSave`).
4. Atomic load of `*paddr` with acquire ordering. If not equal to `expected`, unlock and return `E_AGAIN` (-9).
5. If `timeout_ns == 0` (try-only), unlock and return `E_TIMEOUT` (-8).
6. Set thread state to `blocked`.
7. Push thread onto bucket.
8. Unlock bucket with IRQ restore.
9. Enable interrupts and yield. The thread will be descheduled.
10. On wake, return 0.

### wake(paddr, count) -> u64

1. Compute bucket index.
2. Acquire bucket lock with IRQ save.
3. Pop up to `count` waiters from the bucket.
4. For each popped thread: spin until `on_cpu` is false, set state to `ready`, determine target core (from affinity mask via `@ctz`, or current core), enqueue on target core's run queue.
5. Unlock, return number woken.

---

## 8. SHM Internals

### SharedMemory Struct

```
SharedMemory {
    pages: []PAddr          -- slice of physical page addresses
    refcount: atomic(u32)   -- atomic reference count
}
```

`MAX_PAGES = 256` (1 MiB maximum SHM size at 4K pages).

### Allocation

SharedMemory objects are allocated from `SlabAllocator(SharedMemory, false, 0, 64)`, backed by a bump allocator over the SHM slab VA region (16 MiB). The `pages` slice is allocated from a separate pages allocator.

### create(num_bytes) -> *SharedMemory

1. Validate size > 0 and page count <= MAX_PAGES.
2. Allocate SharedMemory struct from slab.
3. Allocate `pages` slice from pages allocator.
4. For each page: allocate from PMM, zero the page, store PAddr.
5. Set `refcount = 1`.

### incRef

`fetchAdd(1, .monotonic)` -- no ordering needed, just count.

### decRef

`fetchSub(1, .release)`. If previous value was 1 (now 0): acquire fence, then `destroy()`.

### destroy

1. Free all physical pages back to PMM.
2. Free the `pages` slice.
3. Free the SharedMemory struct back to slab.

---

## 9. Stack Internals

### User Stacks

Allocated from the process VMM as three contiguous kernel-internal tree nodes (`handle = HANDLE_NONE`, `restart_policy = .free`):

1. **Underflow guard** -- 1 page, `rights = none`. Never mapped.
2. **Usable region** -- N pages, `rights = RW`. First page eagerly mapped via PMM, rest demand-paged.
3. **Overflow guard** -- 1 page, `rights = none`. Never mapped.

`createUser(proc_vmm, num_pages)` calls `proc_vmm.reserveStack(num_pages)` which inserts the three VMM nodes and returns `StackResult { guard, base, top }`. The stack grows downward; `top` is the highest address (initial stack pointer), `base` is the lowest usable address.

`destroyUser(stack, proc_vmm)` walks PTEs in the usable range, unmaps and frees committed pages, removes all three VMM nodes.

### Kernel Stacks

Single large kernel VA reservation divided into fixed-size slots.

**Layout constants** (from `kernel/memory/address.zig`):
- `MAX_KERNEL_STACKS = 16384`
- `KERNEL_STACK_PAGES = 8` (32 KiB usable per stack)
- `KERNEL_STACK_SLOT_SIZE = (8 + 1) * 4096 = 36864 bytes` (1 guard page + 8 usable pages)
- Total reservation: `alignForward(16384 * 36864, 1 GiB)` -- aligned to 1 GiB boundary

**VA range**: starts at `AddrSpacePartition.kernel.start` (0xFFFF_8000_0000_0000).

### Kernel Stack Allocator

Freelist-based slot allocator:
- `next_slot: atomic(u64)` -- monotonically increasing slot counter for fresh allocations.
- `freelist_buf: [512]u64` -- fixed-capacity array of recycled slot indices.
- `freelist_top: usize` -- stack pointer into freelist.
- `freelist_lock: SpinLock` -- protects freelist access.

`allocSlot()`: Try freelist first (pop), then bump `next_slot`. Error if `slot >= MAX_SLOTS`.

`recycleSlot(slot)`: Push to freelist if not full (capacity 512). If full, slot is leaked (bounded waste).

### Stack Struct

```
Stack {
    top: VAddr
    base: VAddr
    guard: VAddr
    slot: u64         -- kernel stack slot index (U64_MAX for user stacks)
}
```

### Guard Detection (Kernel Stacks)

`isKernelStackPage(vaddr) -> enum { usable, guard, not_stack }`:
- If vaddr outside kernel stack VA range: `not_stack`.
- Compute `slot_offset = (vaddr - STACK_RANGE_START) % SLOT_SIZE`.
- If `slot_offset == 0`: `guard` (first page of each slot is the guard).
- Otherwise: `usable`.

This is pure modular arithmetic -- no data structure lookup needed. A guard hit in kernel mode triggers a panic.

### Guard Detection (User Stacks)

User stack guard pages are VMM reservation nodes with all-zero rights (`read=false, write=false, execute=false`) and size == `PAGE4K`. Detection happens in the page fault handler's rights-violation branch:
1. If the faulting node has all-zero rights and size == PAGE4K, it is a guard page.
2. Look up the VMM node immediately above this guard page (`findNode(guard_start + PAGE4K)`).
3. If the node above is a writable region, the guard is below the usable stack → `stack_overflow` (stack grew past bottom).
4. Otherwise, the guard is above the usable stack → `stack_underflow` (popped past top).

### createKernel() -> Stack

Allocate a slot. Compute addresses:
- `guard = STACK_RANGE_START + slot * SLOT_SIZE`
- `base = guard + PAGE4K` (first usable page)
- `top = guard + SLOT_SIZE` (one past last usable page)

Usable pages are demand-paged -- no physical memory committed until first access.

### destroyKernel(stack, addr_space_root)

Walk from `base` to `top` in PAGE4K increments. For each page, `arch.unmapPage` -- if a physical page was mapped, free it back to PMM. Then `recycleSlot(stack.slot)`.

---

## 10. Timer Internals

### Timer Interface

Defined in `kernel/arch/timer.zig`. Vtable-based polymorphic interface:

```
Timer {
    ptr: *anyopaque
    vtable: *const {
        now: fn(*anyopaque) -> u64
        armInterruptTimer: fn(*anyopaque, timer_val_ns: u64) -> void
    }
}
```

### HPET (High Precision Event Timer)

Defined in `kernel/arch/x64/timers.zig`. Discovered via ACPI HPET table. MMIO-mapped registers at a physical address from the HPET table's `base_address` field.

**Key registers** (memory-mapped volatile pointers):
- `GenCapsAndId` (offset 0x00): revision, num timers, 64-bit capability, vendor ID, counter clock period (femtoseconds).
- `GenConfig` (offset 0x10): enable bit, legacy mapping.
- `MainCounterVal` (offset 0xF0): 64-bit monotonic counter.
- `NthTimerConfigAndCaps` (offset 0x100 + n*0x20): per-timer configuration.
- `NthTimerComparatorVal` (offset 0x108 + n*0x20): comparator value.

**Frequency calculation**: `freq_hz = 10^15 / counter_clock_period` (counter_clock_period is in femtoseconds).

**now()**: Read `main_counter_val`, convert ticks to nanoseconds: `nanosFromTicksFloor(freq_hz, ticks)`.

The HPET is used as the reference clock for TSC and LAPIC timer calibration.

### TSC (Time Stamp Counter)

`Tsc` struct with `freq_hz: u64`. Calibrated against HPET at boot.

**Calibration** (`Tsc.init(hpet)`):
1. Run 3 iterations of 10 ms measurement windows.
2. Each iteration: read TSC start, read HPET start, busy-wait 10 ms on HPET, read TSC end and HPET end.
3. Compute `sample_hz = (delta_tsc * 10^9) / delta_hpet_ns`.
4. Running average across iterations.
5. Cache result in `cached_freq_hz` (shared with LAPIC calibration).

**now()**: `rdtscp()`, convert to nanoseconds.

**armInterruptTimer()**: Compute deadline in TSC ticks, `apic.armTscDeadline(now_ticks + delta_ticks)`. Uses TSC deadline mode when available.

### LAPIC Timer

`Lapic` struct with `freq_hz`, `divider`, `vector`.

**Calibration** (`Lapic.init(hpet, int_vec)`):
1. Set divider to 16 (DIV_CODE = 0b011).
2. Run 3 iterations of 10 ms measurement windows.
3. Each iteration: set initial count to 0xFFFFFFFF, busy-wait 10 ms on HPET, read current count.
4. Compute `elapsed = 0xFFFFFFFF - current_count`.
5. Compute `sample = (elapsed * DIVIDER * 10^9) / delta_ns`.
6. Running average.

**armInterruptTimer()**: Compute ticks from nanoseconds using effective frequency (`freq_hz / divider`). Clamp to 32-bit range. Call `apic.armLapicOneShot(ticks, vector)`.

### Timer Selection

- **Preemption timer** (`getPreemptionTimer`): LAPIC timer (one-shot mode) for per-core scheduling interrupts.
- **Monotonic clock** (`getMonotonicClock`): TSC-based for `clock_gettime` and futex timeouts. Falls back to HPET if TSC is unavailable.
- **ASLR entropy** (`readTimestamp`): raw RDTSC value.

---

## 11. Page Fault Handling Internals

### Virtual BAR Interception

The x64 exception entry path checks the faulting address against the current process's VMM tree before dispatching to the generic fault handler. If the node kind is `virtual_bar`, the x64 handler emulates the access inline and returns without calling the generic handler. The generic handler's decision tree is unchanged.

Emulation path:
1. Fetch up to `min(15, PAGE_SIZE - (rip & 0xFFF))` instruction bytes from user RIP via `resolveVaddr` + physmap. If RIP is unmapped, kill with `protection_fault`.
2. Call `mmio_decode.decodeBytes(buf)`. On decode error or unsupported instruction, kill with `protection_fault`.
3. Compute `port_offset = fault_addr - node.start.addr`. If `port_offset + op.size > device.port_count`, kill with `invalid_read` or `invalid_write`.
4. Compute `port = device.base_port + port_offset`.
5. Execute `cpu.outb`/`outw`/`outd` or `cpu.inb`/`inw`/`ind` directly.
6. For reads, call `writeContextGpr(ctx, op.reg, op.size, value)` — a local helper in `exceptions.zig` that maps ModRM register indices to `cpu.Context` fields, respecting x86-64 partial register write semantics (8/16-bit writes preserve upper bits; 32-bit writes zero-extend).
7. Advance `ctx.rip += op.len`. Return.

Note: two VMM lookups occur for non-virtual-BAR faults — one in the x64 intercept check, one in the generic handler. Acceptable for now; branch prediction trains to the fast-miss case.

### User Faults

Fault handler receives faulting address, error code, and privilege level from the CPU exception frame.

**Path 1 -- Ring 0 fault on user VA**: Occurs when the kernel reads user memory (e.g., during `proc_create` ELF loading). Kill the calling process.

**Path 2 -- No VMM node**: `vmm.findNode(fault_addr)` returns null. Kill path.

**Path 3 -- SHM or MMIO node**: These are always eagerly mapped. A fault means corruption or a bug. Kill path.

**Path 4 -- Private node, access denied**: The fault type (read/write/execute) is not in the node's `current_rights`. Kill path.

**Path 5 -- Private node, access permitted**: Demand-page. Allocate a zeroed physical page from PMM, `arch.mapPage` with the node's rights, resume execution.

### Kill Path

Check the stack guard registry for `(pid, fault_addr)`. If found, emit stack overflow/underflow diagnostic. Otherwise, emit access violation diagnostic. Then kill the process (non-recursive).

### Kernel Faults

`isKernelStackPage(fault_addr)`:
- `usable`: Demand-page the kernel stack page. Allocate from PMM, map with kernel RW permissions.
- `guard`: Kernel stack overflow. **Panic**.
- `not_stack`: Unexpected kernel fault. **Panic**.

---

## 12. Process Kill Internals

### Non-Recursive Kill (Fault, Voluntary Exit)

For each thread in the process's thread list:
1. Read thread state.
2. **running**: Mark `exited`. The thread is on a CPU -- it will be cleaned up by the scheduler timer handler on that core (stored as zombie, freed next tick). For remote cores, `arch.triggerSchedulerInterrupt(core_id)` sends an IPI to force a scheduling decision.
3. **ready**: The thread is on a run queue. Remove from run queue, mark `exited`.
4. **blocked**: The thread is in a futex bucket. Remove from bucket, mark `exited`.
5. **faulted**: Mark `exited`, clear bit in `proc.faulted_thread_slots`. If the thread is queued or pending in some handler's `fault_box`, that reference becomes stale — `fault_reply` will return `E_NOENT` because `findThreadHandle` will fail (the thread's handle entry has been cleared). The dying side does not eagerly walk the handler's box; the stale check happens lazily at `fault_reply` time. (`releaseFaultHandler` and `cleanupPhase1` do walk the handler's box on the *handler* death and *target* death paths to drop dangling `*Thread` references.)
6. **suspended**: Mark `exited`, clear bit in `proc.suspended_thread_slots`.
7. **exited**: Already exited, skip.

After all threads are marked exited and removed from queues:
- Destroy stacks, deregister stack guards.
- Process exit logic runs.
- If `restart_context` present: restart (process survives). `restart_count` is incremented with wrapping arithmetic (`+%=`). `fault_reason` and `restart_count` are written to the process's own user view (slot 0 field0) and the parent's user view entry via `updateParentView`, which also issues a `futex.wake` on the parent's field0 physical address.
- If no restart context: cleanup. In `cleanupPhase2`, `convertToDeadProcess` replaces the parent's `.process` entry with `.dead_process` storing `*Process`, syncs the parent's user view, and issues a `futex.wake`. The Process struct remains alive until all handle holders revoke (`handle_refcount` reaches 0).

### Process Restart Internals

Before the ELF reload step of the restart path, a thread handle cleanup phase runs:

**Thread handle and core_pin cleanup on restart**:
1. If `proc.fault_handler_proc` is non-null: acquire handler's `perm_lock`, scan handler's perm table for all thread-type entries whose `object` pointer belongs to a thread in `proc`, clear those entries, call `syncUserView(handler)`, release `perm_lock`.
2. Scan `proc`'s own perm table for all thread-type and core_pin-type entries. For core_pin entries, release the `PerCoreState.pinned_thread` on the referenced core (clearing the pin). Clear all matched entries.
3. Clear `proc.faulted_thread_slots = 0` and `proc.suspended_thread_slots = 0`.

After creating the fresh initial thread, a thread handle insertion phase runs:

**Thread handle insertion on restart**:
1. Insert the fresh initial thread handle into `proc`'s own perm table with the process's configured `thread_handle_rights`. Call `syncUserView(proc)`.
2. If `proc.fault_handler_proc` is non-null: insert the fresh initial thread handle into the handler's perm table with full `ThreadHandleRights`. Call `syncUserView(handler)`.

**`fault_handler_proc` is not cleared during restart.** The debugging relationship persists across restarts.

### VM Cleanup on Process Exit

If `proc.vm != null` when a process exits, the kernel calls `Vm.destroy()` before address space teardown. This kills all vCPU threads, frees guest physical memory mappings, tears down arch-specific virtualization structures (VMCS/EPT on x64), frees the Vm and VCpu structs back to their slabs, and clears `proc.vm`. This ensures guest memory pages are freed before `freeUserAddrSpace` runs.

### proc_create Internals

**New parameters**: `thread_rights: ThreadHandleRights` and `max_thread_priority: Priority`. `thread_rights` is stored on the Process struct as `thread_handle_rights: ThreadHandleRights` — this is the rights mask used whenever a new thread handle is inserted into this process's own perm table. `max_thread_priority` is stored as `process.max_thread_priority: Priority` — this is the ceiling priority for any thread in the process. The kernel validates that `max_thread_priority` does not exceed the parent's own `max_thread_priority`.

**Initial thread handle**: After `Thread.create` for the initial thread, call `insertPerm` to insert the thread handle at slot 1 of the child's perm table with rights = `thread_rights`. Call `syncUserView(child)`.

**fault_handler_proc initialization**: Set `child.fault_handler_proc = null` at process creation. The child self-handles by default.

### Recursive Kill (Parent Revokes Child Process Handle)

Depth-first post-order traversal of the child's entire subtree:
1. For each descendant process (depth-first):
   - Kill all threads (same per-thread state machine).
   - Destroy stacks, deregister guards.
   - If `restart_context` present: **restart** (process survives, children stay attached).
   - If no restart context: cleanup.
2. Restartable processes in the subtree get a forced restart, keeping device handles.
3. Non-restartable processes die; device handles return up the tree via the device handle return walk.

### IPI Mechanism

When killing a thread that is `running` on another core, the kernel sends an inter-processor interrupt via `arch.triggerSchedulerInterrupt(core_id)`. This forces the target core's scheduler timer handler to run, which will observe the thread's `exited` state and switch away from it. The `on_cpu` atomic flag is used by futex wake to wait until a thread has fully yielded before re-enqueuing.

### last_in_proc Flag

When the process kill path determines which thread is the last one, it sets `thread.last_in_proc = true`. The scheduler's zombie cleanup path checks this flag to trigger `proc.exit()` after the last thread's `deinit`.

---

## 13. Architecture Interface

Portable dispatch layer in `kernel/arch/dispatch.zig`. All functions dispatch at comptime via `builtin.cpu.arch` to architecture-specific implementations.

### Boot

**init() -> void** -- IDT, GDT/TSS (per-core), segment registers, SYSCALL/SYSRET MSRs, PAT, CR0.AM alignment check, SMEP/SMAP (see below), speculation barriers (see below). Once on bootstrap core. Secondary cores repeat the SMEP/SMAP and speculation barrier enables in `coreInit` after loading GDT/IDT.

**SMEP/SMAP** -- `enableSmapSmep()` probes CPUID.(EAX=7,ECX=0):EBX bits 7 (SMEP) and 20 (SMAP), then sets the corresponding CR4 bits (20 and 21). SMEP prevents CPL-0 instruction fetch from user pages. SMAP prevents CPL-0 data access to user pages unless RFLAGS.AC=1. The interrupt stub prologue emits `CLAC` as its first instruction so handlers always enter with AC=0 regardless of the interrupted context's AC value (IRETQ restores the saved RFLAGS on return). Kernel code that must read/write user-mode buffers brackets the access with `userAccessBegin()` / `userAccessEnd()` (STAC / CLAC).

**Speculation Barriers (IBRS/STIBP)** -- `enableSpeculationBarriers()` probes CPUID.(EAX=7,ECX=0):EDX bit 26 (IBRS/IBPB) and bit 27 (STIBP), then programs `IA32_SPEC_CTRL` MSR (0x48). IBRS (Indirect Branch Restricted Speculation) prevents indirect branch predictions made at a lower privilege level from influencing speculative execution at a higher privilege level — mitigates Spectre v2 (Branch Target Injection). STIBP (Single Thread Indirect Branch Predictors) prevents one logical processor from influencing its sibling hyperthread's branch predictions. On CPUs with enhanced IBRS (eIBRS, available Coffee Lake Refresh / Zen 2 and later), the MSR is set once at boot with zero ongoing overhead. On older CPUs with basic IBRS, the same set-once approach is used — acceptable for a microkernel since the MSR persists across privilege transitions. Both bits are set per-core on BSP and all APs. Intel SDM Vol 3A §4.10.1; AMD APM Vol 2 §3.2.8.

**parseFirmwareTables(firmware_table_paddr: PAddr) -> void** -- Parse ACPI tables:
- XSDP validation (signature, checksum).
- XSDT walk: iterate 8-byte physical pointers to SDTs.
- MADT: enumerate Local APICs (active cores), I/O APICs, interrupt source overrides, LAPIC address override. Initialize APIC subsystem.
- HPET: validate, MMIO-map, initialize timer.
- MCFG: PCI Enhanced Configuration Access Mechanism (ECAM) base addresses and bus ranges. Map ECAM pages, enumerate PCI devices.
- Fallback: if MCFG not present or no devices found, legacy PCI config space enumeration.
- Serial port probing.

### SYSCALL Entry / IRETQ Return Path

The kernel uses SYSCALL for fast entry and IRETQ for return (Intel SDM Vol 2B "SYSCALL"; Vol 3A §5.8.8). This avoids the SYSRET SS selector issue under KVM, where SYSRET's reliance on the hidden descriptor cache is unreliable. Entry via SYSCALL is ~2.5x faster than the interrupt gate path.

**GDT Layout** — SYSRET loads CS = STAR[63:48]+16, SS = STAR[63:48]+8 (Intel SDM Vol 2B "SYSRET" Operation). This requires user data to precede user code in the GDT:

```
0x08  KERNEL_CODE
0x10  KERNEL_DATA
0x18  USER_DATA     ← SYSRET SS = 0x10+8 = 0x18 | RPL3 = 0x1B
0x20  USER_CODE     ← SYSRET CS = 0x10+16 = 0x20 | RPL3 = 0x23
0x28  TSS
```

**MSR Configuration** (`cpu.initSyscall`, called per-core from `init.zig` and `smp.zig:coreInit`):
- IA32_STAR (0xC0000081): [47:32]=0x08 (kernel CS for SYSCALL), [63:48]=0x10 (base for SYSRET)
- IA32_LSTAR (0xC0000082): address of `syscallEntry` in `interrupts.zig`
- IA32_FMASK (0xC0000084): clears IF(9), DF(10), AC(18) on entry
- IA32_EFER (0xC0000080): set SCE (bit 0) to enable SYSCALL/SYSRET

**SWAPGS Stack Switch** — `kernel/arch/x64/interrupts.zig:syscallEntry` uses SWAPGS (Intel SDM Vol 3A §5.8.8) to access per-CPU data for the kernel stack pointer. Each core's IA32_KERNEL_GS_BASE MSR (0xC0000102) is set during init to point to a `SyscallScratch` struct: `[0]=kernel_rsp, [8]=user_rsp_scratch`. The `kernel_rsp` field is updated on every context switch alongside TSS.RSP0.

Entry sequence:
1. SWAPGS — GS base → per-CPU SyscallScratch
2. Save user RSP to gs:8, load kernel RSP from gs:0
3. Save user RBP to its stack slot, use RBP to ferry user RSP from gs:8
4. SWAPGS — restore user GS base (safe for context switches)
5. Build iret-compatible `cpu.Context` frame on kernel stack
6. FXSAVE, call `syscallDispatch`, FXRSTOR
7. Restore GPRs from saved frame
8. IRETQ — return to userspace using the iret frame (RIP, CS, RFLAGS, RSP, SS)

The return always uses IRETQ, which properly loads CS/SS from the stack frame. SYSRET is not used because its hidden descriptor cache behavior is unreliable under KVM (Intel SDM Vol 2B "SYSRET" 64-Bit Mode Exceptions). The GDT layout still supports SYSRET (user data before user code) but only the MSR configuration for SYSCALL entry is active.

**smpInit() -> void** -- Bring up secondary cores:
1. Initialize per-core GDT/TSS for all cores.
2. Map real-mode trampoline code at physical 0x8000.
3. For each secondary core: write trampoline parameters (CR3, stack top, entry point), send INIT IPI, send SIPI with vector 0x08 (0x8000 >> 12).
4. Secondary core executes trampoline: enters long mode, loads GDT/IDT, jumps to `arch.init()` + `sched.perCoreInit()`.
5. Atomic `cores_online` counter tracks bringup progress.

**dropIdentityMapping() -> void** -- Remove the identity mapping (low VA = PA) set up by the bootloader. After this, all kernel code runs in the higher half.

### Memory Management

**getAddrSpaceRoot() -> PAddr** -- Read CR3 (x86_64) to get the current page table root physical address.

**mapPageBoot(addr_space_root: VAddr, phys, virt, size, perms, allocator) -> void** -- Early boot page mapping using identity-mapped virtual addresses (before physmap is set up). Supports 4K, 2M, and 1G page sizes. Uses the provided allocator (bump allocator) for page table allocation since PMM is not yet available. The addr_space_root is a VAddr (identity-mapped) rather than PAddr.

**mapPage(addr_space_root: PAddr, phys, virt, perms) -> void** -- Map a 4K page. Walks the 4-level page table (PML4 -> PDPT -> PD -> PT), allocating intermediate page table pages from PMM as needed. Accesses page tables via physmap.

**unmapPage(addr_space_root: PAddr, virt) -> ?PAddr** -- Unmap a 4K page. Walk page tables, clear PTE, invalidate TLB (`invlpg`). Returns the physical address that was mapped (or null if not present). Caller decides whether to free the physical page.

**updatePagePerms(addr_space_root, virt, new_perms) -> void** -- Walk page table to the leaf PTE, update permission bits in place, invalidate TLB.

**resolveVaddr(addr_space_root, virt) -> ?PAddr** -- Pure read-only page table walk. Returns the physical address mapped at `virt`, or null if not present. No side effects.

**freeUserAddrSpace(addr_space_root) -> void** -- Walk all user-half page table entries. Free every mapped 4K page and every intermediate page table page. Indiscriminate -- caller must remove SHM/MMIO PTEs first (those pages are not owned by the address space). Used only in the full process teardown path.

**copyKernelMappings(new_root: VAddr) -> void** -- Copy the upper-half PML4 entries (kernel mappings) from the current address space root into a new page table root. This ensures all address spaces share the same kernel mappings.

### Execution

**prepareThreadContext(kstack_top, ustack_top, entry, arg: u64) -> *CpuContext** -- Construct an initial CPU context (register frame) on the kernel stack. Sets up the IRET frame: RIP = entry, RSP = ustack_top, CS = user code segment, SS = user data segment, RFLAGS = interrupts enabled. RDI = arg (System V calling convention). Returns a pointer to the context on the kernel stack.

**switchTo(Thread) -> void** -- Save current registers to the outgoing thread's kernel stack. Load incoming thread's kernel stack pointer. If crossing process boundaries, swap address space (`swapAddrSpace`). Load incoming thread's register state. Return to the incoming thread's execution point.

**swapAddrSpace(root: PAddr) -> void** -- Write CR3 with the new page table root. Hardware flushes TLB automatically on CR3 write.

**halt() -> noreturn** -- Infinite loop of `hlt` instructions. Used for idle cores and bootstrap core after initialization.

**shutdown() -> noreturn** -- Power off the machine. On x86: write to ACPI PM1a control register (S5 sleep state). Port I/O to 0x604 with value 0x2000 (QEMU), or port 0xB004 (Bochs/older QEMU).

### Interrupts

**enableInterrupts() -> void** -- `sti` instruction.

**saveAndDisableInterrupts() -> u64** -- `pushfq; pop rax; cli`. Returns the RFLAGS value (opaque state). Used by spinlock acquire to prevent deadlocks from timer interrupts.

**restoreInterrupts(state: u64) -> void** -- Restore RFLAGS from saved state. If interrupts were enabled before, re-enables them. Used by spinlock release.

**triggerSchedulerInterrupt(core_id: u64) -> void** -- Send an IPI (inter-processor interrupt) to the specified core. Self-IPI for yield (`core_id == current core`), remote IPI for kill. Writes to LAPIC ICR (Interrupt Command Register) or x2APIC MSR.

**userAccessBegin() -> void** -- On x86_64, executes `STAC` to set RFLAGS.AC=1, allowing the current core to access user-mode pages under SMAP. Must be paired with `userAccessEnd()` on every return path. On aarch64, this is a no-op. Keep the window as tight as possible — it suppresses SMAP protection for the duration on the issuing core.

**userAccessEnd() -> void** -- On x86_64, executes `CLAC` to clear RFLAGS.AC, re-arming SMAP protection after a bracketed user access.

### Timing

**getPreemptionTimer() -> Timer** -- Returns a LAPIC timer instance configured for one-shot mode. Used for per-core scheduler preemption. The LAPIC timer frequency is calibrated against HPET at boot.

**getMonotonicClock() -> Timer** -- Returns a TSC-based timer for monotonic nanosecond timestamps. Used by `clock_gettime` syscall and futex timeout logic.

**readTimestamp() -> u64** -- Raw `RDTSC` instruction. Architecture-specific cycle counter. Used for ASLR entropy at process creation time.

**randomSeed() -> ?u64** -- Hardware-sourced random value. On x86_64 executes `RDRAND`; returns null if the entropy source is unavailable or temporarily exhausted. On aarch64 returns null (stub).

**readRtc() -> u64** -- Reads the hardware RTC and returns nanoseconds since the Unix epoch. On x86_64: reads CMOS RTC via ports 0x70/0x71, converts BCD to binary, computes Unix nanoseconds. On aarch64: returns 0 (no RTC). Called once during boot to initialize the wall clock offset (§22).

**getRandom() -> ?u64** -- Returns 8 bytes of hardware-sourced randomness. On x86_64: executes RDRAND. On aarch64: returns null. Used by the `getrandom` syscall (§23). Distinct from `randomSeed()` which is the boot-time entropy source.

### IRQ Control

**maskIrq(irq: u8) -> void** -- Masks (disables) the given IRQ line. On x86_64: sets the mask bit in the I/O APIC redirection table entry. On aarch64: no-op. Called from the IRQ handler path after identifying the interrupting device (§24).

**unmaskIrq(irq: u8) -> void** -- Unmasks (enables) the given IRQ line. On x86_64: clears the mask bit in the I/O APIC redirection table entry. On aarch64: no-op. Called from the `irq_ack` syscall handler (§24).

**findIrqForDevice(device: *DeviceRegion) -> ?u8** -- Linearly scans irq_table to find the IRQ line number for a device. On x86_64: iterates `irq_table[0..256]`, returns the index where the entry matches `device`, or null if not found. On aarch64: returns null. Used by the `irq_ack` syscall handler (§24).

### Power Control

**powerAction(action: PowerAction) -> i64** -- Performs a system-wide power action. On x86_64: dispatches to ACPI sleep states, keyboard controller reset, or DPMS blanking per action variant. On aarch64: returns E_NODEV. `shutdown` and `reboot` do not return on success. See §25.

**cpuPowerAction(action: CpuPowerAction, value: u64) -> i64** -- Performs a per-CPU power control action. On x86_64: programs `IA32_PERF_CTL` for `set_freq`, configures MWAIT C-state hints for `set_idle`. On aarch64: returns E_NODEV. See §25.

### Identification

**coreCount() -> u64** -- Returns the number of active cores discovered during MADT parsing. Reads from the LAPIC array length.

**coreID() -> u64** -- Returns the current core's LAPIC ID. On x2APIC: read IA32_X2APIC_APICID MSR. On xAPIC: read from MMIO register.

### Port I/O (x86-only)

**ioportIn(port: u16, width: u8) -> u32** -- `in` instruction. Width 1 = `inb`, 2 = `inw`, 4 = `ind`.

**ioportOut(port: u16, width: u8, value: u32) -> void** -- `out` instruction. Width 1 = `outb`, 2 = `outw`, 4 = `outd`.

### Virtual Machine

**vmInit() -> void** -- Detect hardware virtualization support via CPUID (Intel VT-x or AMD-V). Cache availability in a global flag. Called once from `kMain` after `parseFirmwareTables`.

**vmPerCoreInit() -> void** -- Per-core VM setup. On Intel: execute VMXON to enter VMX root operation. On AMD: set EFER.SVME. Called from `sched.perCoreInit()`.

**vmSupported() -> bool** -- Returns the cached virtualization availability flag.

### Performance Monitoring Unit

**pmuInit() -> void** -- One-time PMU initialization on the bootstrap core. Performs feature detection (CPUID on x64), records the number of available counters and the supported-event bitmask into a cached `PmuInfo`, and primes the PMI handler vector. Called from `kMain` after `arch.init()`. On aarch64 this is a no-op stub.

**pmuGetInfo() -> PmuInfo** -- Returns the cached `PmuInfo` computed by `pmuInit`. Used by the generic `pmu_info` syscall in `kernel/syscall/pmu.zig`.

**pmuSave(state: *PmuState) -> void** -- Called from the context switch path on the *outgoing* thread when `thread.pmu_state != null`. Reads the current hardware counter values into `state`, disables all counters. Leaves no counter running on the core.

**pmuRestore(state: *PmuState) -> void** -- Called from the context switch path on the *incoming* thread when `thread.pmu_state != null`. Writes saved counter values back to hardware and re-enables the counters that were configured when the thread last called `pmu_start` / `pmu_reset`.

**pmuStart(state: *PmuState, configs: []const PmuCounterConfig) -> error!void** -- Programs the hardware counters described by `configs` into the arch-specific state, clears the counter registers, and enables them. Only called while the state's owning thread is the current thread (the generic layer arranges this).

**pmuRead(state: *PmuState, sample: *PmuSample) -> void** -- Snapshots the counter values stored in `state` into `sample.counters` in configuration order. Does *not* touch hardware — `pmu_read` is only ever called on a thread in `.faulted` or `.suspended` state (§2.14.11), so by the time the generic layer calls this the outgoing save has already pushed the final values into `state`.

**pmuReset(state: *PmuState, configs: []const PmuCounterConfig) -> error!void** -- Same as `pmuStart` but for a thread that already has allocated state. Reprograms counters, writes the new overflow preload values, and re-enables.

**pmuStop(state: *PmuState) -> void** -- Disables counters, tears down arch-specific bookkeeping, and returns `state` to `PmuStateAllocator`.

**PmuState** -- `pub const PmuState = switch (builtin.cpu.arch) { .x86_64 => x64.PmuState, .aarch64 => aarch64.PmuState, else => @compileError(...) };`. The generic kernel only stores `*arch.PmuState` pointers and passes them opaquely to the dispatch functions above — it never inspects struct fields.

Hardware PMU availability is detected once at boot in `arch.pmuInit()` and cached. The cached `PmuInfo` is the single source of truth for the generic layer's syscall validation.

### System Information

**getCoreFreq(core_id: u64) -> u64** -- Reads the current operating frequency of the given core in hertz. Called once per core per `sys_info` invocation with a non-null `cores_ptr`. Dispatches to the arch-specific implementation (`arch/x64/sysinfo.zig` or `arch/aarch64/sysinfo.zig`).

**getCoreTemp(core_id: u64) -> u32** -- Reads the current temperature of the given core in milli-celsius. Same dispatch pattern as `getCoreFreq`.

**getCoreState(core_id: u64) -> u8** -- Reads the current C-state level of the given core. `0` means the core is active; higher values mean progressively deeper idle states. Same dispatch pattern.

All three functions are side-effect free reads against the target core's hardware interface. See §21 for the x64 implementation details (the MSRs used, how TjMax is discovered, and how remote cores are polled).

### Diagnostics

**print(format, args) -> void** -- Serial port output via `kernel/arch/x64/serial.zig`. Formats into a 256-byte stack buffer, writes byte-by-byte to the configured COM port. Protected by a global `print_lock` SpinLock. No-op in release builds (`builtin.mode != .Debug`).

### x86_64 Page Table Format

4-level paging (PML4). Each level has 512 entries of 8 bytes (`PageEntry` packed struct):
- Bits 0-11: flags (present, writable, user, write-through, not-cacheable, accessed, dirty, huge, global, 3 ignored).
- Bits 12-51: 40-bit physical address (shifted right by 12).
- Bits 52-62: reserved.
- Bit 63: NX (no-execute).

Level shifts: L4 = 39, L3 = 30, L2 = 21, L1 = 12. Index extraction: `@truncate(vaddr >> shift)` gives 9-bit index.

### AArch64 Architecture Details

All aarch64 code lives in `kernel/arch/aarch64/`. The module index (`aarch64.zig`) exports 16 submodules mirroring the x64 structure. Key differences from x64 are documented below.

#### Reference Manuals

PDFs in `docs/aarch64/`:
- **DDI0487** (ARM ARM): paging, exceptions, system registers, generic timer, EL2 virtualization.
- **IHI0069** (GICv3): interrupt controller.
- **IHI0070** (SMMUv3): IOMMU.
- **DEN0022** (PSCI): power management, SMP boot.
- **DDI0183** (PL011): UART.
- **DEN0049** (IORT): IO remapping table.

#### Build

`zig build -Darch=arm` cross-compiles for `aarch64-freestanding` targeting `cortex-a76` (ARMv8.2, required for PAN). Produces `BOOTAA64.EFI` and `kernel.elf`. QEMU: `zig build run -Darch=arm` launches `qemu-system-aarch64 -M virt,gic-version=3`.

#### Exception Model

ARM uses a vector table (VBAR_EL1) with 16 entries of 0x80 bytes each, replacing x86's IDT. Four exception groups × four types (Synchronous, IRQ, FIQ, SError). ESR_EL1 bits [31:26] encode the Exception Class (EC): 0x15=SVC (syscall), 0x24=Data Abort from EL0, 0x20=Instruction Abort from EL0. FAR_EL1 holds the faulting VA (equivalent of CR2). ARM ARM D1.10, D13.2.37.

Each 0x80-byte vector entry saves x0/x30, loads a handler address, and branches to a shared trampoline that saves all 31 GPRs + SP_EL0 + ELR_EL1 + SPSR_EL1 in ArchCpuContext layout (272 bytes), calls the handler, restores state, and ERETs. File: `exceptions.zig`.

#### ArchCpuContext Layout

```
offset  size  field
  0     248   x0-x30 (31 GPRs × 8 bytes, Registers extern struct)
248       8   sp_el0 (user stack pointer)
256       8   elr_el1 (exception link register — return address for ERET)
264       8   spsr_el1 (saved processor state — mode, DAIF, condition flags)
Total: 272 bytes
```

SPSR_EL1 values: EL0t (user) = 0x000, EL1h (kernel) = 0x004, DAIF mask = 0x3C0. File: `interrupts.zig`.

#### Syscall/IPC Register Mapping

```
x8  = syscall number     (x86: rax)
x0  = arg0 / return      (x86: rdi / rax)
x1  = arg1 / return2     (x86: rsi / rdx)
x2  = arg2               (x86: rdx)
x3  = arg3               (x86: r10)
x4  = arg4               (x86: r8)
x5  = IPC handle          (x86: r13)
x6  = IPC metadata        (x86: r14)
x0-x4 = IPC payload words (x86: rdi,rsi,rdx,r8,r9)
```

#### FaultRegSnapshot

Arch-dependent GPR count: 31 on aarch64 (x0-x30), 15 on x86-64. `arch.fault_gpr_count`, `arch.fault_regs_size` (272 bytes), `arch.fault_msg_size` (304 bytes) are derived comptime constants. See `dispatch.zig`.

#### Page Tables (VMSAv8-64)

4-level tables with 4KB granule, same depth as x86 PML4 but different entry format. Split address space: TTBR0_EL1 for user VA (lower half), TTBR1_EL1 for kernel VA (upper half). This means `copyKernelMappings()` is a no-op — kernel pages are always visible via TTBR1.

PageEntry (packed struct, 64 bits): valid(1), is_table(1), AttrIndx(3), NS(1), AP(2), SH(2), AF(1), nG(1), addr(36), res(4), contiguous(1), PXN(1), XN(1), sw(4), ignored(4), res(1).

AP encoding (ARM ARM D5.4, Table D5-34):
- 0b00 = EL1 RW, EL0 none
- 0b01 = EL1 RW, EL0 RW
- 0b10 = EL1 RO, EL0 none
- 0b11 = EL1 RO, EL0 RO

MAIR_EL1 indices: 0 = Device-nGnRnE, 1 = Normal WB. AF bit always set. SH = Inner Shareable (0b11) for normal memory.

TLB maintenance: `DSB ISHST → TLBI VAE1IS → DSB ISH → ISB`. ARM broadcasts TLBI across all cores in the inner shareable domain — no software IPI shootdown needed (unlike x86 `invlpg` which is local).

Level shifts: L3 (level 0) = 39, L2 (level 1) = 30, L1 (level 2) = 21, L0 (level 3) = 12. File: `paging.zig`.

#### Address Space Layout

```
0x0000_0000_0000_0000 – 0x0001_0000_0000_0000  user (TTBR0, 16 TB)
0xFFFF_0000_0000_0000 – 0xFFFF_0000_4000_0000  kernel_code (TTBR1, 1 GB)
0xFFFF_0000_4000_0000 – 0xFFFF_0400_0000_0000  kernel heap/data (TTBR1, ~4 TB)
0xFFFF_FF80_0000_0000 – 0xFFFF_FF88_0000_0000  physmap (TTBR1, 32 GB)
```

Linker script: `kernel/linker-aarch64.ld`, base at `0xFFFF_0000_0000_0000`.

#### GIC (Generic Interrupt Controller)

GICv3 driver replacing x86's APIC. Three components: Distributor (GICD, global MMIO), Redistributor (GICR, per-core MMIO), CPU Interface (ICC system registers). IHI 0069H.

Interrupt ID ranges: SGI 0-15 (IPIs), PPI 16-31 (per-core timer/PMU), SPI 32-1019 (devices). Scheduler IPI uses SGI 0. Timer interrupt is PPI 30 (physical timer).

Discovery: ACPI MADT GICD (type 0x0C) for distributor base, GICR (type 0x0E) for redistributor ranges, GICC (type 0x0B) for core count and MPIDR values.

Init sequence: `initDistributor()` (enable ARE, Group 1, route all SPIs to core 0), `initRedistributor(0)` (wake BSP's redistributor, enable SGIs), `initCpuInterface()` (enable ICC_SRE_EL1, set PMR=0xFF, enable Group 1). Secondary cores call `initSecondaryCoreGic()` (redistributor + CPU interface only). File: `gic.zig`.

#### PAN (Privileged Access Never)

ARM equivalent of x86 SMAP. PSTATE.PAN prevents EL1 from accessing EL0 pages. `userAccessBegin()` clears PAN (`MSR PAN, #0`), `userAccessEnd()` sets PAN (`MSR PAN, #1`). Requires ARMv8.1 (Cortex-A76+). ARM ARM D5.4.6. File: `cpu.zig`.

#### Timers

ARM Generic Timer replaces x86's HPET + LAPIC timer + TSC. Single hardware block provides both monotonic clock and per-core preemption timer. ARM ARM D11.2.

- **Monotonic clock**: reads CNTVCT_EL0 (virtual counter), converts to nanoseconds via CNTFRQ_EL0.
- **Preemption timer**: writes CNTP_CVAL_EL0 (physical timer comparator), enables via CNTP_CTL_EL0 (ENABLE=1, IMASK=0). Timer fires as PPI 30.
- **readTimestamp()**: reads CNTVCT_EL0 (equivalent of RDTSC).

File: `timers.zig`.

#### Serial (PL011 UART)

Replaces x86 NS16550 COM port. MMIO at base address from ACPI SPCR. UEFI firmware initializes baud rate and enables the UART. Driver polls UARTFR.TXFF (offset 0x018, bit 5) and writes UARTDR (offset 0x000). DDI0183. File: `serial.zig`.

#### ACPI Parsing

Same XSDT walk as x64. ARM-specific MADT entry types: GICC (0x0B, 80 bytes — CPU Interface Number at offset 4, Flags at offset 12, MPIDR at offset 68), GICD (0x0C — Physical Base Address at offset 8), GICR (0x0E — Discovery Range Base at offset 4). SPCR table provides PL011 UART base. Two-pass MADT parsing: first pass counts cores and stores MPIDRs, second pass extracts GICD/GICR addresses. ACPI 6.5 Tables 5-45/5-47/5-49. File: `acpi.zig`.

#### SMP Boot (PSCI)

ARM uses PSCI CPU_ON (DEN0022D Section 5.1.4) instead of x86's INIT-SIPI-SIPI. No assembly trampoline needed. Sequence: for each secondary core, allocate kernel stack, call `power.cpuOn(target_mpidr, entry_paddr, core_idx)` via SMC #0. Secondary core wakes at the entry point in EL1, sets SP from pre-allocated stack, installs VBAR_EL1, initializes GIC, signals BSP via atomic counter, enters scheduler.

MPIDR values from ACPI MADT GICC entries, stored in `smp.mpidr_table`. Fallback: flat topology (Aff0 = core_idx). File: `smp.zig`.

#### Power Management (PSCI)

PSCI via SMC/HVC replaces x86 ACPI PM1/keyboard controller. Function IDs: SYSTEM_OFF (0x84000008), SYSTEM_RESET (0x84000009), CPU_ON (0xC4000003), CPU_SUSPEND (0xC4000001), SYSTEM_SUSPEND (0xC400000E). SMC/HVC clobbers x0-x3 (args/return) and x4-x17 (caller-saved per SMCCC DEN0028E). File: `power.zig`.

#### VM Stubs

ARM virtualization (EL2) is not yet implemented. `vmSupported()` returns false, all KVM syscalls return E_NOSYS. Stub types in `vm.zig` and dispatch.zig.

#### IOMMU Stubs

ARM SMMU (IHI0070) is not yet implemented. `isDmaRemapAvailable()` returns false. Stub in `iommu.zig`.

#### PMU / SysInfo Stubs

`pmuGetInfo()` reports 0 counters. `PmuState` is a 32-byte stub (minimum for slab allocator intrusive freelist). SysInfo returns zero for frequency/temperature/C-state. Files: `pmu.zig`, `sysinfo.zig`.

---

## 14. Memory Management Internals

### Physical Memory Manager (PMM)

Defined in `kernel/memory/pmm.zig`. Global singleton: `pmm.global_pmm: ?PhysicalMemoryManager`.

```
PhysicalMemoryManager {
    backing_allocator: std.mem.Allocator   -- buddy allocator
    lock: SpinLock
}
```

Implements the `std.mem.Allocator` interface. The PMM wraps the buddy allocator with per-core page caches for fast single-page allocations.

**freePageCount() -> u64** -- Returns the number of physical pages currently free. Acquires the PMM global lock, queries the buddy allocator's internal free page accounting (sum of the per-order free list lengths weighted by order), adds the pages sitting in all per-core page caches, and returns the total. Called by the `sys_info` syscall (§21) to populate `SysInfo.mem_free`. A companion `totalPageCount() -> u64` returns the static total page count established at buddy init time for `SysInfo.mem_total`.

### Per-Core Page Cache

```
PerCorePageCache {
    head: ?*PageNode     -- intrusive freelist
    count: u32
}
```

- `MAX_CORES = 64`
- `CACHE_REFILL_ORDER = 4` (refill 16 pages at a time)
- `CACHE_MAX_PAGES = 64` (not currently enforced as a drain threshold)

**Allocation path** (single page, scheduler initialized):
1. Disable interrupts, read core ID.
2. Try pop from per-core cache. If hit, restore interrupts and return.
3. If miss: acquire PMM global lock, request a bulk allocation of 16 pages (order 4) from buddy allocator.
4. Split the bulk allocation into individual pages, push all onto per-core cache.
5. Pop one page from cache, unlock, restore interrupts.
6. Fallback: if bulk alloc fails, try single-page alloc from buddy under lock.

**Free path**: Push page onto per-core cache (interrupt-safe).

### Buddy Allocator

Defined in `kernel/memory/allocators/buddy.zig`. Backing allocator for the PMM.

```
BuddyAllocator {
    start_addr: u64
    end_addr: u64
    init_allocator: std.mem.Allocator      -- bump allocator (for metadata)
    page_pair_orders: []PagePairOrders     -- per-pair order tracking
    bitmap: BitmapFreeList                 -- allocation bitmap
    freelists: [NUM_ORDERS]IntrusiveFreeList
}
```

Uses a bitmap to track allocation state and per-order intrusive freelists for O(1) allocation of power-of-two page blocks. `PagePairOrders` tracks the order of each buddy pair (even/odd pages). The bitmap and page pair metadata are allocated from the bump allocator at init time.

**addRegion(start, end)**: Feeds free physical memory regions into the buddy allocator by freeing each page individually (which coalesces with buddies).

**splitAllocation(addr, split_order)**: Splits a higher-order allocation into individual pages, returning a `FreeListBatch` for bulk cache refill.

### Bump Allocator

Defined in `kernel/memory/allocators/bump.zig`. Simple monotonic allocator.

```
BumpAllocator {
    start_addr: u64
    free_addr: u64
    end_addr: u64
}
```

Allocation: align `free_addr` to requested alignment, advance by `len`. Returns null if exceeds `end_addr`. No free support (unreachable). Used for:
- Early boot physical memory allocation (before buddy allocator is ready).
- Backing storage for slab allocators (each slab type gets its own 16 MiB bump region).

### Slab Allocator

Defined in `kernel/memory/allocators/slab.zig`. Generic, comptime-parameterized.

```
SlabAllocator(T, stack_bootstrap, stack_size, allocation_chunk_size) {
    backing_allocator: std.mem.Allocator
    freelist: IntrusiveFreeList
    alloc_headers: ?*AllocHeader           -- linked list of chunk allocations
    lock: SpinLock
}
```

Parameters:
- `T`: element type.
- `stack_bootstrap`: if true, pre-allocate a small stack-resident array (used for bootstrapping before heap is available).
- `stack_size`: size of stack array (0 if not bootstrapping).
- `allocation_chunk_size`: number of elements per backing allocation (e.g., 64).

**Allocation**: Pop from freelist. If empty, allocate a new chunk of `allocation_chunk_size` elements from the backing allocator, push all onto freelist, then pop one. Track chunks via `AllocHeader` linked list for cleanup.

**Free**: Push back onto freelist.

In debug mode, tracks net allocations and asserts zero on `deinit`.

**Slab instances** (each backed by a dedicated 16 MiB bump allocator region):
- `VmNodeSlab`: `SlabAllocator(VmNode, false, 0, 64)` -- VMM tree data nodes.
- `VmTreeSlab`: `SlabAllocator(VmTree.Node, false, 0, 64)` -- red-black tree nodes.
- `SharedMemoryAllocator`: `SlabAllocator(SharedMemory, false, 0, 64)` -- SHM objects.
- `DeviceRegionSlab`: `SlabAllocator(DeviceRegion, false, 0, 32)` -- device region objects.
- `ProcessAllocator`: `SlabAllocator(Process, false, 0, 64)` -- process structs.
- `ThreadAllocator`: `SlabAllocator(Thread, false, 0, 64)` -- thread structs.
- `VmAllocator`: `SlabAllocator(arch.Vm, false, 0, 64)` -- VM structs (dispatched from arch/x64/kvm/).
- `VCpuAllocator`: `SlabAllocator(arch.VCpu, false, 0, 64)` -- vCPU structs (dispatched from arch/x64/kvm/).
- `PmuStateAllocator`: `SlabAllocator(arch.PmuState, false, 0, 64)` -- per-thread PMU state blocks. `arch.PmuState` is the arch-dispatched type (see §13 and §20); on aarch64 it is an empty struct stub so the allocator compiles but is never exercised.

### Heap Allocator

Defined in `kernel/memory/allocators/heap.zig`. General-purpose kernel heap for variable-size allocations.

```
HeapAllocator {
    reserve_start: u64
    commit_end: u64        -- current committed boundary (grows on demand)
    reserve_end: u64
    free_tree: RedBlackTree -- free blocks indexed by size
}
```

**Design**: Best-fit allocator backed by a red-black tree of free blocks. Each block has:
- `AllocHeader` (8 bytes): `is_free: bool`, `bucket_size: u63`.
- User data region.
- `AllocFooter` (8 bytes): `header: u64` -- pointer back to header (for coalescing).
- `AllocPadding` (8 bytes): `header_offset: u64` -- for alignment padding.

**Allocation**: Search the free tree for the smallest block >= requested size (best-fit lower bound). If found, split if remainder >= minimum block size. If not found, bump `commit_end` to allocate from reserved VA space (demand-paged).

**Free**: Mark block as free, coalesce with adjacent free blocks (using footer to find predecessor), insert into free tree.

The free tree's node allocator (`TreeAllocator`) is a separate slab backed by a 1 GiB bump region. The heap itself has a 256 GiB VA reservation.

### Physmap Layout

Direct physical-to-virtual mapping at a fixed offset. Defined in `kernel/memory/address.zig`:

```
AddrSpacePartition.physmap: [0xFFFF_FF80_0000_0000, 0xFFFF_FF88_0000_0000)
```

Size: 32 GiB. Maps all physical memory (free and ACPI regions) using the largest available page sizes:
- 1 GiB pages where physically aligned.
- 2 MiB pages where 2 MiB-aligned.
- 4 KiB pages otherwise.

**Mapping**: Done during `memory.init` before `dropIdentityMapping`. Each memory map entry (free or ACPI type) is mapped with kernel RW, no-execute, write-back, global permissions.

**Address conversion**:
- `VAddr.fromPAddr(paddr, null)` -- adds physmap base offset.
- `PAddr.fromVAddr(vaddr, null)` -- subtracts physmap base offset.

### Kernel VA Layout

```
[0x0000_0000_0000_0000, 0xFFFF_8000_0000_0000)  -- User address space
  [0x0000_0000_0000_0000, 0x0000_0000_0000_1000)  -- Null guard (unmapped)
  [0x0000_0000_0000_1000, 0x0000_1000_0000_0000)  -- ASLR zone
  [0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)  -- Static reservation zone

[0xFFFF_8000_0000_0000, 0xFFFF_8400_0000_0000)  -- Kernel address space
  [0xFFFF_8000_0000_0000, +KERNEL_STACKS_RES)      -- Kernel stacks (slot-based)
  [+kernel_stacks.end, +16 MiB)                    -- VmNode slab
  [+vm_node_slab.end, +16 MiB)                     -- VmTree node slab
  [+vm_tree_slab.end, +16 MiB)                     -- SharedMemory slab
  [+shm_slab.end, +16 MiB)                         -- DeviceRegion slab
  [+device_region_slab.end, +16 MiB)               -- Process slab
  [+proc_slab.end, +16 MiB)                        -- Thread slab
  [+thread_slab.end, +16 MiB)                      -- Vm slab
  [+vm_slab.end, +16 MiB)                          -- VCpu slab
  [+vcpu_slab.end, +16 MiB)                        -- PmuState slab
  [+pmu_slab.end, +1 GiB)                          -- Heap tree node slab
  [+heap_tree.end, +256 GiB)                       -- Kernel heap

[0xFFFF_FF80_0000_0000, 0xFFFF_FF88_0000_0000)  -- Physmap (32 GiB)

[0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_C000_0000)  -- Kernel code (KASLR range, 1 GiB)
  Kernel image (.text, .rodata, .data, .bss) loaded at a random
  page-aligned offset within this range by the bootloader.
```

Comptime assertions verify that no kernel VA regions overlap.

### Memory Initialization Sequence

`memory.init(firmware_mmap)`:
1. Collapse firmware memory map entries.
2. Find smallest-address region, largest-address free region, and largest free region.
3. Initialize bump allocator on the largest free region (physical addresses, identity-mapped).
4. Set up physmap: map all free and ACPI physical memory into the physmap VA range using `mapPageBoot` with the bump allocator for page table allocation. Uses largest available page sizes (1G > 2M > 4K).
5. Switch bump allocator addresses from physical to virtual (physmap).
6. `arch.dropIdentityMapping()`.
7. Initialize buddy allocator spanning from smallest physical address to end of largest-address free region. Metadata allocated from bump allocator.
8. Feed all free memory map regions into buddy allocator (excluding bump allocator's consumed range and low memory below 1 MiB).
9. Initialize global PMM with buddy allocator as backing.
10. Initialize slab bump allocators for each kernel object type (VmNode, VmTree, SHM, DeviceRegion, Process, Thread, Vm, VCpu, PmuState) -- each gets a 16 MiB VA region.
11. Initialize slabs: VmNode slab, VmTree slab, DeviceRegion slab, SharedMemory slab, Vm slab, VCpu slab, PmuState slab.

`memory.initHeap()`:
1. Initialize heap tree bump allocator (1 GiB region).
2. Initialize heap tree allocator (slab for RBT nodes, backed by heap tree bump).
3. Initialize heap allocator (256 GiB VA reservation, free tree backed by heap tree allocator).

---

## 15. Device Enumeration

### Overview

Device enumeration runs during `arch.parseFirmwareTables` (called from `kMain`). It discovers PCI devices and legacy serial ports, registers them in a global device table, and grants all device handles to the root service at boot.

### Device Registry

Defined in `kernel/devices/registry.zig`:

```
device_table: [MAX_DEVICES]*DeviceRegion   -- MAX_DEVICES = 128
device_count: u32
```

**registerMmioDevice(phys_base, size, device_class, pci_vendor, pci_device, pci_class, pci_subclass) -> *DeviceRegion**: Allocate DeviceRegion from slab, populate fields, add to table. Error if table full.

**registerPortIoDevice(base_port, port_count, device_class, pci_vendor, pci_device, pci_class, pci_subclass) -> *DeviceRegion**: Same for Port I/O devices.

**grantAllToRootService(root_proc)**: Iterate device table, insert each as a PermissionEntry with rights `0b111` (map + grant + dma) into the root service's permissions table.

### DeviceRegion Struct

```
DeviceRegion {
    phys_base: PAddr
    size: u64
    base_port: u16
    port_count: u16
    device_type: DeviceType { mmio, port_io }
    device_class: DeviceClass { network, serial, storage, display, timer, usb, unknown }
    pci_vendor: u16
    pci_device: u16
    pci_class: u8
    pci_subclass: u8
}
```

Allocated from `SlabAllocator(DeviceRegion, false, 0, 32)`.

### PCI Enumeration -- ECAM (Enhanced Configuration Access Mechanism)

Triggered when an MCFG ACPI table is found.

**parseMcfg(mcfg_vaddr, length)**:
1. Parse MCFG entries (16 bytes each after 44-byte header): base address (8 bytes), segment group (2), start bus (1), end bus (1).
2. For each entry: compute ECAM region size as `(end_bus - start_bus + 1) << 20` bytes.
3. Map entire ECAM region into physmap (page-by-page, 4K pages, uncacheable).
4. Call `enumeratePci(ecam_base, start_bus, end_bus)`.

**enumeratePci(ecam_base, start_bus, end_bus)**:
1. For each bus in [start_bus, end_bus]:
2. For each device slot 0..31:
3. Read vendor/device ID at `ecam_base + (bus << 20) | (dev << 15) | (func << 12) | offset`. If vendor == 0xFFFF, skip.
4. Read header type. If bit 7 set (multi-function), scan functions 0..7; otherwise function 0 only.
5. For each function: read class/subclass. Skip bridges (class 0x06). Skip non-Type-0 headers.
6. Map PCI class to DeviceClass: 0x01 = storage, 0x02 = network, 0x03 = display, 0x0C/0x03 = USB, else = unknown.
7. Enumerate BARs 0..5:
   - If BAR bit 0 set (I/O space): extract port base (`bar & 0xFFFC`), register as Port I/O device with port_count = 32.
   - If BAR bit 0 clear (memory space): extract physical address (`bar & 0xFFFFFFF0`). For 64-bit BARs (type 2), read next BAR for high 32 bits. Register as MMIO device with size = PAGE4K.
   - Skip zero BARs.

### PCI Enumeration -- Legacy Config Space

Fallback when MCFG is not present or yields zero devices.

**enumeratePciLegacy()**:
1. Same bus/device/function walk as ECAM, but for all 256 buses.
2. Config space access via I/O ports: write address to port 0xCF8 (`0x80000000 | bus << 16 | dev << 11 | func << 8 | offset & 0xFC`), read data from port 0xCFC.
3. Same BAR parsing logic, except 64-bit BARs are not supported in legacy mode (only low 32 bits).

### Serial Port Probing

**probeSerialPorts()**:
1. Check COM1 (0x3F8), COM2 (0x2F8), COM3 (0x3E8), COM4 (0x2E8).
2. For each port: write 0xA5 to scratch register (port + 7), read back. If readback == 0xA5, port is present.
3. Clear scratch register (write 0x00).
4. Register as Port I/O device: `base_port = port, port_count = 8, device_class = .serial, pci_vendor = 0, pci_device = 0, pci_class = 0, pci_subclass = 0`.

### Kernel-Internal Devices

HPET, LAPIC, and I/O APIC are discovered during ACPI parsing and mapped into kernel VA space, but they are **not** registered in the device table and **not** exposed to userspace. They are used exclusively by the kernel for timing, interrupt routing, and IPI.

---

## 16. Message Passing Internals

### Overview

Synchronous, zero-buffered IPC. Messages are transferred directly from sender registers to receiver registers via the saved CPU context on each thread's kernel stack. No kernel-internal message queues or buffers.

Four syscalls: `send` (non-blocking fire-and-forget), `call` (blocking RPC), `recv` (receive with blocking/non-blocking flag), `reply` (respond to pending message, optional atomic recv).

### Register Convention

5 payload registers in order: `rdi`(0), `rsi`(1), `rdx`(2), `r8`(3), `r9`(4). Only caller-saved registers are used for payload. `r13` = target process handle. `r14` = metadata flags. `rax` = syscall number / return status. `rcx` and `r11` reserved for future `syscall` instruction.

r14 encoding varies by syscall — see spec §2.11.

### MessageBox

IPC message passing state is encapsulated in the `MessageBox` struct on each Process, accessed as `proc.msg_box`. See §17 for details.

### Thread Struct Fields

```
ipc_server: ?*Process         — back-pointer to process we're waiting for reply from (for cleanup)
```

### Context Switch Strategy

IPC syscalls use direct `arch.switchTo` calls, bypassing the scheduler interrupt. This preserves `thread.ctx` pointing at the int 0x80 frame, allowing `reply` to write directly into the caller's saved registers.

`switchToThread(current, target, ctx, enqueue_current)`:
1. Saves `current.ctx = ctx` and clears `on_cpu`
2. If `enqueue_current`, places current on run queue (after ctx is saved, before switch)
3. Picks target core respecting affinity via `pickCoreForThread`
4. Same core (fast path): direct `switchTo`
5. Different core: enqueue target remotely, IPI the target core, run next ready thread locally
6. Returns `E_BUSY` if all affinity cores are pinned

`switchToNextReady()`: dequeues from current core's run queue and switches. Used when blocking without a specific target.

### Capability Transfer

When r14 bit 3 is set, the last 2 payload words are `handle` + `rights`. The kernel validates the sender's permissions and transfers at send time (before the message is delivered to the receiver).

Transfer rules by handle type:
- **SHM**: validate `grant` bit on SHM handle, rights subset, `incRef`, `insertPerm` into target
- **Process handles**: validate `grant` bit on process handle, rights subset, `insertPerm` into target
- **Device handles**: validate `grant` bit on device handle, parent→child only, exclusive transfer (removed from sender)

### ProcessHandleRights

When a process holds a handle to another process (not `HANDLE_SELF`), the `rights` field uses `ProcessHandleRights` encoding: `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5), `fault_handler`(6). `proc_create` grants the parent full `ProcessHandleRights` on the child handle. The `grant` bit controls whether the handle can be re-transferred to another process via capability transfer. The `kill` bit controls whether `revoke_perm` triggers `killSubtree` or just drops the handle.

### Cleanup on Process Death

`cleanupIpcState()` runs at the beginning of `cleanupPhase1`:

**Server dies (this process has waiters):**
1. Drain `msg_box.waiters` priority queue: for each dequeued waiter, set `waiter.ipc_server = null`, write `E_NOENT` to `waiter.ctx.regs.rax`, wake waiter
2. If `msg_box.pending_caller` non-null: same treatment
3. Clear all msg_box fields

**Caller dies (this process has threads blocked on other processes):**
1. For each thread with `ipc_server` set: lock the server, remove this thread from `msg_box.pending_caller` or `msg_box.waiters` (via `removeLocked`), clear `ipc_server`, unlock server

Both sides clean up to prevent dangling pointers regardless of death order.

### Restart Semantics

On process restart, IPC state persists with adjustments:
1. If `msg_box.pending_caller` is set (message delivered but not replied to), the caller is re-enqueued into `msg_box.waiters` so the restarted process can `recv` it again
2. `msg_box.pending_reply` cleared, `msg_box.receiver` cleared (old thread is dead)
3. `msg_box.waiters` queue persists untouched — callers from other processes remain blocked

This allows a server to crash mid-handling, restart, and pick up right where it left off.

### Process Handle Refcounting

Each Process has a `handle_refcount: u32` tracking how many perm table entries across all processes reference it (both `.process` and `.dead_process` entries). Incremented atomically on `insertPerm` for process/dead_process entries, decremented on `removePerm` and during `cleanupPhase1` perm table teardown.

`dead_process` KernelObject stores `*Process` (not just fault info), keeping the struct alive for refcount management. Fault reason and restart count are read directly from the Process struct fields.

`cleanupPhase2` sets `cleanup_complete = true` and only calls `allocator.destroy` if `handle_refcount == 0`. If refcount > 0, the struct persists as a zombie — address space freed, perm table cleared, but the struct itself remains allocated. When the last handle holder calls `removePerm`, the decrement sees `cleanup_complete == true` and `handle_refcount == 0`, triggering `allocator.destroy`.

---

## 17. MessageBox Internals

`kernel/proc/message_box.zig` defines a single `MessageBox` struct used for both IPC message passing and fault delivery. Each `Process` instantiates two of them: `proc.msg_box` for IPC, `proc.fault_box` for faults. The struct is payload-agnostic — it owns a state machine, a FIFO wait queue of `*Thread`, the blocked receiver slot, the pending-reply slot, and a lock. Callers (the IPC syscalls and the fault delivery path) extract payloads between state transitions.

### MessageBox

```
State = enum { idle, receiving, pending_reply }

MessageBox {
    state:          State
    waiters:        PriorityQueue // priority-ordered queue of waiting senders (intrusive via thread.next)
    receiver:       ?*Thread      // thread blocked on recv(), valid iff state == .receiving
    pending_thread: ?*Thread      // thread that owns the currently-pending message,
                                  // valid iff state == .pending_reply; for IPC this is
                                  // the caller (or null for send-with-no-caller); for
                                  // faults this is always the faulted thread itself
    lock:           SpinLock
}
```

The queued unit is `*Thread` for both uses. For IPC, the queued thread is the calling thread of `ipc_call`, and its payload lives in `thread.ctx.regs` (saved by the int 0x80 entry). For faults, the queued thread is the faulted thread itself; its payload is `thread.fault_reason` / `thread.fault_addr` / `thread.fault_rip` plus the register snapshot in `thread.ctx.regs`. The `waiters` priority queue reuses the existing `thread.next` pointer — safe because a thread is in at most one of {run queue, IPC waiters, fault box queue} at any moment.

### State transitions

| From | To | Trigger |
|---|---|---|
| `idle` | `receiving` | `beginReceivingLocked(thread)` — caller blocks on recv with empty queue |
| `idle` | `pending_reply` | `beginPendingReplyLocked(t)` — recv dequeued a sender, or send delivered to a non-blocked box |
| `receiving` | `idle` | `takeReceiverLocked()` — sender takes the blocked receiver out of the box (followed by either direct delivery or queue) |
| `pending_reply` | `idle` | `endPendingReplyLocked()` — reply was delivered |
| `pending_reply` | `pending_reply` | Not valid — `recv` while pending returns `E_BUSY` |

### Methods

All methods take a locked `MessageBox` (the `*Locked` suffix); the lock is the caller's responsibility.

- `enqueueLocked(sender)` — enqueue `sender` into the `waiters` priority queue via `waiters.enqueue(sender)`. No state change.
- `dequeueLocked() → ?*Thread` — dequeue the highest-priority waiter via `waiters.dequeue()`, or `null` if empty. No state change.
- `removeLocked(target) → bool` — remove `target` from the `waiters` priority queue via `waiters.remove(target)` (used when a queued caller dies). Returns whether it was present.
- `beginReceivingLocked(thread)` — assert `state == .idle && queue_head == null && receiver == null`, then set `receiver = thread`, `state = .receiving`.
- `takeReceiverLocked() → *Thread` — assert `state == .receiving`, return and clear receiver, set `state = .idle`.
- `beginPendingReplyLocked(?*Thread)` — assert `state != .pending_reply`, set `pending_thread`, `state = .pending_reply`.
- `endPendingReplyLocked() → ?*Thread` — assert `state == .pending_reply`, return and clear pending_thread, set `state = .idle`.
- `isPendingReply() / isReceiving() / hasQueuedLocked()` — state queries.

### Process integration

`Process` holds two instances:
```
msg_box:   MessageBox    // IPC; manipulated by sysIpcSend/Call/Recv/Reply
fault_box: MessageBox    // faults; manipulated by faultBlock and sysFaultRecv/Reply
```

The two instances are completely independent — they have their own locks, state, and queues. A process can have its IPC box in `pending_reply` and its fault box in `receiving` simultaneously with no interaction.

### Per-thread fault metadata

When a thread enters `.faulted`, the fault payload is stamped onto the thread itself in `kernel/sched/thread.zig`:
```
fault_reason: FaultReason   // none / unmapped_access / breakpoint / ...
fault_addr:   u64           // CR2 for page faults; faulting RIP for non-PF exceptions
fault_rip:    u64           // RIP at the moment of the fault
```
The full saved register state lives in `thread.ctx.regs` (set by the exception entry stub before any kernel handler runs). Materializing a `FaultMessage` for userspace just reads these fields plus the perm-table handle IDs — no separate allocation.

### Cleanup paths

`Process.cleanupIpcState` (called from `cleanupPhase1`) drains `msg_box.waiters` priority queue: each dequeued waiter is woken with `E_NOENT` in its saved rax, the receiver (if any) is dropped, the pending caller (if any) is woken with `E_NOENT`. Then for every thread in the dying process whose `ipc_server` points elsewhere, the corresponding entry is removed from that other process's `msg_box` (via `removeLocked` or pending) so no `*Thread` references the dying process.

`Process.releaseFaultHandler` and `cleanupPhase1` perform the analogous cleanup for `fault_box`: any thread in the `waiters` priority queue or in `pending_thread` whose owning process matches is removed (via `removeLocked`), so the box never holds a stale `*Thread`.

---

## 18. Fault Routing Internals

Defined in `Process.faultBlock` (`kernel/proc/process.zig`). The fault delivery path is called from `kernel/arch/x64/exceptions.zig` (general exceptions) and `kernel/memory/fault.zig` (page faults) after the exception handler identifies a userspace fault.

### faultBlock(self, thread, reason, fault_addr, rip) → bool

Returns `true` if the fault was queued (caller should yield); `false` if the process must die immediately (§2.12.7 / §2.12.9). The caller — the exception handler — is responsible for stamping the metadata onto the thread *before* this function (or at function entry) and for either yielding or initiating kill on the return value.

```
1. Stamp metadata onto the thread:
   thread.fault_reason = reason
   thread.fault_addr   = fault_addr
   thread.fault_rip    = rip

2. handler = self.faultHandlerOf()
   - returns self.fault_handler_proc if non-null
   - else returns self iff self holds the fault_handler ProcessRights bit on slot 0
   - else returns null → return false (no handler, kill)

3. If handler == self (self-handling):
   a. Lock self.lock.
      alive = num_threads - popcount(faulted_thread_slots)
      If alive <= 1:
        unlock; return false  (§2.12.7 / §2.12.9 — no surviving thread to recv,
                               immediate kill/restart)
   b. thread.state = .faulted
      set bit thread.slot_index in faulted_thread_slots
      Unlock self.lock.
   c. Lock self.fault_box.lock.
      If self.fault_box.isReceiving():
        Direct-deliver to the waiter (see §6 below).
      Else:
        self.fault_box.enqueueLocked(thread)
      Unlock self.fault_box.lock.
   d. return true

4. If handler != self (external handler):
   a. Lock self.lock.
      For every other thread T in self:
        if T.state == .running or T.state == .ready:
          T.state = .suspended
          set bit T.slot_index in self.suspended_thread_slots
      thread.state = .faulted
      set bit thread.slot_index in self.faulted_thread_slots
      Unlock self.lock.
   b. Lock handler.fault_box.lock.
      If handler.fault_box.isReceiving():
        Direct-deliver to the waiter.
      Else:
        handler.fault_box.enqueueLocked(thread)
      Unlock handler.fault_box.lock.
   c. return true
```

**TODO (§2.12.11):** the external-handler branch should, *before* applying stop-all in step 4a, check the faulted thread's `exclude_oneshot` / `exclude_permanent` perm-entry flags in the handler's table and skip stop-all (and clear `exclude_oneshot`) if either is set. This is not yet wired up.

### Direct delivery to a blocked receiver

When the box is in `.receiving` state, the kernel cannot rely on the receiver to re-execute the dequeue logic on wake-up — `sysFaultRecv`'s blocking path saves the receiver's int 0x80 frame and calls `switchToNextReady`, so when the receiver is later resumed it returns straight to userspace through the syscall epilogue. The fault box therefore has to materialize the `FaultMessage` in the receiver's address space *before* waking it.

`Process.deliverFaultToWaiter(handler, receiver, faulted)` does this:
1. Read the receiver's user buffer pointer from `receiver.ctx.regs.rdi` (the saved arg from when the receiver entered `sysFaultRecv`).
2. Look up the source thread's handle and the source process's handle in the handler's perm table (`lookupHandlesForFault`).
3. Build the `arch.fault_msg_size`-byte `FaultMessage` in a stack-local buffer.
4. Walk the receiver process's page table page-by-page (`arch.resolveVaddr` + physmap) and copy the message into the user buffer.
5. Set `receiver.ctx.regs.rax = thread_handle` so the syscall returns the fault token.
6. Wake the receiver via `wakeReceiver` (spin on `on_cpu`, mark `.ready`, enqueue on its core).

This is the only place in the kernel that performs a cross-address-space write into another process's userspace buffer, and it's intentional — the alternative (have the receiver loop and re-dequeue after wake) would require either a setjmp/longjmp-style continuation or making `switchToNextReady` save a kernel RIP, neither of which the kernel has.

### FaultMessage layout

Arch-dependent extern struct (`arch.fault_msg_size` bytes), matches `libz.FaultMessage`.
The header (bytes 0–31) is fixed; the register tail varies by architecture.

```
offset  size              field
  0      8               process_handle  (handler's perm-table handle for source process)
  8      8               thread_handle   (handler's perm-table handle for source thread; = fault token)
 16      1               fault_reason    (FaultReason u8)
 17      7               _pad
 24      8               fault_addr      (CR2 / FAR_EL1 for page faults; faulting VA otherwise)
 32      8               ip              (instruction pointer at fault)
 40      8               flags           (RFLAGS on x86-64, SPSR_EL1 on aarch64)
 48      8               sp              (stack pointer)
 56      N×8             gprs            (arch.fault_gpr_count GPRs)
```

| Architecture | GPR count | fault_regs_size | fault_msg_size |
|--------------|-----------|-----------------|----------------|
| x86-64       | 15        | 144             | 176            |
| aarch64      | 31        | 272             | 304            |

Both the synchronous-dequeue path (`writeFaultMessage` in `syscall.zig`) and the cross-AS direct delivery path (`writeFaultMessageInto` in `proc/process.zig`) build the same buffer via a shared `buildFaultMessage` helper.

---

## 19. VM Internals

### Architecture Layering

The VM arch dispatch follows the same pattern as the rest of the kernel:

```
arch/dispatch.zig       — generic VM interface, comptime dispatch on arch
arch/x64/vm.zig         — x64 VM interface, runtime dispatch on CPU vendor (Intel vs AMD)
arch/x64/intel/vmx.zig  — Intel VT-x implementation
arch/x64/amd/svm.zig    — AMD-V/SVM implementation (VMCB, NPT, VMRUN/#VMEXIT, MSR/IO intercepts)
```

The runtime vs comptime distinction matters: Intel vs AMD is a runtime check (CPUID vendor detection at boot) because the same kernel binary runs on both. x64 vs other architectures is comptime because you cross-compile for a target.

Generic types exposed by `arch/dispatch.zig` for VM support:

```zig
pub const GuestState = switch (builtin.cpu.arch) {
    .x86_64 => x64.GuestState,
    .aarch64 => aarch64.GuestState,
    else => @compileError("unsupported architecture"),
};
```

Same pattern for `VmExitInfo`, `GuestInterrupt`, `GuestException`, `VmPolicy`. The aarch64 variants are empty struct stubs.

Dispatch functions added to `arch/dispatch.zig`:
- `pub fn vmInit() void` — dispatches to arch VM initialization (CPUID feature detection, global flag set).
- `pub fn vmPerCoreInit() void` — dispatches to per-core arch VM setup (VMXON on Intel, EFER.SVME on AMD).
- `pub fn vmSupported() bool` — returns whether hardware virtualization is available (cached from `vmInit`).

Hardware virtualization availability is detected once at boot in `arch.vmInit()` and cached. `vm_create` checks this cached flag and returns `E_NODEV` if unavailable.

### x64-Specific Types

Defined in `kernel/arch/x64/vm.zig`:

- `GuestState` — all x64 guest registers: GP regs (RAX-R15), RIP, RSP, RFLAGS, CR0/CR2/CR3/CR4, segment registers (CS/DS/ES/FS/GS/SS with selector, base, limit, access rights), MSRs that need saving.
- `VmExitInfo` — tagged union of all x64 exit reasons with qualification data.
- `GuestInterrupt` — x64 interrupt injection fields: vector, type, error code valid flag.
- `GuestException` — x64 exception injection fields: vector, error code, fault address.
- `VmPolicy` — x64 policy table: CPU feature query responses (CPUID leaf/subleaf → EAX/EBX/ECX/EDX), privileged register policy.

`kernel/arch/x64/vm.zig` detects Intel vs AMD at runtime via CPUID vendor string and dispatches all VM operations to `intel/vmx.zig` or `amd/svm.zig`. Also handles per-core VMX/SVM initialization called from `sched.perCoreInit()`.

### Vm Struct

Defined in `kernel/arch/x64/kvm/vm.zig`:

```
Vm {
    vcpus:                [MAX_VCPUS]*VCpu  -- MAX_VCPUS = 64
    num_vcpus:            u32
    owner:                *Process
    exit_box:             VmExitBox
    policy:               arch.VmPolicy      -- static, set at creation, never changes
    lock:                 SpinLock
    vm_id:                u64                -- monotonic ID
    arch_structures:      PAddr              -- physical address of arch-specific VM structures (VMCB on AMD, VMCS+EPT on Intel)
    guest_mem:            GuestMemory        -- tracks guest physical regions for cleanup
    guest_ram_host_base:  u64                -- host VA base of the main guest RAM region (first vm_guest_map at guest_addr=0)
    guest_ram_size:       u64                -- size of that main guest RAM region
    lapic:                Lapic              -- in-kernel LAPIC emulation state
    ioapic:               Ioapic             -- in-kernel IOAPIC emulation state
}
```

`MAX_VCPUS` = 64, matching `MAX_THREADS`.

The Vm is not a perm table entry type — ownership is implicit via `proc.vm`. No capability transfer of VM objects is supported.

`guest_ram_host_base`/`guest_ram_size` are captured on the first `vm_guest_map` call at `guest_addr=0` and exist so the kernel MMIO decoder can read guest physical memory directly (page table walks for instruction fetch and operand resolution) without going through the EPT.

`lapic` and `ioapic` cross-link in `vm_create`: `ioapic.init(&vm.lapic)` so the IOAPIC can deliver interrupts, and `lapic.init(&vm.ioapic)` so the LAPIC can notify the IOAPIC on EOI for level-triggered IRQs.

The `Vm` struct exposes a small set of `pub fn` methods so callers (vcpu.zig, exit_handler.zig, mmio_decode.zig) never reach into the LAPIC/IOAPIC fields directly:
- `exitBox()` — returns `*VmExitBox`. Used so callers don't need to know the box lives inside `Vm`.
- `injectExternal(vector)` — wraps `lapic.injectExternal`. Single entry for routing an IRQ vector into the LAPIC IRR.
- `tickInterruptControllers(elapsed_ns)` — wraps `lapic.tick`. Future timers (HPET/PIT) hook in here.
- `deliverPendingInterrupts(*GuestState)` — checks LAPIC for a deliverable vector and, if guest IF=1 with no pending EVENTINJ, builds the EVENTINJ qword and accepts the vector. Called from the vCPU entry loop before VMRUN.
- `tryHandleMmio(vcpu, guest_phys)` — if `guest_phys` falls in the LAPIC or IOAPIC page, pre-fetches instruction bytes from guest RIP and calls `mmio_decode.decodeBytes(buf)` to decode the faulting instruction, dispatches to the matching controller, writes any read result back via `writeGpr`, and advances RIP. Returns true if handled. Internal helpers `handleLapicMmio`/`handleIoapicMmio` are non-pub.
- `guestPhysToHost(phys, len)` / `readGuestPhysSlice(phys, len)` — bounds-checked guest-phys → host-VA translation backed by `guest_ram_host_base`/`guest_ram_size`. Single home for the arithmetic so the bookkeeping is owned by `Vm`.

### VCpu Struct

Defined in `kernel/arch/x64/kvm/vcpu.zig`:

```
VCpu {
    thread:         *Thread
    vm:             *Vm
    guest_state:    arch.GuestState     -- current guest register snapshot
    state:          VCpuState           -- { idle, running, exited, waiting_reply }
    last_exit_info: arch.VmExitInfo     -- most recent VM exit info (set by entry loop)
    guest_fxsave:   arch.FxsaveArea     -- guest FPU/SSE state, 512B/16B-aligned, defaults MXCSR=0x1F80, FCW=0x037F
}
```

State meanings:
- `idle` — created but not yet started via `vm_vcpu_run`.
- `running` — actively executing guest code or scheduled to do so.
- `exited` — hit a VM exit, waiting for `vm_recv`.
- `waiting_reply` — exit message delivered, pending reply.

vCPU threads have a fixed kernel-managed entry point in `kernel/arch/x64/kvm/vcpu.zig` (`vcpuEntryPoint`). When scheduled, the entry loop:

1. If state ≠ `running`, blocks the thread and yields. On wake, resets the TSC reference and continues.
2. Reads TSC and calls `vm.tickInterruptControllers(elapsed_ns)` to advance the in-kernel LAPIC timer. The TSC tick is treated as 1 ns (assumes a ~1 GHz bus clock).
3. Calls `vm.deliverPendingInterrupts(&guest_state)`. If the LAPIC has a deliverable pending vector and guest `IF=1` with no prior `pending_eventinj`, the Vm method builds the EVENTINJ qword (vector | type=external | valid bit) and marks the vector accepted in the LAPIC.
4. Calls `arch.vmResume(&guest_state, vm.arch_structures, &guest_fxsave)` to enter guest mode. The arch layer copies guest state into VMCB/VMCS, runs VMRUN/VMRESUME, and returns the exit reason on `#VMEXIT`.
5. Stores the exit info in `last_exit_info` and calls `exit_handler.handleExit(vcpu, exit_info)`.
6. Loops.

vCPU threads are allocated from the existing `ThreadAllocator` slab.

### VmExitBox

Defined in `kernel/arch/x64/kvm/exit_box.zig`:

```
VmExitBox {
    state:    VmExitBoxState    -- { idle, receiving, pending_replies }
    queue:    PriorityQueue     -- queued exited vCPUs waiting to be recv'd
    receiver: ?*Thread          -- thread blocked on vm_recv
    pending:  [MAX_VCPUS]bool   -- which vCPUs have unresolved exits
    lock:     SpinLock
}
```

Unlike FaultBox which has a single `pending_reply` constraint, VmExitBox tracks one pending exit per vCPU independently. Multiple vCPUs can exit simultaneously — each enqueues on the box. The VM manager dequeues and replies to each via the exit token (the vCPU's thread handle ID). The box moves to `idle` only when all pending exits are resolved.

State transitions:
- `idle` → `receiving`: VM manager calls blocking `vm_recv` with empty queue.
- `idle` → `pending_replies`: first vCPU exit arrives, VM manager calls `vm_recv` and dequeues it.
- `receiving` → `pending_replies`: vCPU exit delivered directly to blocked receiver.
- `pending_replies` → `idle`: last pending exit resolved via `vm_reply`.
- `pending_replies` → `pending_replies`: additional vCPU exits arrive or are resolved while others remain pending.

### VmExitMessage and VmReplyAction

Defined in `kernel/arch/x64/kvm/exit_box.zig`:

```
VmExitMessage {
    thread_handle: u64              -- vCPU thread handle ID in caller's perm table
    exit_info:     arch.VmExitInfo  -- arch-specific exit reason and qualification
    guest_state:   arch.GuestState  -- full guest register snapshot at time of exit
}
```

```
VmReplyAction = union(enum) {
    resume_guest:     arch.GuestState
    inject_interrupt: arch.GuestInterrupt
    inject_exception: arch.GuestException
    map_memory: struct { host_vaddr: u64, guest_addr: u64, size: u64, rights: u8 }
    kill:             void
}
```

### Exit Handler

Defined in `kernel/arch/x64/kvm/exit_handler.zig`. Called from the vCPU entry loop after `arch.vmResume()` returns. Classifies exits as kernel-handled or VMM-handled.

**Kernel-handled inline** — resolved without VMM involvement, the entry loop re-enters the guest on return:
- **EPT/NPT violations on the LAPIC or IOAPIC page** (`0xFEE00000` / `0xFEC00000`): the handler calls `vm.tryHandleMmio(vcpu, ept.guest_phys)`, which routes the access to the matching controller, pre-fetches instruction bytes and decodes via `mmio_decode.decodeBytes`, writes any read result back into the destination GPR via `writeGpr`, and advances RIP by the decoded instruction length. The handler imports neither `lapic` nor `ioapic` directly — the only entry point is `Vm.tryHandleMmio`.
- Guest memory is no longer demand-paged: all regions are eagerly mapped at `vm_guest_map` time. EPT/NPT violations on truly unmapped regions fall through to the VMM as exits.
- **`cpuid`** where `(leaf, subleaf)` matches an entry in `vm.policy.cpuid_responses`: the kernel writes the pre-configured `eax/ebx/ecx/edx` into guest GPRs and advances RIP by 2.
- **`interrupt_window` (VMEXIT_VINTR)**: returns immediately so the entry loop checks `vm.deliverPendingInterrupts` again now that guest `IF=1`.
- **VMEXIT_INTR (0x060) / VMEXIT_NMI (0x061) / VMEXIT_VINTR (0x064)**: the host interrupt handler already ran on `#VMEXIT`. The kernel just returns so the entry loop re-enters the guest.

**VMM-handled** — enqueued on VmExitBox:
- Guest device I/O (port I/O, MMIO on unmapped regions other than LAPIC/IOAPIC).
- EPT/NPT violations on truly unmapped guest physical regions.
- `cpuid` not in `vm.policy`.
- `cr_access` (CR policy lookup is stubbed; all CR exits currently fall through to the VMM).
- `msr_read` / `msr_write` exits the kernel didn't intercept via the MSRPM passthrough bitmap.
- `hlt`, `shutdown`, `triple_fault`, exceptions, and any other unclassified exits.

For VMM-handled exits, the handler transitions the vCPU to `.exited` and calls `exit_box.queueOrDeliver(vm.exitBox(), vm, vcpu)`. That function takes the box lock and either delivers the exit message directly to a thread blocked on `vm_recv` (via the internal `deliverExit` helper) or enqueues the vCPU thread on the `VmExitBox` for a later `vm_recv`. Direct delivery spins on `receiver.on_cpu` until the receiver is fully off-CPU, then writes the `VmExitMessage` into the receiver's saved `RDI` buffer pointer and re-enqueues it on the scheduler.

### Guest Memory

Defined in `kernel/arch/x64/kvm/guest_memory.zig`. Tracks guest physical memory regions for cleanup.

Guest physical address space is managed separately from host virtual address space. The VM has its own arch-specific guest physical memory structures (EPT on x64, Stage-2 page tables on ARM).

`vm_guest_map(host_vaddr, guest_addr, size, rights)` maps an existing host virtual memory range into the guest's physical address space. The kernel walks the VMM process's page tables to resolve each host page to its physical address, then wires that physical page into the guest EPT at the corresponding guest physical address. The VMM retains host access to the pages. `rights` controls guest access permissions (read, write, execute) in EPT.

EPT violations on unmapped guest physical regions are delivered to the VMM as exits. The VMM can respond by calling `vm_guest_map` to wire more host pages, or by injecting a fault into the guest.

### In-kernel LAPIC

Defined in `kernel/arch/x64/kvm/lapic.zig`. Single-vCPU xAPIC emulation per Intel SDM Vol 3 Ch 13. APIC base is fixed at `0xFEE00000` (the kernel refuses to `vm_guest_map` over this page in `vm.zig`). All registers are 32-bit on 16-byte boundaries.

State the `Lapic` struct holds: APIC ID, TPR, LDR/DFR, SVR, ESR (with shadow for accumulated errors), ICR_LO/HI, six LVT registers (timer/thermal/perf/LINT0/LINT1/error), timer ICR/CCR/DCR, a `timer_accum_ns` carry for fractional ticks between `tick()` calls, three 256-bit vectors `irr`/`isr`/`tmr`, and a back-pointer to the paired `Ioapic`.

Public surface used by the rest of the kernel (all called through `Vm` methods, never directly from outside `kvm/`):
- `init(ioapic_ptr)` — reset to power-up state per SDM 13.4.7.1.
- `mmioRead(offset)` / `mmioWrite(offset, value)` — handle MMIO accesses dispatched from `Vm.tryHandleMmio`.
- `tick(elapsed_ns)` — advance the timer. Treats the bus clock as 1 GHz, decodes the divide config (table from Figure 13-10), counts down `timer_current_count`, and fires the LVT timer vector in one-shot or periodic mode. TSC-deadline mode is stubbed.
- `getPendingVector()` — returns the highest-priority IRR vector that beats both ISR and TPR priority classes (and only if the APIC is software-enabled). Used by `Vm.deliverPendingInterrupts` to decide whether to inject before VMRUN.
- `acceptInterrupt(vector)` — moves a vector from IRR → ISR.
- `injectExternal(vector)` — set IRR for an external IRQ delivered by the IOAPIC.
- Internal (non-pub): `handleEOI` clears the highest ISR bit and notifies the IOAPIC for level-triggered vectors via `tmr`. `handleICR` covers self-IPI delivery (only shorthand=01 fixed-mode IPIs are implemented; broadcast/init/SIPI are stubbed since this is single-vCPU).

### In-kernel IOAPIC

Defined in `kernel/arch/x64/kvm/ioapic.zig`. 24-pin IOAPIC per Intel 82093AA datasheet. Base fixed at `0xFEC00000` (also guarded in `vm_guest_map`). Register access is the standard indirect IOREGSEL (offset 0x00) / IOWIN (offset 0x10) protocol.

State the `Ioapic` struct holds: `ioregsel`, `ioapic_id`, the 24-entry `redir_table` (each entry 64 bits, all reset with the mask bit set), an `irq_level` bitmap tracking the last asserted state per pin (used to debounce edge-triggered IRQs and re-fire level-triggered IRQs after EOI), and a back-pointer to the paired `Lapic`.

Public surface:
- `init(lapic_ptr)` — reset.
- `mmioRead(offset)` / `mmioWrite(offset, value)` — MMIO handlers used by `Vm.tryHandleMmio`. Indirectly drive internal `readRegister`/`writeRegister` helpers, which know about ID/VER/ARB and the 0x10..0x3F redirection-table window. Bits 12 (delivery status) and 14 (remote IRR) in the redirection table are read-only from the guest.
- `assertIrq(irq)` — used by both the kernel-side serial path and the `vm_ioapic_assert_irq` syscall. Honors the per-entry mask bit, debounces edges, and tracks remote IRR for level-triggered entries before calling the internal `deliverInterrupt`.
- `deassertIrq(irq)` — clears the level bit for level-triggered re-delivery.
- `handleEOI(vector)` — called by the LAPIC on EOI for level-triggered interrupts. Clears remote IRR and re-fires the entry if the line is still asserted.
- Internal (non-pub): `deliverInterrupt` reads the vector and delivery mode from the entry. Fixed/lowest-priority/ExtINT all just call `lapic.injectExternal`. SMI/NMI/INIT are stubbed.

### MMIO Instruction Decoder

Defined in `kernel/arch/x64/mmio_decode.zig`. Shared by VM LAPIC/IOAPIC handlers and virtual BAR emulation.

Supported instruction patterns (the ones Linux's `readl`/`writel` and friends compile to):
- `0x89` MOV r/m32, r32
- `0x8B` MOV r32, r/m32
- `0xC7` MOV r/m32, imm32
- `0xC6` MOV r/m8, imm8
- `0x88` MOV r/m8, r8
- `0x8A` MOV r8, r/m8

ModR/M and SIB decoding handles all addressing forms Linux actually emits, including the `mod=00 rm=100 base=101` SIB-with-disp32 form needed for PIE kernels. Operand-size prefix `0x66` and REX prefixes are decoded for register selection and operand width. REX.W (64-bit operand size) on 0x89/0x8B/0xC7 returns `UnsupportedInstruction` — port I/O only supports 1/2/4-byte widths.

`decodeBytes(buf: []const u8) DecodeError!MmioOp` takes a pre-fetched byte slice rather than requiring a `*Vm` pointer. Both the VM path and the virtual BAR path pre-fetch instruction bytes into a local buffer, then call this shared decoder.

Returns a `MmioOp { is_write, size, reg, value, len, is_immediate }`. The caller dispatches to the device, then either calls `writeGpr` for reads or trusts the device to have stored `op.value` for writes, then advances RIP by `op.len`.

GPR read/write is caller-specific because the two register layouts differ structurally. The VM path uses `mmio_decode.writeGpr(*GuestState, reg, value)` and `readGpr(*const GuestState, reg)` which operate on named fields in the flat `GuestState` struct. The virtual BAR path uses `writeContextGpr(*cpu.Context, reg, size, value)` and `readContextGpr(*const cpu.Context, reg)` in `exceptions.zig` which operate on the packed `Registers` struct pushed by the ISR stub, with `rsp` in the iret frame. A shared abstraction is not used because the ISR push order and the GuestState field layout are dictated by different hardware constraints.

Guest virtual → physical translation goes through `guestVirtToPhys`, which walks the guest's CR3 4-level page tables (handling 1 GiB and 2 MiB huge pages) by reading guest physical memory through `Vm.guestPhysToHost`. When CR0.PG is clear (early boot in real/protected mode), guest virt = guest phys directly. The existing `guestVirtToPhys` logic stays in the VM path (it needs `*Vm` for guest page tables), but instruction decoding itself is now arch-generic via `decodeBytes`. The decoder never touches `Vm`'s memory bookkeeping fields directly — `guestPhysToHost`/`readGuestPhysSlice` are the single home for that arithmetic.

### MSR Passthrough

`vm.msrPassthrough(msr_num, allow_read, allow_write)` flips bits in the VMCB MSRPM via `arch.vmMsrPassthrough` so the guest can directly RDMSR/WRMSR a given MSR without an exit. The kernel maintains a hard blocklist of security-critical MSRs (`isSecurityCriticalMsr`) and returns `E_PERM` for any of them — these always trap to the kernel/VMM regardless of what userspace requests:

```
EFER, STAR, LSTAR, CSTAR, SFMASK,
APIC_BASE (0x1B),
KERNEL_GS_BASE,
SYSENTER_CS / SYSENTER_ESP / SYSENTER_EIP
```

### IOAPIC IRQ Syscalls and vCPU Kick

`vm.ioapicAssertIrq(irq)` and `vm.ioapicDeassertIrq(irq)` give userspace device emulators direct access to the kernel IOAPIC. Both syscalls validate that `irq < 24`, call the corresponding `Ioapic` method, and then call `kickRunningVcpus(vm)`.

`kickRunningVcpus` walks `vm.vcpus[0..num_vcpus]` and, for any vCPU in the `running` state that is currently scheduled on a core (`sched.coreRunning(thread)` returns the core ID), calls `arch.triggerSchedulerInterrupt(core_id)`. The IPI forces a `#VMEXIT` so the entry loop runs again, ticks the LAPIC, and notices the new pending vector before re-entering the guest. Without the kick, a guest in a tight HLT-less polling loop would never see the new IRQ until its next timer-induced exit.

### Slab Allocators

Two new slabs added to `kernel/memory/init.zig`, each with dedicated 16 MiB bump allocator backing regions:
- `VmAllocator = SlabAllocator(arch.Vm, false, 0, 64, true)` — Vm structs (dispatched type from arch/x64/kvm/).
- `VCpuAllocator = SlabAllocator(arch.VCpu, false, 0, 64, true)` — VCpu structs (dispatched type from arch/x64/kvm/).

Initialized in `memory.init()` alongside the existing slabs.

### Locking

VmExitBox lock ordering: acquire `exit_box.lock` before `fault_box.lock` if both are ever needed simultaneously. In practice they should never be needed at the same time.

The Vm struct has its own `lock: SpinLock` protecting vCPU list and VM-wide state. Lock ordering: `vm.lock` before `exit_box.lock`.

### Module Root

`kernel/arch/x64/kvm/kvm.zig` exports the kvm submodules: `pub const exit_box`, `exit_handler`, `guest_memory`, `ioapic`, `lapic`, `vcpu`, `vm`. Referenced by `kernel/arch/x64/x64.zig` as `pub const kvm = @import("kvm/kvm.zig")`. KVM is inherently x86-specific (VT-x/AMD-V, VMCB, EPT/NPT, MSR bitmaps), so it lives under `arch/x64/`. Generic kernel code accesses KVM through dispatched functions in `arch/dispatch.zig` (`kvmVmCreate`, `kvmVcpuRun`, etc.) and dispatched types (`arch.Vm`, `arch.VmAllocator`, `arch.VCpuAllocator`). The `syscall/vm.zig` file calls only through dispatch, never into x64 directly.

---

## 20. PMU Internals

Per-thread performance monitoring unit support. The public contract is in spec §2.14 and spec §4.50–§4.54. This section describes how the pieces fit together internally.

### Layering

```
kernel/syscall/pmu.zig      -- generic PMU syscall layer, owns PmuStateAllocator slab
kernel/arch/dispatch.zig    -- PmuState type alias, pmuInit/pmuGetInfo/pmuSave/
                               pmuRestore/pmuStart/pmuRead/pmuReset/pmuStop
kernel/arch/x64/pmu.zig     -- x64 PMU implementation (PmuState, MSR programming,
                               CPUID detection, PMI handler)
kernel/arch/aarch64/pmu.zig -- aarch64 stubs (unimplemented)
```

The generic layer (`kernel/syscall/pmu.zig`) is architecture-agnostic. It validates syscall arguments, enforces the capability model, looks up thread handles, manages `PmuStateAllocator`, and calls into `arch.pmuXxx` for all hardware touching. It never references MSRs, event select registers, or vendor-specific encodings. Adding a new architecture only requires implementing the `arch/<arch>/pmu.zig` module; the generic layer is untouched.

### Module-Level Changes

- **`kernel/zag.zig`** — module root. Re-exports `arch`, `memory`, `proc`, `sched`, `syscall`, `utils`, etc. The syscall dispatch in `kernel/syscall/dispatch.zig` reaches the generic PMU entry points through `zag.syscall.pmu`.
- **`kernel/main.zig`** — calls `arch.pmuInit()` once after `arch.vmInit()` and before `sched.globalInit()`, mirroring the VM init ordering.
- **`kernel/arch/dispatch.zig`** — adds the `PmuState` comptime type alias and the `pmuInit`/`pmuGetInfo`/`pmuSave`/`pmuRestore`/`pmuStart`/`pmuRead`/`pmuReset`/`pmuStop` functions (see §13).
- **`kernel/syscall/dispatch.zig`** — dispatch cases for syscall numbers `pmu_info`, `pmu_start`, `pmu_read`, `pmu_reset`, and `pmu_stop` forward to the corresponding `pmu.sysPmuXxx` entry point in `kernel/syscall/pmu.zig`. No arg validation happens in the dispatch layer; validation lives in the generic layer so all arches share it.
- **`kernel/sched/thread.zig`** — adds the `pmu_state: ?*arch.PmuState = null` field (see §5) and the PMU-free step in `Thread.deinit` (automatic `pmu_stop` on thread exit, §2.14.9).
- **`kernel/sched/scheduler.zig`** — context switch paths (`schedTimerHandler` and IPC `switchToThread`) add the null-guarded `arch.pmuSave` / `arch.pmuRestore` calls around `arch.switchTo` (see §6). All other scheduler logic is unchanged.
- **`kernel/memory/init.zig`** — adds `PmuStateAllocator = SlabAllocator(arch.PmuState, false, 0, 64)` with a dedicated 16 MiB bump region between the VCpu slab region and the heap tree slab region. Initialized in `memory.init()` alongside the other slabs.
- **`kernel/perms/permissions.zig`** — adds `pmu` bit (bit 8) on `ProcessRights` and `pmu` bit (bit 4) on `ThreadHandleRights` (see §4). No other rights types are touched.

### PmuStateAllocator

`PmuStateAllocator = SlabAllocator(arch.PmuState, false, 0, 64)`. One dedicated 16 MiB bump region in the kernel VA layout (§14). Chunk size 64 matches the other slab allocators.

Allocation is lazy: a thread that never calls `pmu_start` never touches the allocator. The first `pmu_start` call in a thread's lifetime calls `PmuStateAllocator.create()`, stores the pointer on `thread.pmu_state`, and programs the hardware via `arch.pmuStart`. `pmu_stop` and `Thread.deinit` call `arch.pmuStop` (which disables counters) and `PmuStateAllocator.destroy(state)`.

Because allocation happens in the syscall path and deallocation happens either in the syscall path or in `Thread.deinit`, the allocator is touched under the process perm lock (for syscall paths) or the thread cleanup path — both serialized against concurrent PMU syscalls on the same thread. No extra PMU-specific locking is needed.

### Arch-Dispatched PmuState Type

`arch.PmuState` is exposed via `kernel/arch/dispatch.zig` as a comptime switch, exactly like `arch.SavedRegs`, `arch.GuestState`, etc.:

```zig
pub const PmuState = switch (builtin.cpu.arch) {
    .x86_64 => x64.PmuState,
    .aarch64 => aarch64.PmuState,
    else => @compileError("unsupported architecture"),
};
```

The generic layer stores only `*arch.PmuState`. It never dereferences the struct or inspects its fields. All reads/writes happen inside `arch.pmuXxx` functions. This keeps x86-specific types (MSR register numbers, event select bitfields, vendor quirks) out of `kernel/syscall/pmu.zig`.

### x64 PmuState and MSR Programming

Defined in `kernel/arch/x64/pmu.zig`. The struct holds one entry per configured counter:

```
x64.PmuState (extern struct) {
    num_counters: u8
    configs:      [MAX_COUNTERS]PmuCounterConfig
    values:       [MAX_COUNTERS]u64   // last-saved counter values
}
```

**Initialization** (`x64.pmuInit`): reads CPUID leaf `0x0A` (Architectural Performance Monitoring). The `EAX` register returns the version ID in bits 0–7, the number of general-purpose counters per logical core in bits 8–15, and the bit width of each counter in bits 16–23. `EBX` bits 0–6 indicate which architectural events are *not* available (a 1 bit means the event is missing). From these the init routine:

1. Rejects `version < 2`. `IA32_PERF_GLOBAL_CTRL`, `_STATUS`, and `_OVF_CTRL` are only guaranteed present on architectural PMU v2+ (Intel SDM Vol 3 §18.2.2); writing them on a v1-only CPU raises `#GP`. Zag therefore requires architectural PMU v2+ on x64 — on v1-only hardware the kernel bails out early with `num_counters = 0`, and the generic syscall layer rejects every `pmu_start`.
2. Caches the GP counter count as `PmuInfo.num_counters`.
3. Walks the `PmuEvent` enum and, for each variant, checks whether the corresponding architectural event is available via the `EBX` inverse bitmap; sets the corresponding bit in `PmuInfo.supported_events`.
4. Sets `PmuInfo.overflow_support = true` if the PMI LVT entry is wired up (it is — see below).
5. Registers `x64.pmuPmiHandler` as the IDT handler for the PMI vector. The LAPIC LVT performance-counter entry is programmed per-core by `pmuPerCoreInit`, not here.

**Per-core init** (`x64.pmuPerCoreInit`): runs on every core (BSP and APs) from `sched.perCoreInit`. If `cached_info.num_counters == 0` it is a no-op. Otherwise it programs the LAPIC LVT performance-counter entry with the PMI vector (fixed delivery, unmasked) so overflows on this core deliver to `pmuPmiHandler`. Without this hook, secondary cores' LVT entries would never be programmed and PMIs there would be masked / misdelivered.

**Event mapping**: each `PmuEvent` variant has a baked-in `(event_select, unit_mask)` pair matching the architectural events defined in Intel SDM Vol 3 Ch 18 and AMD APM Vol 2 Ch 13. For example, `PmuEvent.cycles` → `(0x3C, 0x00)` (`CPU_CLK_UNHALTED.THREAD`), `PmuEvent.instructions` → `(0xC0, 0x00)` (`INST_RETIRED.ANY_P`), etc. The mapping table lives in `arch/x64/pmu.zig` and is *not* visible to any other kernel file.

**MSRs used**:
- `IA32_PERFEVTSELx` (`0x186 + x`) — per-counter event select register: event number, unit mask, `USR`/`OS` bits, `EN` bit, `INT` bit (enables PMI on overflow).
- `IA32_PMCx` (`0xC1 + x`) — per-counter value register.
- `IA32_PERF_GLOBAL_CTRL` (`0x38F`) — global enable bitmask.
- `IA32_PERF_GLOBAL_STATUS` (`0x38E`) — overflow status bits used by the PMI handler to identify which counter overflowed.
- `IA32_PERF_GLOBAL_OVF_CTRL` (`0x390`) — write-1-to-clear register for the global status bits.

**`pmuStart(state, configs)`**: zero `IA32_PERF_GLOBAL_CTRL`, copy `configs` into `state.configs`, for each config write the mapped `(event_select, unit_mask, USR, EN, INT_if_overflow_threshold_set)` into `IA32_PERFEVTSELx`, preload `IA32_PMCx` with `(counter_max - overflow_threshold)` so the counter overflows exactly at the threshold (or zero if no threshold), then write the enable bitmask into `IA32_PERF_GLOBAL_CTRL`.

**`pmuSave(state)`**: write `0` to `IA32_PERF_GLOBAL_CTRL` (disable all), then for each configured counter read `IA32_PMCx` and store into `state.values[i]`.

**`pmuRestore(state)`**: for each configured counter write `state.values[i]` back into `IA32_PMCx`, re-write `IA32_PERFEVTSELx` (event select is not changed by save/restore, but rewriting is idempotent and cheap), then write the enable bitmask into `IA32_PERF_GLOBAL_CTRL`.

**`pmuRead(state, sample)`**: `pmu_read` is only legal on a thread that is `.faulted` or `.suspended` (§2.14.11), which means the outgoing save has already run and pushed hardware values into `state.values`. `pmuRead` simply copies `state.values[0..state.num_counters]` into `sample.counters` and zero-fills the remainder; `sample.timestamp` is filled in by the generic layer via `arch.getMonotonicClock().now()`.

**`pmuReset(state, configs)`**: same as `pmuStart` but assumes `state` is already allocated; overwrites the configs and preload values, clears any stale overflow status bits in `IA32_PERF_GLOBAL_STATUS` via `IA32_PERF_GLOBAL_OVF_CTRL`, and re-enables.

**`pmuStop(state)`**: zero `IA32_PERF_GLOBAL_CTRL`, zero each `IA32_PERFEVTSELx` for configured counters (so leftover state cannot re-enable), clear overflow status bits, return `state` to `PmuStateAllocator`.

### PMI Handler Flow

`x64.pmuPmiHandler` runs from the IDT vector wired up by `pmuInit`. PMIs are level-triggered via the LAPIC LVT performance-counter entry. The handler's job is to convert a counter overflow into a fault delivered through the existing fault path. It runs in the context of the thread whose counter overflowed (PMIs are per-core interrupts delivered to the core where the overflow happened, which is always the same core the thread is running on at that instant).

```
pmuPmiHandler(frame):
    1. Read IA32_PERF_GLOBAL_STATUS; the set bits identify which counters overflowed.
       Write those bits to IA32_PERF_GLOBAL_OVF_CTRL to clear them.
    2. Write 0 to IA32_PERF_GLOBAL_CTRL to stop all counters on this core immediately.
       (This prevents another PMI from firing while we're delivering the fault.)
    3. Read the current thread from per-core state. If thread.pmu_state == null
       (race: pmu_stop completed between overflow and PMI), return to the
       interrupted context with counters disabled — no fault delivered.
    4. Save the overflowed counter values into state.values (same as pmuSave).
    5. Call proc.faultBlock(thread, .pmu_overflow, rip_at_pmi, rip_at_pmi).
       The existing fault delivery path (§18) handles single-thread-self-handler
       kill (§2.12.7), external-handler stop-all, and enqueue into the handler's
       fault_box. FaultMessage.fault_addr and FaultMessage.regs.rip are both
       the instruction pointer at the time of overflow — this is the sample.
    6. If faultBlock returned false (no surviving handler), kill the process
       and halt this core in a `sti; hlt` loop. The handler must NOT return
       from this path — returning would iret back to the killed thread's user
       RIP. Same pattern as exceptionHandler's unhandled-user-fault path.
    7. If faultBlock returned true, yield into the scheduler. The thread is now
       in .faulted state; the PMI handler does not return to the interrupted RIP.

The PMI vector is registered as `.external` in `pmuInit`, so
`dispatchInterrupt` issues the LAPIC EOI after the handler returns. The
handler itself must not EOI — doing so would pop an extra ISR bit and
could mis-acknowledge an unrelated lower-priority pending interrupt.
```

The PMI handler does not program new counters; that is the profiler's job via `pmu_reset`. When the profiler eventually calls `fault_reply` with `FAULT_RESUME`, the scheduler resumes the thread via the normal context switch path, which calls `arch.pmuRestore` and re-enables the (now reprogrammed) counters. No special "resume from PMI" path is needed.

### Generic Syscall Layer

`kernel/syscall/pmu.zig` implements `sysPmuInfo`, `sysPmuStart`, `sysPmuRead`, `sysPmuReset`, and `sysPmuStop`. Each follows the same shape:

1. Look up the target thread via `getPermByHandle` on the calling process's perm table. Validate that the entry is a thread-type entry.
2. Check `ProcessRights.pmu` on slot 0 of the calling process, then check `ThreadHandleRights.pmu` on the thread entry. `E_PERM` if either is missing. (`sysPmuInfo` skips both checks — see spec §2.14.1 and §4.50.2.)
3. Validate state constraints: `.faulted`/`.suspended` for `sysPmuRead`, `.faulted` for `sysPmuReset`, any-state-except-exited for `sysPmuStop`.
4. Validate the userspace buffer pointer via the standard `validateUserReadable` / `validateUserWritable` helpers.
5. Validate the config array against the cached `PmuInfo` (`count > 0`, `count <= num_counters`, every event bit set in `supported_events`, overflow thresholds only if `overflow_support`). Return `E_INVAL` on any failure.
6. For `sysPmuStart`: if `thread.pmu_state == null`, allocate from `PmuStateAllocator`. `E_NOMEM` on allocation failure. If `target == scheduler.currentThread()`, call `arch.pmuStart(state, configs)`; otherwise call `arch.pmuConfigureState(state, configs)` (stamp only, no MSR writes — see "Locking and Cross-Core Constraints" below).
7. For `sysPmuRead`: call `arch.pmuRead(state, sample)` and fill `sample.timestamp` from `arch.getMonotonicClock().now()`.
8. For `sysPmuReset`: same self/remote branch as `sysPmuStart` — `arch.pmuReset` on self, `arch.pmuConfigureState` on remote.
9. For `sysPmuStop`: on self call `arch.pmuStop(state)`, on remote call `arch.pmuClearState(state)`. In both cases clear `thread.pmu_state = null` and free to allocator.

All buffer writes into the caller's address space go through physmap. No direct user-pointer dereference in kernel mode, matching the existing convention.

### aarch64 Stub Policy

`kernel/arch/aarch64/pmu.zig` defines `PmuState` as an empty `extern struct {}`, `pmuInit` as a no-op, and `pmuGetInfo` as returning `PmuInfo{ .num_counters = 0, .supported_events = 0, .overflow_support = false }`. The other functions (`pmuSave`, `pmuRestore`, `pmuStart`, `pmuRead`, `pmuReset`, `pmuStop`) are `unreachable`: with `num_counters = 0`, the generic syscall layer rejects every `pmu_start` call at the validation step, so the allocation path and all arch hardware entry points are statically unreachable. The stubs exist so `kernel/arch/dispatch.zig` comptime switches compile on aarch64 and so the PMU syscalls return `E_INVAL` cleanly instead of `@compileError`-ing the build.

When aarch64 PMU support is actually implemented (ARMv8-A has its own performance monitor architecture — `PMCR_EL0`, `PMEVCNTRn_EL0`, `PMEVTYPERn_EL0`, per-CPU counter overflow interrupt), it will replace the stubs in-place and the generic layer will need no changes.

### Locking and Cross-Core Constraints

PMU syscalls that take a thread handle always operate on a thread owned by a process whose perm table is locked while the thread is being accessed (the same lock discipline as `thread_suspend` / `thread_resume`). Because `pmu_read` is restricted to `.faulted` / `.suspended` threads (§2.14.11), the kernel never needs to interrupt a running remote core to read counters.

`pmu_start`, `pmu_reset`, and `pmu_stop` all branch on `target_thread == scheduler.currentThread()`:

- **Self path** (target is the caller): the hardware is on this exact core. Call the full `arch.pmuStart` / `pmuReset` / `pmuStop`, which writes MSRs in place.
- **Remote path** (target is a different thread): the target is required by the generic layer to be `.faulted` or `.suspended` before any stamping happens — `pmu_start` / `pmu_stop` return `E_BUSY` (spec §4.51.11 / §4.54.7) and `pmu_reset` returns `E_INVAL` (spec §4.53.5, .faulted-only) otherwise. This is enforced *before* touching `state`, so stamping can never race `pmuSave` / `pmuRestore` on the target's core. The generic layer then calls `arch.pmuConfigureState` / `arch.pmuClearState` — these stamp `state.configs` / `state.values` without touching any MSRs. The next `pmuRestore` (when the target is next scheduled onto a core) programs hardware fresh from the stamped state. No cross-core IPI is needed.

Writing MSRs on the caller's core for a remote target would be doubly wrong: it would clobber the PMU state of whatever thread is currently running on the caller's core, and it would do nothing to the target's future core.

`Thread.deinit` runs on the teardown path (timer handler deferred cleanup, etc.) and the thread being freed is by construction not running on any core. It always goes through `arch.pmuClearState` + slab destroy — never touches MSRs. Real hardware teardown for the dying thread happened at its last `pmuSave` on context switch away.

Overflow races: if a PMI fires on core A while the generic layer is mid-`pmu_stop` on core B against a remote target, the PMI handler's `thread.pmu_state == null` check falls through cleanly. The remote `pmu_stop` never touches hardware on core A, so there is no cross-core serialization window to reason about.

---

## 21. System Info Internals

Per-process read access to system-wide and per-core hardware and scheduler state. The public contract is in spec §2.15 and spec §4.55. This section describes how the pieces fit together internally.

### Layering

```
kernel/arch/dispatch.zig    -- generic sysinfo interface, comptime dispatch on arch
kernel/arch/x64/sysinfo.zig -- x64 hardware reads (new file)
kernel/arch/aarch64/sysinfo.zig -- aarch64 stubs (new file)
```

The generic layer follows the same split as PMU and VM: architecture-independent scheduler accounting, buffer validation, and the observable `SysInfo`/`CoreInfo` extern types live in `kernel/syscall/sysinfo.zig`, and all hardware-specific reads go through the `arch.getCoreFreq` / `arch.getCoreTemp` / `arch.getCoreState` dispatch functions in `kernel/arch/dispatch.zig` (§13). The generic layer never references MSRs, port I/O, or any vendor-specific encoding.

### Module-Level Changes

- **`kernel/arch/dispatch.zig`** — adds `getCoreFreq(core_id: u64) u64`, `getCoreTemp(core_id: u64) u32`, and `getCoreState(core_id: u64) u8` dispatch functions, each comptime-switched on `builtin.cpu.arch`.
- **`kernel/syscall/dispatch.zig`** — dispatch case for the `sys_info` syscall number forwards directly to `kernel/syscall/sysinfo.zig::sysSysInfo`.
- **`kernel/syscall/sysinfo.zig`** — owns the observable `SysInfo` / `CoreInfo` extern types, the `sysSysInfo` entry point, the user-pointer validation/write helpers (a local copy of the same `validateUserWritable` / `writeUser` helpers used by the PMU module — duplicated to keep sysinfo free of any cross-dependency on PMU — plus a `probeUserWritable` helper that walks a range via `demandPage` + `resolveVaddr` without writing, used to reject partition-contained-but-unmapped `cores_ptr` addresses before any state is committed), the per-core read-and-reset of the scheduler accounting fields, and the physmap writes that stamp the result into the caller's address space.
- **`kernel/sched/scheduler.zig`** — adds `idle_ns`, `busy_ns`, and `last_tick_ns` to `PerCoreState` (see §6) and the accounting hook at the top of `schedTimerHandler` (see §6). `last_tick_ns` is seeded in `sched.perCoreInit` after the monotonic clock is available and before the preemption timer is armed.
- **`kernel/memory/pmm.zig`** — adds `freePageCount() u64` and `totalPageCount() u64` (see §14). Both read PMM and buddy-allocator state under `pmm.lock`.

### sys_info Handler

The handler runs entirely in `kernel/syscall/sysinfo.zig::sysSysInfo` (the syscall dispatch layer just forwards to it). The flow must satisfy two independent §4.55 invariants:

  * **§4.55.5** — a bad `cores_ptr` returns `E_BADADDR` without leaving a partial write in `info_ptr`.
  * **§4.55.6** — if the `info_ptr` write itself fails after up-front validation (a late page-out race), the per-core `idle_ns` / `busy_ns` accounting must not have been consumed.

To satisfy both, the handler uses a probe-before-write ordering:

1. Read `arch.coreCount()` into a local `core_count`, `pmm.totalPageCount()` into `mem_total`, and `pmm.freePageCount()` into `mem_free`. These populate the `SysInfo` struct that will be written to `info_ptr`.
2. If `cores_ptr` is null: write the assembled `SysInfo` into `info_ptr` via physmap and return `E_OK`. No per-core accounting is touched and no counters are reset. (This is the §4.55.4 short-circuit path — nothing below this point executes.)
3. Otherwise, symbolically validate `cores_ptr` as a writable region of `core_count * sizeof(CoreInfo)` bytes via the local `validateUserWritable` helper. Return `E_BADADDR` on partition-boundary / wraparound / null rejection.
4. Symbolically validate `info_ptr` as a writable region of `sizeof(SysInfo)` bytes via the same helper. Return `E_BADADDR` on failure.
5. **Probe** the `cores_ptr` range with `probeUserWritable` — this walks every page of the range via `proc.vmm.demandPage` and `arch.resolveVaddr` without writing. The symbolic validator in step 3 is a purely range-based check; a partition-contained but unmapped pointer (e.g. `0x1`) slips through it and would otherwise only fail at the final `writeUser(cores_ptr)`, after `info_ptr` had already been committed — violating §4.55.5. The probe forces the fault-or-fail decision up front. Returns `E_BADADDR` on any page-walk failure.
6. Write `SysInfo` into `info_ptr` via physmap. A late page-out race between step 4 and this write still fails cleanly here because we haven't touched accounting yet — §4.55.6 is preserved.
7. For each core `i` in `[0, core_count)`:
   - Acquire that core's `rq_lock`, `@atomicRmw(.Xchg, .monotonic)` both `idle_ns` and `busy_ns` to zero, release `rq_lock`. Each counter is independently atomic with the scheduler tick hook's `@atomicRmw(.Add, .monotonic)`; see §6 for the per-counter coherence story.
   - Call `arch.getCoreFreq(i)`, `arch.getCoreTemp(i)`, and `arch.getCoreState(i)` to populate the hardware fields.
   - Stamp the `CoreInfo` entry for slot `i` in a local stack buffer sized by `MAX_CORES = 64` (spec §5 "Max SysInfo.core_count").
8. Write the `CoreInfo` array into the caller's address space via physmap. After step 5's probe the pages are guaranteed-faulted-in, so this write is essentially infallible — only a concurrent unmap can still fail it, in which case the accounting window has already been consumed (the caller did receive `SysInfo`, and step 7 has already committed the reset). This is the one remaining "accounting loss on late failure" corner the doc comment on `sysSysInfo` explicitly acknowledges.

The read-and-reset at step 7 is the only place the handler holds `rq_lock`, and it's held for at most two atomic exchanges per core. Scheduler ticks are 2 ms apart (§6, `SCHED_TIMESLICE_NS`), so the lock-hold time on either side is a couple of cache-line updates.

### x64 Hardware Reads

Defined in `kernel/arch/x64/sysinfo.zig`. Each function issues a single MSR read or a short sequence of MSR reads against the target core's PMU/thermal interface. The Intel SDM references cited below are the load-bearing primary source for the encodings.

All three MSR reads are gated behind an `intel_msrs_available` flag that is latched on the bootstrap core in `sysInfoInit` based on a CPUID leaf 0 `GenuineIntel` vendor-string check. On non-Intel vendors (AMD, etc.) the flag stays false and the arch-specific reads short-circuit with the zero-initialised cache, so `getCoreFreq` / `getCoreTemp` / `getCoreState` all return `0` — matching the aarch64 stub behaviour below. A non-Intel kernel therefore reports "unavailable" for the hardware triple without raising `#GP`.

**`getCoreFreq(core_id)`** reads the core's current operating frequency via `IA32_PERF_STATUS` (MSR `0x198`). The current performance state is encoded in the low 16 bits; the relevant frequency ratio is in bits 8–15 of the low dword. The returned hertz value is computed as `(ratio * base_bus_freq_hz)`, where the base bus frequency is the fixed platform bus clock (typically 100 MHz on modern Intel parts, discovered at boot via `CPUID.16h` when available; otherwise the `DEFAULT_BUS_FREQ_HZ = 100 MHz` fallback is used). See Intel SDM Vol 4 "Model-Specific Registers" table entry for `IA32_PERF_STATUS` and Vol 3 §15 "Power and Thermal Management".

**`getCoreTemp(core_id)`** reads the core's current temperature via `IA32_THERM_STATUS` (MSR `0x19C`). The raw register encodes temperature as an *offset below* the thermal junction maximum (TjMax), not an absolute reading. Bit 31 indicates valid reading; bits 22–16 are the "digital readout" which is the number of degrees below TjMax. TjMax is discovered once at boot by reading `MSR_TEMPERATURE_TARGET` (`0x1A2`) bits 23–16. The returned milli-celsius value is computed as `(tjmax_c - offset_c) * 1000`, with `tjmax_c` cached per core since it does not change at runtime. See Intel SDM Vol 4 entries for `IA32_THERM_STATUS` and `MSR_TEMPERATURE_TARGET`, and Intel SDM Vol 3 §15.8 "Platform Specific Power Management Support".

**`getCoreState(core_id)`** currently always returns `0` (active). §2.15.6 permits this — the spec tag says "0 means active, non-zero means idle at some package-default depth" but does not require any particular non-zero value to be reachable. Finer-grained per-core C-state accounting via `MSR_CORE_C1_RES` / `MSR_CORE_C3_RES` / `MSR_CORE_C6_RES` / `MSR_CORE_C7_RES` is reserved for a future iteration; the scheduler already knows whether a core is currently running the idle thread, so wiring up a simple active/idle signal is a small follow-up. See Intel SDM Vol 3 §15.5 "Thread and Core C-States".

**Remote core reads (and the cache).** `IA32_PERF_STATUS`, `IA32_THERM_STATUS`, and friends are core-local MSRs — the `rdmsr` instruction always reads the issuing core's own register, so reading a remote core's values would normally require either a cross-core IPI or running the read on that core during its next scheduler tick. The current x64 implementation uses the tick-sampled approach and exposes it **uniformly** for local AND remote reads:

  * A file-scoped array `var core_cache: [MAX_CORES]CoreCache align(64)` in `kernel/arch/x64/sysinfo.zig` holds one `{freq_hz, temp_mc, c_state, tjmax_c}` slot per core. Each slot is written by exactly one core (its owner) and read by any core.
  * On every scheduler tick, `schedTimerHandler` calls `arch.sampleCoreHwState()` AFTER it has updated `state.last_tick_ns` and the `idle_ns` / `busy_ns` counters. `sampleCoreHwState` issues the three MSR reads against the running (owner) core and stores the values into its own `core_cache[coreID()]` slot via `@atomicStore(..., .monotonic)`.
  * `getCoreFreq` / `getCoreTemp` / `getCoreState` read from `core_cache[core_id]` via `@atomicLoad(..., .monotonic)` — they never issue an MSR themselves, and make no local-vs-remote distinction. Even a call for the current core's own ID goes through the cache, not a direct `rdmsr`.

This keeps `sys_info` cheap (no cross-core IPIs, no MSR reads on the hot path — just an atomic load per field) at the cost of up-to-2 ms staleness on frequency/temperature readings, which is acceptable for UI-grade polling. The atomic stores on the writer side and atomic loads on the reader side prevent torn u64/u32 reads across cores, but there is no ordering relationship between freq/temp/c_state within a slot — a reader can see a fresh `freq_hz` alongside a stale `temp_mc`, and the implementation explicitly documents this as acceptable.

### aarch64 Stubs

`kernel/arch/aarch64/sysinfo.zig` defines `getCoreFreq`, `getCoreTemp`, and `getCoreState` as stubs returning `0` for all values. The aarch64 port does not yet implement performance-counter or thermal MSR equivalents (ARMv8-A exposes frequency via `CNTFRQ_EL0` and thermal via platform-specific sideband, neither of which is wired up). The stubs exist so `kernel/arch/dispatch.zig` comptime switches compile on aarch64 and so `sys_info` returns a syntactically valid `CoreInfo` array (all hardware fields zero) rather than `@compileError`-ing the build. Scheduler accounting still works unchanged — `idle_ns` and `busy_ns` are produced by architecture-independent code.

When aarch64 sysinfo support is implemented, it will replace the stubs in-place and the generic layer will need no changes.

### Locking

No new locks. `sys_info` takes each core's existing `rq_lock` in turn for the read-and-reset of the accounting fields; it never holds more than one `rq_lock` at a time, so deadlock is not a concern even if two callers sweep cores in opposite orders. The accounting fields themselves are updated lock-free from the scheduler tick hook via `@atomicRmw(.Add, .monotonic)` (see §6 "Idle/Busy Accounting Hook" for the per-counter coherence story).

The PMM lock is taken by `pmm.freePageCount()` for its global free-list query, but the per-core PMM caches (`count`) are read on the alloc/free fast path without `pmm.lock` and without IRQ-disabling on the owning core. As a result the `mem_free` value reported by `sys_info` may be off by a few pages per core. This is acceptable for UI-grade reporting — the userspace consumer is a periodic dashboard sampler, not a transactional accounting system.

The arch dispatch functions run without holding any kernel lock; the x64 implementation's remote-core cache is updated by the owning core's scheduler tick hook via lock-free atomic stores, and read by any core via lock-free atomic loads.

---

## 22. Wall Clock Time Internals

Wall clock time as an offset from the monotonic clock. The public contract is in spec §2.16 and spec §4.56--§4.57. This section describes how the pieces fit together internally.

### Layering

```
kernel/arch/x64/rtc.zig        -- CMOS RTC hardware read, BCD-to-Unix conversion
kernel/arch/dispatch.zig        -- readRtc() dispatch function
kernel/syscall/clock.zig        -- clock_gettime / clock_getwall / clock_setwall handlers, wall_offset state
kernel/syscall/dispatch.zig     -- dispatch cases
```

The wall clock handlers live in `kernel/syscall/clock.zig` alongside the `wall_offset` global. All hardware access is confined to `arch/x64/rtc.zig`.

### Boot Sequence

During `kMain`, after `arch.init()` and before `sched.globalInit()`:

1. `arch.readRtc()` reads the CMOS RTC registers and returns Unix nanoseconds.
2. The kernel computes `wall_offset = rtc_nanos - monotonic_now`, where `monotonic_now` comes from `arch.getMonotonicClock().now()`.
3. `wall_offset` is stored in a global `i64` variable (`var wall_offset: i64`), accessed atomically.

The RTC is read exactly once. All subsequent wall clock queries derive from the monotonic clock plus the offset.

### Global State

```
var wall_offset: i64    -- atomic, initialized at boot from RTC
```

Accessed via `@atomicLoad(.monotonic)` for reads and `@atomicStore(.monotonic)` for writes. No lock is needed — single-word atomic operations on `i64` are sufficient for the offset update to be tear-free.

### clock_getwall Handler

In `kernel/syscall/clock.zig`:

```
monotonic_now = arch.getMonotonicClock().now()
offset = @atomicLoad(&wall_offset, .monotonic)
return @as(i64, monotonic_now) +% offset
```

No rights check. Always succeeds. The wrapping add (`+%`) handles the signed/unsigned boundary correctly.

### clock_setwall Handler

In `kernel/syscall/clock.zig`:

```
1. Check ProcessRights.set_time on slot 0. Return E_PERM if absent.
2. new_offset = @as(i64, requested_nanos) -% @as(i64, arch.getMonotonicClock().now())
3. @atomicStore(&wall_offset, new_offset, .monotonic)
4. Return E_OK.
```

The offset recomputation is atomic in the sense that concurrent `clock_getwall` calls see either the old or the new offset, never a torn value (single-word atomic store).

### Arch Layer: readRtc

**`arch/dispatch.zig`** adds:

```
pub fn readRtc() u64 {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.rtc.readRtc(),
        .aarch64 => return 0,
        else => unreachable,
    }
}
```

The aarch64 stub returns 0. On aarch64, the wall clock offset starts at `-(monotonic_now)`, meaning `clock_getwall` returns approximately 0 (the Unix epoch) until userspace calls `clock_setwall` with a real time. This is the correct fallback — a system with no RTC has no wall clock until one is set.

### x64 RTC Read

Defined in `kernel/arch/x64/rtc.zig`. Reads the MC146818-compatible CMOS real-time clock via I/O ports `0x70` (address) and `0x71` (data).

**Register map** (CMOS RAM offsets):

| Offset | Field |
|--------|-------|
| 0x00 | Seconds |
| 0x02 | Minutes |
| 0x04 | Hours |
| 0x07 | Day of month |
| 0x08 | Month |
| 0x09 | Year |
| 0x0A | Status Register A (bit 7 = update-in-progress) |
| 0x0B | Status Register B (bit 1 = 24h mode, bit 2 = binary mode) |
| 0x32 | Century (if available) |

**Read procedure**:

1. Spin until Status Register A bit 7 (UIP) is clear — the RTC is not mid-update.
2. Read seconds, minutes, hours, day, month, year, century.
3. Re-read all fields and compare; if any differ, loop back to step 1 (update race).
4. Check Status Register B bit 2: if clear, values are BCD-encoded — convert each field from BCD to binary via `(val & 0x0F) + ((val >> 4) * 10)`.
5. Check Status Register B bit 1: if clear, hours are in 12-hour format — convert PM hours (bit 7 set) to 24-hour.
6. Compose the full year: `century * 100 + year`. If century register reads 0 (not available), assume century = 20.
7. Convert the calendar date/time to Unix nanoseconds using a standard days-since-epoch calculation (accounting for leap years).

The function returns `u64` nanoseconds since 1970-01-01T00:00:00Z. Precision is 1 second (the RTC has no sub-second granularity). The monotonic clock provides sub-nanosecond precision for all subsequent queries.

### Module-Level Changes

- **`kernel/arch/dispatch.zig`** — adds `readRtc() u64` dispatch function.
- **`kernel/main.zig`** — calls `arch.readRtc()` during boot to initialize `wall_offset`. Placed after `arch.init()` (needs port I/O) and after `arch.getMonotonicClock()` is available (needs TSC/HPET).
- **`kernel/syscall/clock.zig`** — implements `clock_gettime`, `clock_getwall`, and `clock_setwall` handlers and owns the `wall_offset` global state.
- **`kernel/perms/permissions.zig`** — adds `set_time` bit (bit 9) on `ProcessRights`. Root service slot 0 is initialized with this bit set.

---

## 23. Randomness Internals

Hardware-sourced random bytes for userspace. The public contract is in spec §2.17 and spec §4.58. This section describes how the pieces fit together internally.

### Layering

```
kernel/arch/x64/cpu.zig         -- getRandom() via RDRAND
kernel/arch/dispatch.zig        -- getRandom() dispatch function
kernel/syscall/system.zig       -- getrandom handler
kernel/syscall/dispatch.zig     -- dispatch case
```

The `getrandom` handler lives in `kernel/syscall/system.zig` alongside other simple system syscalls.

### Arch Layer: getRandom

**`arch/dispatch.zig`** adds:

```
pub fn getRandom() ?u64 {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.cpu.getRandom(),
        .aarch64 => return null,
        else => unreachable,
    }
}
```

The aarch64 stub returns `null`, causing `getrandom` to return `E_NODEV` (no hardware RNG).

### x64 RDRAND

Defined in `kernel/arch/x64/cpu.zig`. The `getRandom()` function uses the `RDRAND` instruction to obtain a 64-bit random value from the on-chip Digital Random Number Generator (DRNG).

```
pub fn rdrand() ?u64 {
    var value: u64 = 0;
    var success: u8 = 0;
    asm volatile (
        \\rdrand %[val]
        \\setc %[ok]
        : [val] "=r" (value),
          [ok] "=r" (success),
    );
    return if (success != 0) value else null;
}
```

RDRAND sets the carry flag (CF=1) on success and clears it (CF=0) when the hardware entropy source is temporarily exhausted. The inline assembly uses `setc` to capture CF into a general-purpose register. Returning `null` on failure maps to `E_AGAIN` in the syscall handler.

RDRAND availability is determined by CPUID leaf 1, ECX bit 30. If unavailable on the host CPU, the function returns `null` unconditionally. The CPUID check can be done once at boot and cached, but the current implementation checks RDRAND availability implicitly: if the instruction is not supported, the `#UD` exception handler would fire. In practice, all x86_64 CPUs that Zag targets (Ivy Bridge and later) support RDRAND.

**E_NODEV limitation:** The current implementation cannot distinguish "hardware RNG temporarily exhausted" (E_AGAIN) from "no hardware RNG at all" (E_NODEV). On architectures without RDRAND, `getRandom()` returns null, and the handler returns E_AGAIN. A future enhancement could check CPUID for RDRAND support at boot and return E_NODEV if absent.

### getrandom Handler

In `kernel/syscall/system.zig`:

```
1. Validate len: if len == 0 or len > 4096, return E_INVAL.
2. Validate buf_ptr: validateUserWritable(buf_ptr, len). Return E_BADADDR on failure.
3. Loop: fill the buffer 8 bytes at a time via arch.getRandom().
   - If getRandom() returns null on the first attempt, return E_AGAIN.
   - For each successful 8-byte read, write to the user buffer via physmap.
   - Handle the final partial chunk (if len is not a multiple of 8) by reading
     one more u64 and copying only the needed bytes.
4. Return E_OK.
```

The buffer is written through physmap (resolve user VA to PA, convert PA to physmap VA, memcpy). This follows the same convention as `sys_info` and PMU buffer writes — no direct user-pointer dereference in kernel mode.

The maximum of 4096 bytes per call means at most 512 RDRAND invocations. RDRAND throughput on modern x86 is approximately 500 MB/s, so a full 4096-byte fill takes roughly 8 microseconds — well within syscall latency expectations.

### Module-Level Changes

- **`kernel/arch/x64/cpu.zig`** — adds `getRandom() ?u64` using RDRAND.
- **`kernel/arch/dispatch.zig`** — adds `getRandom() ?u64` dispatch function.
- **`kernel/syscall/system.zig`** — implements the `getrandom` handler.

---

## 24. IRQ Notification Delivery Internals

Asynchronous kernel-to-userspace IRQ notification via a per-process bitmask. The public contract is in spec §2.18 and spec §4.59--§4.60. This section describes how the pieces fit together internally.

### Layering

```
kernel/sched/notification.zig   -- NotificationBox struct and methods
kernel/arch/x64/irq.zig         -- IRQ masking/unmasking, irq_table
kernel/arch/dispatch.zig        -- maskIrq/unmaskIrq dispatch functions
kernel/proc/process.zig         -- notification_box field on Process
kernel/perms/permissions.zig    -- badge_bit on PermissionEntry, badge_counter on Process
kernel/syscall/system.zig       -- notify_wait handler
kernel/syscall/device.zig       -- irq_ack handler
kernel/syscall/dispatch.zig     -- dispatch cases
```

### NotificationBox Struct

Defined in `kernel/sched/notification.zig`:

```
NotificationBox {
    word:    atomic(u64)     -- accumulated notification bitmask
    waiters: PriorityQueue   -- threads blocked on notify_wait
    lock:    SpinLock
}
```

Added to `Process` alongside `msg_box` and `fault_box`:

```
notification_box: NotificationBox = .{
    .word = @as(atomic(u64), 0),
    .waiters = .{},
    .lock = .{},
}
```

The `word` field accumulates IRQ notifications via atomic OR. The `waiters` priority queue holds threads blocked on `notify_wait`. The `lock` protects the queue and the read-and-clear operation on `word`.

### Badge Bit Assignment

Each `Process` has a `badge_counter: u6` field, initialized to 0. When a device region handle is inserted into the process's permissions table (via `insertPerm` for device_region entries), the current `badge_counter` value is assigned as the badge bit for that entry, and the counter is incremented mod 64.

The badge bit is stored on the `PermissionEntry` struct. For device_region entries, it is exposed in the dedicated `badge_byte` field of `UserViewEntry` (offset 9, the byte after `entry_type`) so userspace can map notification bits to device handles without a syscall (spec §2.18.3). The `field0` encoding is unchanged and carries only device type, class, and size:

```
UserViewEntry layout (device_region):
  handle:     u64  (offset 0)
  entry_type: u8   (offset 8)  — ENTRY_TYPE_DEVICE_REGION (3)
  badge_byte: u8   (offset 9)  — badge_bit (u6, 0-63)
  rights:     u16  (offset 10)
  _pad:       [4]u8
  field0:     u64  (offset 16) — device_type[0:7], device_class[8:15], size_or_port_count[32:55]
  field1:     u64  (offset 24) — PCI topology
```

### NotificationBox Methods

**`signal(box: *NotificationBox, badge_bit: u6)`** — Called from the IRQ handler path. Atomically ORs `(1 << badge_bit)` into `box.word` via `@atomicRmw(.Or, .monotonic)`. Then acquires `box.lock`, drains all waiters from the priority queue, and wakes each one (spin on `on_cpu`, set `.ready`, enqueue on target core). Releases `box.lock`.

The `@atomicRmw(.Or)` is lock-free; the lock is only held for the waiter drain. This means multiple IRQs from different devices can accumulate concurrently without contention on the signal path — only the waiter wake needs serialization.

**`wait(box: *NotificationBox, thread: *Thread, timeout_ns: u64) -> i64`** — Called from the `notify_wait` syscall handler.

```
1. Acquire box.lock.
2. Read word = @atomicLoad(&box.word, .monotonic).
3. If word != 0:
   - @atomicStore(&box.word, 0, .monotonic)  // clear
   - Release box.lock.
   - Return @as(i64, word).
4. If timeout_ns == 0:
   - Release box.lock.
   - Return E_AGAIN.
5. Set thread.state = .blocked.
6. Enqueue thread on box.waiters.
7. Release box.lock.
8. Yield to scheduler.
9. On wake: re-read and clear word atomically (same as step 2-3).
   Return the bitmask, or E_TIMEOUT if woken by timeout expiry.
```

The read-and-clear is atomic with respect to concurrent `signal` calls because the lock serializes the "check zero + enqueue" path, and `signal` drains all waiters after the OR. Between the OR and the drain, additional signals may accumulate — this is correct because `notify_wait` returns the full accumulated bitmask.

**`cleanup_on_death(box: *NotificationBox)`** — Called from `cleanupPhase1` when a process dies. Acquires `box.lock`, drains all waiters (waking each with `E_NOENT` in `rax`), clears `word`, releases lock. Prevents dangling thread pointers in the queue.

### Kernel IRQ Handler Path

When a device IRQ fires on x86, the interrupt vector handler in `kernel/arch/x64/irq.zig` executes:

```
1. Identify the IRQ line from the interrupt vector number (vector - IRQ_BASE_VECTOR).
2. Look up irq_table[irq_line]. If null (no registered device), send EOI and return.
3. Mask the IRQ line via I/O APIC redirection table (set the mask bit).
4. Send LAPIC EOI.
5. Look up the owning process: irq_table[irq_line] -> *DeviceRegion -> owner_proc.
6. Look up the badge_bit from the PermissionEntry for this device in the owner's perm table.
7. Call notification_box.signal(badge_bit) on the owner process's notification_box.
```

The IRQ line remains masked until userspace calls `irq_ack`, which unmasks it. This prevents interrupt storms while the driver is processing the previous interrupt.

### IRQ Table

Defined in `kernel/arch/x64/irq.zig`:

```
var irq_table: [256]?*DeviceRegion = [_]?*DeviceRegion{null} ** 256
```

Populated during firmware table parsing (ACPI MADT interrupt source overrides, PCI INTx routing). Each entry maps an IRQ line number to the `DeviceRegion` that owns it. The table is static after boot — entries are not modified at runtime.

### I/O APIC Masking

**`maskIrq(irq: u8)`** — Reads the I/O APIC redirection table entry for `irq`, sets bit 16 (mask bit), writes back. The I/O APIC is accessed via its MMIO registers (IOREGSEL at base+0x00, IOWIN at base+0x10).

**`unmaskIrq(irq: u8)`** — Same read-modify-write, but clears bit 16.

Both operations are protected by the existing I/O APIC lock to prevent concurrent redirection table corruption.

### Arch Dispatch

**`arch/dispatch.zig`** adds:

```
pub fn maskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn unmaskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq),
        .aarch64 => {},
        else => unreachable,
    }
}
```

The aarch64 stubs are no-ops.

### irq_ack Handler

In `kernel/syscall/device.zig`:

```
1. Look up device_handle in caller's perm table. Return E_BADHANDLE if not found or not device_region.
2. Check DeviceRegionRights.irq. Return E_PERM if absent.
3. Look up the device's IRQ line. Return E_INVAL if the device has no associated IRQ.
4. Call arch.unmaskIrq(irq_line).
5. Return E_OK.
```

### Process Struct Additions

```
Process {
    ...
    notification_box: NotificationBox    -- IRQ notification delivery
    badge_counter: u6 = 0               -- monotonic mod-64 counter for badge assignment
    ...
}
```

### Module-Level Changes

- **`kernel/sched/notification.zig`** — new file. `NotificationBox` struct, `signal`, `wait`, `cleanup_on_death`.
- **`kernel/arch/x64/irq.zig`** — adds `maskIrq(u8)`, `unmaskIrq(u8)` via I/O APIC. Adds global `irq_table: [256]?*DeviceRegion` populated during firmware table parsing. Adds the device IRQ dispatch path in the IRQ handler.
- **`kernel/arch/dispatch.zig`** — adds `maskIrq(u8)`, `unmaskIrq(u8)` dispatch functions.
- **`kernel/proc/process.zig`** — adds `notification_box: NotificationBox` and `badge_counter: u6` fields. `cleanupPhase1` calls `notification_box.cleanup_on_death()`.
- **`kernel/perms/permissions.zig`** — adds `irq` bit (bit 3) on `DeviceRegionRights`. `insertPerm` for device_region entries assigns the badge bit from `process.badge_counter` and increments. `UserViewEntry.fromKernelEntry` packs the badge bit into `field0` bits 56--61.
- **`kernel/syscall/system.zig`** — implements the `notify_wait` handler.
- **`kernel/syscall/device.zig`** — implements the `irq_ack` handler.
- **`kernel/devices/registry.zig`** — `grantAllToRootService` grants device handles with rights `0b1111` (map + grant + dma + irq) instead of `0b111`.

### Timeout Integration

`notify_wait` with a finite timeout uses the same timed-waiter mechanism as `futex_wait`: the thread is placed on both the notification box queue and a global timed-waiter slot. The scheduler tick handler checks timed waiters and wakes expired ones with `E_TIMEOUT`. When a notification signal wakes the thread first, the timed-waiter slot is cleared. This reuses the existing futex timeout infrastructure rather than adding a new timer mechanism.

### Locking

The notification box lock ordering is: acquire `notification_box.lock` before `rq_lock` (same as `fault_box.lock`). The `signal` path acquires `notification_box.lock` to drain waiters, then for each waiter acquires the target core's `rq_lock` to enqueue. No other kernel lock is held when `notification_box.lock` is taken.

The IRQ handler path runs with interrupts disabled on the current core (standard x86 interrupt gate behavior). It acquires `notification_box.lock` briefly for the waiter drain. This is safe because `notification_box.lock` is never held with interrupts enabled on the same core that handles IRQs (the `wait` path disables interrupts via `lockIrqSave`).

---

## 25. Power Control Internals

System-wide and per-CPU power management. The public contract is in spec §2.19 and spec §4.61--§4.62. This section describes how the pieces fit together internally.

### Layering

```
kernel/arch/x64/power.zig       -- x64 power state implementations
kernel/arch/dispatch.zig         -- powerAction/cpuPowerAction dispatch functions
kernel/syscall/system.zig        -- sys_power / sys_cpu_power handlers
kernel/syscall/dispatch.zig      -- dispatch cases
```

The power control handlers live in `kernel/syscall/system.zig`. The arch layer does all the real work.

### PowerAction and CpuPowerAction Enums

Defined in `kernel/arch/dispatch.zig`:

```
PowerAction = enum(u8) {
    shutdown = 0,
    reboot = 1,
    sleep = 2,
    hibernate = 3,
    screen_off = 4,
}

CpuPowerAction = enum(u8) {
    set_freq = 0,
    set_idle = 1,
}
```

### sys_power Handler

In `kernel/syscall/system.zig`:

```
1. Check ProcessRights.power on slot 0. Return E_PERM if absent.
2. Decode action from arg register. Return E_INVAL if not a valid PowerAction variant.
3. Call arch.powerAction(action). The arch layer returns E_OK or E_NODEV.
4. For shutdown/reboot: arch.powerAction does not return.
5. For sleep/hibernate/screen_off: return the arch layer's result (E_OK after resume, or E_NODEV).
```

### sys_cpu_power Handler

In `kernel/syscall/system.zig`:

```
1. Check ProcessRights.power on slot 0. Return E_PERM if absent.
2. Decode action from arg register. Return E_INVAL if not a valid CpuPowerAction variant.
3. Decode value from second arg register.
4. Call arch.cpuPowerAction(action, value). Returns E_OK or E_NODEV.
5. Return result.
```

### Arch Dispatch

**`arch/dispatch.zig`** adds:

```
pub fn powerAction(action: PowerAction) noreturn | i64 {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.power.powerAction(action),
        .aarch64 => return E_NODEV,
        else => unreachable,
    }
}

pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.power.cpuPowerAction(action, value),
        .aarch64 => return E_NODEV,
        else => unreachable,
    }
}
```

The aarch64 stubs return `E_NODEV` for all actions.

### x64 Power State Implementations

Defined in `kernel/arch/x64/power.zig`. Each action maps to a specific hardware mechanism:

**`shutdown`** — ACPI S5 (soft-off) sleep state. Writes to the PM1a control register with the SLP_TYP value for S5 and the SLP_EN bit. The PM1a control port and SLP_TYP are discovered during ACPI FADT parsing at boot. Fallback: write `0x2000` to port `0x604` (QEMU-specific shutdown). Does not return.

**`reboot`** — Three fallback strategies:
1. Keyboard controller reset: write `0xFE` to port `0x64`.
2. ACPI reset register: if FADT advertises a reset register, write the reset value to it.
3. Triple fault: load a zero-length IDT and trigger an interrupt.
Does not return.

**`sleep`** (S3 — suspend to RAM) — Saves CPU state (registers, GDT, IDT, CR0/CR3/CR4), writes the S3 SLP_TYP to PM1a control with SLP_EN, CPU halts. On resume, firmware jumps to the FACS waking vector. The kernel restores CPU state, re-enables paging, and returns `E_OK`. Returns `E_NODEV` if ACPI does not advertise S3 support.

**`hibernate`** (S4 — suspend to disk) — Similar to S3 but with S4 SLP_TYP. The actual save-to-disk is a userspace responsibility (the kernel only manages the power state transition). Returns `E_NODEV` if S4 is not supported.

**`screen_off`** — DPMS (Display Power Management Signaling) off via VGA register writes: read port `0x3DA` to reset the attribute controller flip-flop, write `0x00` to port `0x3C0` to blank the display. For modern systems, this may also involve writing to the GPU's power management registers if a display device region is available. Returns `E_OK`.

**`set_freq`** — Per-CPU frequency control via `IA32_PERF_CTL` MSR (`0x199`). The target frequency in hertz is converted to a P-state ratio using the base bus frequency (same as §21's `getCoreFreq`). The ratio is written to bits 8--15 of `IA32_PERF_CTL`. The hardware adjusts to the nearest achievable frequency. Returns `E_NODEV` if P-state control is not supported (checked via CPUID).

**`set_idle`** — Per-CPU maximum C-state level. The value is stored in a per-core variable that the idle loop consults. When the idle thread runs, it uses `MWAIT` with the C-state hint corresponding to the configured maximum level (C-state sub-state encoding per Intel SDM Vol 2 "MWAIT" instruction). If `MWAIT` is not supported (CPUID leaf 5), falls back to `HLT`. Returns `E_NODEV` if `MWAIT` is not supported and value > 0.

### ACPI Table Dependencies

The power subsystem depends on information discovered during `arch.parseFirmwareTables`:

- **FADT (Fixed ACPI Description Table)**: PM1a control block address, PM1a event block address, SLP_TYP values for S3/S4/S5, reset register address and value, FACS physical address.
- **FACS (Firmware ACPI Control Structure)**: waking vector for S3 resume.
- **DSDT/SSDT**: SLP_TYP values are encoded in the `\_S3`, `\_S4`, `\_S5` objects in the DSDT. The kernel extracts these during ACPI parsing.

These values are cached in a global `AcpiPowerInfo` struct populated during `parseFirmwareTables` and consulted by `power.zig` at syscall time.

### Module-Level Changes

- **`kernel/arch/x64/power.zig`** — new file. Implements `powerAction(PowerAction)` and `cpuPowerAction(CpuPowerAction, u64)`.
- **`kernel/arch/dispatch.zig`** — adds `powerAction` and `cpuPowerAction` dispatch functions.
- **`kernel/arch/x64/acpi.zig`** — extracts and caches FADT power management fields (PM1a control port, SLP_TYP values, reset register, FACS waking vector) in a global `AcpiPowerInfo` struct.
- **`kernel/syscall/system.zig`** — implements `sys_power` and `sys_cpu_power` handlers.
- **`kernel/perms/permissions.zig`** — adds `power` bit (bit 10) on `ProcessRights`. Root service slot 0 is initialized with this bit set.
