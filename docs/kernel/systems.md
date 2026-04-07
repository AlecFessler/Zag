# Zag Microkernel -- Systems Design Document

Internal implementation details. This document describes HOW the kernel is built. For the public specification (WHAT the kernel does), see `readme.md`.

---

## 1. Internal Architecture Overview

Zag is implemented in Zig, targeting x86_64 (with an aarch64 stub). The kernel is a single binary loaded by a bootloader that provides a `BootInfo` structure containing the memory map, XSDP physical address, ELF debug blob, and initial stack pointer.

### Boot Sequence

1. `kEntry` -- Bootloader entry point. Switches to the bootloader-provided stack and jumps to `kTrampoline`.
2. `kTrampoline` -- Calls `kMain`, panics on error.
3. `kMain` executes the following in order:
   - `arch.init()` -- IDT, GDT, segment registers, CPU features (bootstrap core only).
   - `memory.init(boot_info.mmap)` -- Physmap setup, buddy allocator init, PMM init, slab allocator init for VMM nodes, tree nodes, SHM objects, device regions, processes, and threads.
   - `memory.initHeap()` -- Kernel heap allocator init.
   - `debug.info.init()` -- ELF symbol table for stack traces.
   - `arch.parseFirmwareTables(xsdp_phys)` -- ACPI parsing: MADT (cores, APIC), HPET, MCFG (PCI ECAM). PCI enumeration and serial port probing. Device registration.
   - `sched.globalInit()` -- Process/thread slab allocators, idle process, run queues, root service creation with all rights, device grant to root service, enqueue root service initial thread.
   - `arch.smpInit()` -- Secondary core bringup via INIT/SIPI IPI sequence with real-mode trampoline at physical address `0x8000`.
   - `sched.perCoreInit()` -- Per-core scheduler state, preemption timer arm, enable interrupts.
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
    dispatch.zig         -- architecture dispatch layer
    interrupts.zig       -- ArchCpuContext type dispatch
    syscall.zig          -- syscall dispatch and validation
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
  memory/
    init.zig             -- memory subsystem initialization
    address.zig          -- VA/PA types, address space layout constants
    pmm.zig              -- physical memory manager with per-core page caches
    buddy_allocator.zig  -- buddy allocator (PMM backing)
    bump_allocator.zig   -- bump allocator (early boot, slab backing)
    slab_allocator.zig   -- generic typed slab allocator
    heap_allocator.zig   -- general-purpose kernel heap
    vmm.zig              -- virtual memory manager (red-black tree)
    stack.zig            -- kernel and user stack management
    shared.zig           -- shared memory objects
    device_region.zig    -- device region objects
    paging.zig           -- page size constants
  sched/
    scheduler.zig        -- run queues, context switch, timer handler
    process.zig          -- process struct, creation, exit, permissions
    thread.zig           -- thread struct, creation, deinit
    restart_context.zig  -- restart context struct
    futex.zig            -- futex wait queue
    sync.zig             -- SpinLock
  perms/
    permissions.zig      -- rights types, permission entry, user view entry
    privilege.zig        -- kernel/user privilege enum
    memory.zig           -- MemoryPerms (PTE-level permission flags)
  containers/
    red_black_tree.zig   -- generic red-black tree
  devices/
    devices.zig          -- device module root
    registry.zig         -- device table and registration
```

---

## 2. Process Internals

### Process Struct

Defined in `kernel/sched/process.zig`:

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
    crash_reason: CrashReason              -- reason for last crash (u5, .none if no crash)
    restart_count: u16                     -- number of restarts (wraps on overflow)
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

Defined in `kernel/sched/restart_context.zig`:

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
    }
    rights: PageRights { read: bool, write: bool, execute: bool }
    handle: u64               -- HANDLE_NONE (U64_MAX) for kernel-internal nodes
    restart_policy: RestartPolicy { free, decommit, preserve }
}
```

`VmNode.end()` returns `start.addr + size`.

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

Never merge across reservation boundaries (different handles).

### Bump Cursor

The VMM cursor (`range_start` field, advanced during allocation) advances monotonically through the ASLR zone. On `reserve` without a hint, the cursor skips past existing nodes to find a free gap. `bump(size)` advances the cursor without creating a tree node -- used during process creation to position past kernel-internal nodes (ELF segments, permissions view, stacks).

### splitNode

Splits a VmNode at a page-aligned offset into two new nodes. Both halves inherit: `kind`, `rights`, `handle`, `restart_policy`. The original node is removed from the tree and replaced with two new nodes. Used by `vm_perms`, `shm_map`, `mmio_map` to operate on sub-ranges of reservations.

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
}
```

`KernelObject` is a tagged union:
```
KernelObject = union(enum) {
    process: *Process
    dead_process: *Process  // struct stays alive via handle_refcount
    vm_reservation: VmReservationObject { max_rights, original_start, original_size }
    shared_memory: *SharedMemory
    device_region: *DeviceRegion
    core_pin: CorePinObject { core_id, thread_tid }
    empty: void
}
```

### Dead Process Entries

When a non-restartable child process dies, `cleanupPhase2` calls `convertToDeadProcess` on the parent, which replaces the `.process` entry with `.dead_process` storing a `*Process` pointer. The Process struct stays alive via `handle_refcount` until all handle holders revoke. Crash reason and restart count are read from the Process struct fields. The kernel issues a `futex.wake` on the parent's user view field0 physical address for this entry so that watchdog threads blocked on the field are woken. Any handle holder revokes at its convenience via `revoke_perm`, which clears the slot and decrements the refcount.

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

Types: `process = 0, vm_reservation = 1, shared_memory = 2, device_region = 3, core_pin = 4, dead_process = 5`.

### Rights Types

All rights are packed structs with bit fields:

- `ProcessRights`: packed `u16` -- `spawn_thread`(0), `spawn_process`(1), `mem_reserve`(2), `set_affinity`(3), `restart`(4), `shm_create`(5), `device_own`(6), `pin_exclusive`(7), 8 bits reserved.
- `ProcessHandleRights`: packed `u16` -- `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5), 10 bits reserved. Used on handles to other processes (not HANDLE_SELF).
- `VmReservationRights`: packed `u8` -- `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4), 3 bits reserved.
- `SharedMemoryRights`: packed `u8` -- `read`(0), `write`(1), `execute`(2), `grant`(3), 4 bits reserved.
- `DeviceRegionRights`: packed `u8` -- `map`(0), `grant`(1), `dma`(2), 5 bits reserved.

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
    state: State = .ready               -- { running, ready, blocked, exited }
    last_in_proc: bool = false          -- true if this is the last thread in process
    on_cpu: atomic(bool) = false        -- set while thread is actively on a CPU
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

### Thread Deinit

`Thread.deinit()`:
1. Save `last_in_proc` flag.
2. Destroy kernel stack (unmap committed pages, recycle slot).
3. If not last thread: destroy user stack via process VMM.
4. Free Thread to slab.
5. If last thread: call `proc.exit()` (triggers restart or cleanup).

The last thread skips user stack destruction because the process exit path tears down the entire address space.

---

## 6. Run Queue

### Structure

Per-core singly-linked intrusive list with a sentinel node. Defined in `kernel/sched/scheduler.zig`:

```
RunQueue {
    sentinel: Thread       -- dummy head node (belongs to idle_process)
    head: *Thread          -- points to sentinel
    tail: *Thread          -- points to last enqueued thread (or sentinel if empty)
}
```

The sentinel's `tid = U64_MAX`, `process = idle_process`, `state = .running`.

### Per-Core State

```
PerCoreState {
    rq: RunQueue
    rq_lock: SpinLock
    running_thread: ?*Thread
    timer: Timer
    zombie: ?Zombie        -- deferred thread cleanup
}
```

Array of 64 `PerCoreState` structs (`MAX_CORES = 64`), aligned to `CACHE_LINE_SIZE = 64` bytes to avoid false sharing.

### enqueue(thread)

Append to tail: `tail.next = thread; tail = thread; thread.next = null`.

### dequeue() -> ?*Thread

Pop from head: read `head.next`. If non-null, advance head's next pointer, handle tail update. Returns the dequeued thread or null if queue is empty (only sentinel present).

### Scheduler Timer Handler

`schedTimerHandler(ctx)`:
1. Clean up zombie from previous cycle (deferred `deinit`).
2. Save preempted thread's context.
3. Clear preempted thread's `on_cpu` flag.
4. Acquire run queue lock.
5. If preempted thread is not sentinel and still `running`, set to `ready` and re-enqueue.
6. Dequeue next thread (or fall back to sentinel/idle).
7. Set next thread to `running`, set `on_cpu = true`.
8. If preempted thread is `exited`, store as zombie for deferred cleanup.
9. Release run queue lock.
10. Arm scheduler timer for next timeslice.
11. If same thread, return. Otherwise, `arch.switchTo(next)`.

### Timeslice

`SCHED_TIMESLICE_NS = 2_000_000` (2 ms).

### Yield

`sched.yield()` triggers a self-IPI: `arch.triggerSchedulerInterrupt(arch.coreID())`. The scheduler timer handler runs, treating it as a preemption.

### Zombie Deferred Cleanup

Exited threads cannot be freed inside the scheduler timer handler (they are running on the stack being freed). Instead, the thread is stored as a `Zombie { thread, last_in_proc }` and freed at the start of the next scheduler tick.

---

## 7. Futex Internals

### Hash Table

Global array of 256 buckets, statically allocated at compile time:

```
buckets: [256]Bucket

Bucket {
    lock: SpinLock
    head: ?*Thread
}
```

### Hash Function

`bucketIdx(paddr) = (paddr.addr >> 3) % 256`

The shift by 3 accounts for 8-byte alignment of futex addresses. Multiple physical addresses may hash to the same bucket; wake matches on the thread's stored physical address, not just the bucket.

### pushWaiter(bucket, thread)

Prepend to bucket's singly-linked list: `thread.next = bucket.head; bucket.head = thread`.

### popWaiter(bucket) -> ?*Thread

Pop head: `thread = bucket.head; bucket.head = thread.next; thread.next = null`.

### removeWaiter(bucket, target) -> bool

Linear scan of bucket list. Unlink target by updating predecessor's `next` pointer (or `bucket.head` if target is first). Returns true if found and removed.

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
5. **exited**: Already exited, skip.

After all threads are marked exited and removed from queues:
- Destroy stacks, deregister stack guards.
- Process exit logic runs.
- If `restart_context` present: restart (process survives). `restart_count` is incremented with wrapping arithmetic (`+%=`). `crash_reason` and `restart_count` are written to the process's own user view (slot 0 field0) and the parent's user view entry via `updateParentView`, which also issues a `futex.wake` on the parent's field0 physical address.
- If no restart context: cleanup. In `cleanupPhase2`, `convertToDeadProcess` replaces the parent's `.process` entry with `.dead_process` storing `*Process`, syncs the parent's user view, and issues a `futex.wake`. The Process struct remains alive until all handle holders revoke (`handle_refcount` reaches 0).

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

**init() -> void** -- IDT, GDT/TSS (per-core), segment registers, SYSCALL/SYSRET MSRs, CPU features (NX, SMEP, SMAP, etc.). Once on bootstrap core.

**parseFirmwareTables(firmware_table_paddr: PAddr) -> void** -- Parse ACPI tables:
- XSDP validation (signature, checksum).
- XSDT walk: iterate 8-byte physical pointers to SDTs.
- MADT: enumerate Local APICs (active cores), I/O APICs, interrupt source overrides, LAPIC address override. Initialize APIC subsystem.
- HPET: validate, MMIO-map, initialize timer.
- MCFG: PCI Enhanced Configuration Access Mechanism (ECAM) base addresses and bus ranges. Map ECAM pages, enumerate PCI devices.
- Fallback: if MCFG not present or no devices found, legacy PCI config space enumeration.
- Serial port probing.

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

### Timing

**getPreemptionTimer() -> Timer** -- Returns a LAPIC timer instance configured for one-shot mode. Used for per-core scheduler preemption. The LAPIC timer frequency is calibrated against HPET at boot.

**getMonotonicClock() -> Timer** -- Returns a TSC-based timer for monotonic nanosecond timestamps. Used by `clock_gettime` syscall and futex timeout logic.

**readTimestamp() -> u64** -- Raw `RDTSC` instruction. Architecture-specific cycle counter. Used for ASLR entropy at process creation time.

### Identification

**coreCount() -> u64** -- Returns the number of active cores discovered during MADT parsing. Reads from the LAPIC array length.

**coreID() -> u64** -- Returns the current core's LAPIC ID. On x2APIC: read IA32_X2APIC_APICID MSR. On xAPIC: read from MMIO register.

### Port I/O (x86-only)

**ioportIn(port: u16, width: u8) -> u32** -- `in` instruction. Width 1 = `inb`, 2 = `inw`, 4 = `ind`.

**ioportOut(port: u16, width: u8, value: u32) -> void** -- `out` instruction. Width 1 = `outb`, 2 = `outw`, 4 = `outd`.

### Diagnostics

**print(format, args) -> void** -- Serial port output via `kernel/arch/x64/serial.zig`. Formats into a 256-byte stack buffer, writes byte-by-byte to the configured COM port. Protected by a global `print_lock` SpinLock. No-op in release builds (`builtin.mode != .Debug`).

### x86_64 Page Table Format

4-level paging (PML4). Each level has 512 entries of 8 bytes (`PageEntry` packed struct):
- Bits 0-11: flags (present, writable, user, write-through, not-cacheable, accessed, dirty, huge, global, 3 ignored).
- Bits 12-51: 40-bit physical address (shifted right by 12).
- Bits 52-62: reserved.
- Bit 63: NX (no-execute).

Level shifts: L4 = 39, L3 = 30, L2 = 21, L1 = 12. Index extraction: `@truncate(vaddr >> shift)` gives 9-bit index.

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

Defined in `kernel/memory/buddy_allocator.zig`. Backing allocator for the PMM.

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

Defined in `kernel/memory/bump_allocator.zig`. Simple monotonic allocator.

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

Defined in `kernel/memory/slab_allocator.zig`. Generic, comptime-parameterized.

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

### Heap Allocator

Defined in `kernel/memory/heap_allocator.zig`. General-purpose kernel heap for variable-size allocations.

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
  [+thread_slab.end, +1 GiB)                       -- Heap tree node slab
  [+heap_tree.end, +256 GiB)                       -- Kernel heap

[0xFFFF_FF80_0000_0000, 0xFFFF_FF88_0000_0000)  -- Physmap (32 GiB)
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
10. Initialize slab bump allocators for each kernel object type (VmNode, VmTree, SHM, DeviceRegion, Process, Thread) -- each gets a 16 MiB VA region.
11. Initialize slabs: VmNode slab, VmTree slab, DeviceRegion slab, SharedMemory slab.

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

r14 encoding varies by syscall — see spec §2.12.

### Process Struct Fields

```
msg_waiters_head: ?*Thread    — head of FIFO queue of blocked call senders
msg_waiters_tail: ?*Thread    — tail of FIFO queue
receiver: ?*Thread            — thread currently blocked on recv (null if none)
pending_caller: ?*Thread      — call sender whose message was delivered, awaiting reply
pending_reply: bool           — true if a message has been received but not replied to
```

All protected by the existing `process.lock` spinlock. No new lock introduced.

### Thread Struct Fields

```
ipc_server: ?*Process         — back-pointer to process we're waiting for reply from (for cleanup)
```

### Process State Machine

```
Idle:            receiver=null, pending_reply=false, waiters empty
Receiving:       receiver=thread, pending_reply=false (thread blocked on recv)
Pending Reply:   receiver=null, pending_reply=true, pending_caller=thread|null
```

Transitions:
- Idle → Receiving: thread calls blocking `recv` with empty queue
- Idle/Receiving → Pending Reply: message delivered (from send/call to blocked receiver, or from queued caller to recv)
- Pending Reply → Idle: `reply` called, clears pending state

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

When a process holds a handle to another process (not `HANDLE_SELF`), the `rights` field uses `ProcessHandleRights` encoding: `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5). `proc_create` grants the parent full `ProcessHandleRights` on the child handle. The `grant` bit controls whether the handle can be re-transferred to another process via capability transfer. The `kill` bit controls whether `revoke_perm` triggers `killSubtree` or just drops the handle.

### Cleanup on Process Death

`cleanupIpcState()` runs at the beginning of `cleanupPhase1`:

**Server dies (this process has waiters):**
1. Walk `msg_waiters` list: set `waiter.ipc_server = null`, write `E_NOENT` to `waiter.ctx.regs.rax`, wake waiter
2. If `pending_caller` non-null: same treatment
3. Clear all IPC fields

**Caller dies (this process has threads blocked on other processes):**
1. For each thread with `ipc_server` set: lock the server, remove this thread from `pending_caller` or `msg_waiters`, clear `ipc_server`, unlock server

Both sides clean up to prevent dangling pointers regardless of death order.

### Restart Semantics

On process restart, IPC state persists with adjustments:
1. If `pending_caller` is set (message delivered but not replied to), the caller is re-enqueued at the head of `msg_waiters` so the restarted process can `recv` it again
2. `pending_reply` cleared, `receiver` cleared (old thread is dead)
3. `msg_waiters` queue persists untouched — callers from other processes remain blocked

This allows a server to crash mid-handling, restart, and pick up right where it left off.

### Process Handle Refcounting

Each Process has a `handle_refcount: u32` tracking how many perm table entries across all processes reference it (both `.process` and `.dead_process` entries). Incremented atomically on `insertPerm` for process/dead_process entries, decremented on `removePerm` and during `cleanupPhase1` perm table teardown.

`dead_process` KernelObject stores `*Process` (not just crash info), keeping the struct alive for refcount management. Crash reason and restart count are read directly from the Process struct fields.

`cleanupPhase2` sets `cleanup_complete = true` and only calls `allocator.destroy` if `handle_refcount == 0`. If refcount > 0, the struct persists as a zombie — address space freed, perm table cleared, but the struct itself remains allocated. When the last handle holder calls `removePerm`, the decrement sees `cleanup_complete == true` and `handle_refcount == 0`, triggering `allocator.destroy`.
