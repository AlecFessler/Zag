# Zag Microkernel Specification

## §1 Scope

Zag is a microkernel. It provides the minimal set of abstractions needed for isolated userspace processes to communicate and share hardware: physical memory management, virtual memory management, execution management, inter-process communication via shared memory and synchronous message passing, device access, and capability-based permission enforcement. Everything else lives in userspace.

---

## §2 Kernel Objects

### §2.1 Process

A process is an isolated execution environment with its own address space, permissions table, and set of threads. Processes form a tree: **§2.1.1** spawning a child via `proc_create` establishes a parent/children link (process tree).

#### Zombies

When a non-leaf process (one with living children) exits, it becomes a **zombie** rather than being destroyed outright. **§2.1.2** A non-leaf process (has children) that exits becomes a zombie: its parent's entry converts to `dead_process`. Zombies exist so that handles to their children remain valid — **§2.1.3** a zombie's children remain in the process tree and can still be addressed via their handles. **§2.1.4** Zombies hold no resources (no VM reservations, SHM, or device handles). **§2.1.5** A process with a restart context restarts instead of becoming a zombie.

A zombie's handle sticks around until someone cleans it up: **§2.1.6** a `dead_process` handle remains valid until explicitly revoked. **§2.1.7** If multiple processes hold handles to a dead process, revoking one does not invalidate the others.

#### Device Handle Return

Device handles are exclusive — only one process holds each at a time. When a process loses a device handle (through revocation, exit, or cleanup), the kernel walks up the process tree to find a new owner. **§2.1.8** When a device handle is returned (revoke, exit, cleanup), the kernel inserts the handle into the nearest alive ancestor. **§2.1.9** Device handle return skips zombie ancestors. **§2.1.10** A process mid-restart is alive and is a valid device handle return destination. **§2.1.11** If the destination's permissions table is full during device handle return, the walk continues to the next ancestor. **§2.1.12** If device handle return reaches root with no valid destination, the handle is dropped.

#### Root Service

The root service is the first userspace process, started by the kernel at boot. **§2.1.13** Root service is the sole source of all capabilities; all capabilities flow downward via process creation and message passing. **§2.1.14** Root service's slot 0 has all ProcessRights bits set at boot.

#### User Permissions View

Every process has a kernel-maintained read-only page called the **user permissions view** — a 128-entry table that mirrors the process's capability slots. Userspace reads this to discover what capabilities it holds. **§2.1.15** The user permissions view is a read-only region mapped into the process's address space. **§2.1.16** The user view is sized to maximum permissions table capacity. **§2.1.17** The kernel updates the user view on every permissions table mutation (insert, remove, type change).

Each entry has a handle ID and a type tag. **§2.1.18** Each entry's handle field is a monotonic u64 ID; empty slots have handle = `U64_MAX`. **§2.1.19** Each entry has a type field: `process`, `vm_reservation`, `shared_memory`, `device_region`, `core_pin`, or `dead_process`. **§2.1.20** Slot 0 (`HANDLE_SELF`) rights are encoded as `ProcessRights`; all other process handle slots use `ProcessHandleRights`.

The `field0` and `field1` fields carry type-specific metadata. For process entries: **§2.1.21** process entry `field0` encodes `crash_reason(u5, bits 0-4) | restart_count(u16, bits 16-31)`. **§2.1.22** On first boot, process entry `field0` = 0. **§2.1.23** After restart, `crash_reason` in `field0` reflects the triggering fault. **§2.1.24** After restart, `restart_count` in `field0` increments. **§2.1.25** `dead_process` entry has the same `field0` encoding as `process` (crash_reason + restart_count). **§2.1.26** Parent's `process` entry is converted to `dead_process` when the child dies without restarting.

For other types: **§2.1.27** `vm_reservation` entry: `field0` = start VAddr, `field1` = original size. **§2.1.28** `shared_memory` entry: `field0` = size. **§2.1.29** `device_region` entry: `field0` and `field1` follow §2.9 encoding.

**§2.1.30** The initial thread receives the user view pointer via the `arg` register at launch.

#### Address Space Layout

The user half of the virtual address space is split into two zones. The lower ASLR zone is where the kernel places ELF segments and stacks at a randomized base. The upper static reservation zone is for `vm_reserve` with an explicit hint address at deterministic locations.

**§2.1.31** User address space spans `[0, 0xFFFF_8000_0000_0000)`. **§2.1.32** ELF segments and stacks are never placed in the static reservation zone `[0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)`. **§2.1.33** `vm_reserve` with a hint in the static reservation zone uses that address (if no overlap). **§2.1.34** ELF segments and user stacks are placed in the ASLR zone `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` with a randomized base. **§2.1.35** The first 4 KiB `[0, 0x1000)` is unmapped; accessing address 0 causes a fault. **§2.1.36** The ASLR base address is page-aligned.

---

### §2.2 Virtual Memory

Virtual memory is managed per-process through **VM reservations** — contiguous ranges of virtual address space that a process explicitly claims. Within a reservation, memory can be private (demand-paged), backed by shared memory, or mapped to device MMIO.

`VmReservationRights` bits: `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4), `write_combining`(5). `shareable` and `mmio` are mutually exclusive. `write_combining` requires `mmio`.

`vm_perms` adjusts the effective access rights on a sub-range within a reservation. **§2.2.1** Setting RWX = 0 via `vm_perms` decommits the range: pages are freed and the VA range returns to demand-paged state. **§2.2.2** Pages demand-paged after decommit are guaranteed to be zeroed. **§2.2.3** `vm_perms` with non-zero RWX takes effect: accessing the range respects the new permissions (e.g., writing to a read-only range faults).

`shm_map` maps a shared memory region into a reservation at a specified offset. The reservation must have the `shareable` right, and the SHM's RWX rights must not exceed the reservation's max rights. **§2.2.4** `shm_map` maps the full SHM region at the specified offset. SHM pages are eagerly mapped — they're immediately accessible without demand-paging.

**§2.2.6** `shm_unmap` removes the SHM mapping from the reservation. **§2.2.7** After `shm_unmap`, the range reverts to private with max RWX rights.

`mmio_map` maps a device's MMIO region into a reservation. The reservation must have the `mmio` right plus at least `read` or `write`. MMIO mappings use uncacheable attributes by default; if the reservation has the `write_combining` right, write-combining attributes are used instead.

**§2.2.10** After `mmio_unmap`, the range reverts to private with max RWX rights.

---

### §2.3 Permissions

All access to kernel objects is mediated by **capabilities** — handles with associated rights. A process can only perform an operation if it holds a handle with the required rights. Capabilities flow downward through the process tree via `proc_create` and laterally via IPC capability transfer. There is no dedicated grant syscall.

**§2.3.1** Handles are monotonically increasing u64 IDs, unique per process lifetime. **§2.3.2** Handle 0 (`HANDLE_SELF`) exists at process creation and cannot be revoked.

There are four rights types. **ProcessRights** (u16, slot 0 only): `spawn_thread`(0), `spawn_process`(1), `mem_reserve`(2), `set_affinity`(3), `restart`(4), `shm_create`(5), `device_own`(6), `pin_exclusive`(7). **ProcessHandleRights** (u16, other process handles): `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5). **SharedMemoryRights** (u8): `read`(0), `write`(1), `execute`(2), `grant`(3). **DeviceRegionRights** (u8): `map`(0), `grant`(1), `dma`(2).

**§2.3.3** `restart` can only be granted by a parent that itself has restart capability. **§2.3.4** Once cleared via `disable_restart`, the restart capability cannot be re-enabled.

#### Transfer Rules

**§2.3.5** VM reservation handles are not transferable via message passing. **§2.3.6** SHM handles are transferable if the `grant` bit is set. **§2.3.7** SHM transfer is non-exclusive (both sender and target retain handles). **§2.3.8** Process handles are transferable if the `grant` bit is set. **§2.3.9** Device transfer is exclusive (removed from sender on transfer). **§2.3.10** Transferred rights must be a subset of source rights.

#### Revoke

Revoking a capability removes it from the permissions table. The cleanup depends on the type: **§2.3.11** revoking a VM reservation frees all pages in the range and clears the perm slot. **§2.3.12** Revoking SHM unmaps it from all reservations, reverts to private, and clears the slot. **§2.3.13** Revoking a device handle unmaps MMIO, returns handle up the process tree (§2.1), and clears the slot. **§2.3.14** Revoking a core pin unpins the thread, restores preemptive scheduling, and clears the slot. **§2.3.15** Revoking a process handle with `kill` right recursively kills the child's subtree. **§2.3.16** Revoking a process handle without `kill` right drops the handle without killing. **§2.3.17** Revoking a `dead_process` handle clears the slot. **§2.3.18** Sending `HANDLE_SELF` via capability transfer gives the recipient a process handle to the sender.

---

### §2.4 Thread

A thread is a unit of execution belonging to a process. All threads within a process share the same address space and permissions table. Observable states: running, ready, blocked (on futex or IPC), exited.

**§2.4.1** `thread_create` creates a new thread that begins executing at `entry_addr` with the specified `arg` value. `set_affinity` constrains a thread's core affinity; the change takes effect at the next scheduling decision.

---

### §2.5 Futex

The futex mechanism bridges userspace synchronization with the kernel scheduler. A thread atomically checks a memory location and sleeps if the value matches, avoiding busy-waiting.

**§2.5.1** `futex_wait` blocks the calling thread when value at `addr` matches `expected`. **§2.5.2** `futex_wait` with timeout=0 returns `E_TIMEOUT` immediately (try-only). **§2.5.3** `futex_wait` with timeout=`MAX_U64` blocks indefinitely until woken. **§2.5.4** `futex_wait` with a finite timeout blocks for at least `timeout_ns` nanoseconds; actual expiry may be delayed until the next scheduler tick. **§2.5.5** Cross-process futexes work over shared memory (two processes mapping the same SHM can synchronize via the same address). **§2.5.6** `futex_wake` wakes up to `count` threads blocked on `addr`. **§2.5.7** Futex waiters are woken in FIFO order.

---

### §2.6 Process Lifecycle

#### Restart

A process with a **restart context** (set at creation time via the `restart` bit) doesn't die on termination — it restarts. The kernel reloads its ELF, reinitializes its data segment, allocates a fresh stack, and launches a new initial thread. **§2.6.1** Restart is triggered when a process with a restart context terminates by voluntary exit (last thread calls `thread_exit`). **§2.6.2** Restart is triggered when a process with a restart context terminates by a fault. **§2.6.3** Restart is triggered when a process with a restart context terminates by parent-initiated kill.

**§2.6.4** A restarting process remains alive throughout (IPC to it does not return `E_BADHANDLE`).

Most state survives a restart. **§2.6.5** Permissions table persists across restart (except VM reservation entries). **§2.6.7** Restart count increments on each restart. Restart count wraps to zero on u16 overflow. **§2.6.9** Crash reason is recorded in slot 0 `field0` on restart. Code and rodata mappings persist across restart. **§2.6.11** Data mappings persist across restart; content is reloaded from original ELF. **§2.6.12** SHM handle entries persist across restart. **§2.6.13** Device handle entries persist across restart. **§2.6.14** Process tree position and children persist across restart. **§2.6.15** Restart context persists (process can restart again). **§2.6.16** Pending callers (received but not yet replied to) persist across restart. **§2.6.17** User permissions view (mapped read-only region) persists across restart.

What doesn't persist: **§2.6.6** VM reservation entries are cleared on restart. **§2.6.18** User-created VM reservations do not persist across restart. User stacks do not persist — a fresh one is allocated. **§2.6.20** SHM/MMIO mappings within freed reservations do not persist across restart. **§2.6.21** BSS is decommitted on restart. **§2.6.22** All threads are removed on restart; only a fresh initial thread runs.

A restarted process can detect that it restarted by checking slot 0: **§2.6.23** on first boot, only `HANDLE_SELF` exists with `field0` = 0. **§2.6.24** A process can detect restart via slot 0 `field0` (crash_reason or restart_count non-zero).

#### Kill and Death

When a process is killed, the kernel records why and notifies the parent through the user permissions view. **§2.6.25** When a fault kills a process, the crash reason is recorded. **§2.6.26** On restart, crash reason and restart count are written to both the process's own slot 0 and the parent's entry for the child. **§2.6.27** The kernel issues a futex wake on the parent's user view `field0` for a restarted child. **§2.6.28** Non-restartable dead process: parent's entry converts to `dead_process` with crash reason and restart count. **§2.6.29** The kernel issues a futex wake on the parent's user view `field0` for a dead child.

**§2.6.30** Non-parent holders' entries are lazily converted to `dead_process` on IPC attempt (`send`/`call` returns `E_BADHANDLE`).

Recursive kill walks the subtree depth-first. **§2.6.31** Non-recursive kill of a non-restartable process with children makes it a zombie. **§2.6.32** Recursive kill traverses the entire subtree (depth-first post-order). **§2.6.33** Restartable processes in recursive kill restart and keep device handles. **§2.6.34** Non-restartable processes in recursive kill die; device handles return up tree.

---

### §2.7 Shared Memory

A shared memory region is a set of physical pages that can be mapped into multiple processes' address spaces — the primary mechanism for bulk data transfer. SHM pages are eagerly allocated on creation. **§2.7.2** SHM pages are zeroed on creation. **§2.7.3** SHM is freed when the last handle holder revokes or exits.

---

### §2.8 Stack

Each user stack is flanked by unmapped guard pages that catch overflow and underflow. **§2.8.1** Each user stack has a 1-page unmapped underflow guard below the usable region. The first page of the usable region is eagerly mapped; the rest are demand-paged. **§2.8.3** Each user stack has a 1-page unmapped overflow guard above the usable region. **§2.8.4** Fault on the underflow guard (below stack) kills with crash reason `stack_overflow` (§3). **§2.8.5** Fault on the overflow guard (above stack) kills with crash reason `stack_underflow` (§3).

---

### §2.9 Device Region

A device region represents a hardware device. Two types: **MMIO** (memory-mapped, accessed via `mmio_map`) and **Port I/O** (accessed via `ioport_read`/`ioport_write`). **§2.9.1** Device access is exclusive (only one process holds the handle at a time).

Device entries in the user view encode hardware identification: **§2.9.2** device user view `field0` encodes: `device_type(u8) | device_class(u8) << 8 | size_or_port_count(u32) << 32`. **§2.9.3** Device user view `field1` encodes: `pci_vendor(u16) | pci_device(u16) << 16 | pci_class(u8) << 32 | pci_subclass(u8) << 40`.

**§2.9.4** At boot, the kernel inserts all device handles into the root service's permissions table. **§2.9.5** Kernel-internal devices (HPET, LAPIC, I/O APIC) are not exposed in the user view.

---

### §2.10 Core Pin

A core pin grants a thread exclusive, non-preemptible ownership of a CPU core — no other thread will be scheduled on that core until the pin is revoked. **§2.10.1** `pin_exclusive` grants exclusive, non-preemptible core ownership. **§2.10.2** Core pin is created via `pin_exclusive` and revoked via `revoke_perm`. A pinned thread runs uninterrupted until it voluntarily yields or is unpinned. **§2.10.4** After `pin_exclusive`, only the pinned thread executes on that core. **§2.10.5** Core pin user view `field0` = `core_id`. **§2.10.6** Core pin user view `field1` = `thread_tid`.

---

### §2.11 Message Passing

Message passing in Zag is synchronous and zero-buffered: payloads are transferred directly from sender registers to receiver registers, with no intermediate kernel buffer.

Five payload registers carry message data: `rdi`, `rsi`, `rdx`, `r8`, `r9` (words 0–4). `r13` = target process handle. `r14` = metadata flags. `rax` = syscall number (input) / status code (output).

**r14 metadata encoding.** For send/call input: bits [2:0] = word count (0–5), bit 3 = capability transfer flag. For recv output (set by kernel): bit 0 = 0 (from send) or 1 (from call), bits [3:1] = word count. For reply input: bit 0 = atomic recv flag, bit 1 = blocking flag, bits [4:2] = reply word count, bit 5 = capability transfer flag.

#### send

`send` is fire-and-forget. **§2.11.1** `send` is non-blocking: the sender continues running after delivery. **§2.11.2** `send` delivers payload to a receiver blocked on `recv`. **§2.11.3** `send` returns `E_AGAIN` if no receiver is waiting. **§2.11.4** `send` to a `dead_process` handle returns `E_BADHANDLE`.

#### call

`call` is a blocking RPC — the caller sends a message and blocks until the receiver replies. The caller's timeslice is donated to the receiver. **§2.11.5** `call` blocks the caller until the receiver calls `reply`. **§2.11.7** `call` with no receiver waiting queues the caller in the target's FIFO wait queue. **§2.11.8** `call` returns with reply payload in the payload registers. **§2.11.9** `call` to a `dead_process` handle returns `E_BADHANDLE`.

#### recv

**§2.11.10** `recv` dequeues the first waiter from the wait queue and copies its payload. **§2.11.11** `recv` with blocking flag blocks when the queue is empty. **§2.11.12** `recv` without blocking flag returns `E_AGAIN` when the queue is empty. **§2.11.13** `recv` returns `E_BUSY` if a pending reply has not been cleared. **§2.11.14** Only one thread per process may be blocked on `recv` at a time; a second thread gets `E_BUSY`. If capability transfer validation fails during recv dequeue, the receiver gets `E_MAXCAP`.

#### reply

**§2.11.16** `reply` to a `call` copies reply payload to the caller's registers and unblocks the caller. **§2.11.17** `reply` to a `send` clears the pending state. **§2.11.18** The process must call `reply` before calling `recv` again. The atomic recv flag on reply transitions directly into `recv` after replying. **§2.11.20** Non-blocking atomic recv returns `E_AGAIN` if no message is queued.

#### Wait Queue

**§2.11.21** The call wait queue is FIFO ordered. **§2.11.22** `send` never queues — it returns `E_AGAIN` if no receiver is waiting.

#### Capability Transfer

When the capability transfer flag is set, the last two payload words are interpreted as a handle and a rights mask. The kernel looks up the handle in the sender's table and inserts a new entry into the receiver's table with the specified (subset) rights. Validation happens at delivery time — immediately for direct delivery, at recv time for queued callers.

**§2.11.23** Capability transfer uses the last 2 payload words as handle + rights. **§2.11.25** SHM capability transfer requires the `grant` bit on the SHM handle. **§2.11.26** SHM capability transfer is non-exclusive (both sender and target retain handles). **§2.11.27** Process capability transfer inserts with `ProcessHandleRights` encoding. **§2.11.28** Device capability transfer is exclusive (removes from sender). **§2.11.29** Device capability transfer requires the target to have `device_own`.

#### Process Death and IPC Cleanup

When a process dies, blocked IPC threads are cleaned up. **§2.11.32** When a process dies, queued callers in its wait queue are unblocked with `E_NOENT`. **§2.11.33** If a caller is blocked waiting for a reply, it is unblocked with `E_NOENT` on server death. **§2.11.34** A restarting process is a valid IPC target.

---

## §3 Crash Reasons

Each fault or termination records a `CrashReason` (u5) in the process's slot 0 `field0` and the parent's user view entry:

| Value | Name | Trigger |
|-------|------|---------|
| 0 | `none` | first boot sentinel |
| 1 | `stack_overflow` | guard page fault below stack |
| 2 | `stack_underflow` | guard page fault above stack |
| 3 | `invalid_read` | read fault with no read permission |
| 4 | `invalid_write` | write fault with no write permission |
| 5 | `invalid_execute` | execute fault with no execute permission |
| 6 | `unmapped_access` | no VMM node for faulting address |
| 7 | `out_of_memory` | demand page allocation failed |
| 8 | `arithmetic_fault` | divide-by-zero or similar |
| 9 | `illegal_instruction` | invalid opcode |
| 10 | `alignment_fault` | alignment check exception |
| 11 | `protection_fault` | general protection fault |
| 12 | `normal_exit` | last thread voluntarily exited |
| 13 | `killed` | killed by parent via `kill` right |

**§3.1** Fault with no VMM node kills the process with `unmapped_access`. **§3.2** Fault on SHM/MMIO region kills with `invalid_read`/`invalid_write`/`invalid_execute` based on access type. **§3.3** Fault on a private region with wrong permissions kills with `invalid_read`/`invalid_write`/`invalid_execute`. **§3.4** Demand-paged private region: allocate zeroed page, map, resume. **§3.5** Demand page allocation failure kills with `out_of_memory`. **§3.6** Divide-by-zero kills with `arithmetic_fault`. **§3.7** Invalid opcode kills with `illegal_instruction`. **§3.8** Alignment check exception kills with `alignment_fault`. **§3.9** General protection fault kills with `protection_fault`. **§3.10** All user faults are non-recursive: killing a faulting process does not propagate to children.

---

## §4 Syscall API

All syscalls return `i64`. Non-negative = success, negative = error code. Sizes and offsets must be page-aligned (4 KiB). Handles are `u64` monotonic IDs. **§4.1.1** Unknown syscall number returns `E_INVAL`.

### Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `E_OK` | 0 | Success |
| `E_INVAL` | -1 | Invalid argument |
| `E_PERM` | -2 | Permission denied |
| `E_BADHANDLE` | -3 | Invalid or wrong-type handle |
| `E_NOMEM` | -4 | Out of physical memory or VA space |
| `E_MAXCAP` | -5 | Permissions table full |
| `E_MAXTHREAD` | -6 | Thread limit reached |
| `E_BADADDR` | -7 | Invalid virtual address |
| `E_TIMEOUT` | -8 | Timed out |
| `E_AGAIN` | -9 | Transient failure, retry |
| `E_NOENT` | -10 | Entry not found |
| `E_BUSY` | -11 | Resource already in use |
| `E_EXIST` | -12 | Committed pages in range |
| `E_NODEV` | -13 | Required hardware not present |
| `E_NORES` | -14 | Kernel resource limit reached |

---

### §4.2 write(ptr, len) → bytes_written

Debug-only serial output syscall. **§4.2.1** `write` returns the number of bytes written. **§4.2.2** `write` with `len == 0` is a no-op returning 0. **§4.2.3** `write` with `len > 4096` returns `E_INVAL`. **§4.2.4** `write` with invalid pointer returns `E_BADADDR`.

### §4.3 vm_reserve(hint, size, max_perms) → handle

Reserves a contiguous VA range, creating a private demand-paged region and a permissions table entry. **§4.3.1** `vm_reserve` returns handle ID (positive) on success. **§4.3.2** `vm_reserve` returns vaddr via second return register. **§4.3.3** `vm_reserve` with hint in the static reservation zone uses that address (if no overlap). **§4.3.4** `vm_reserve` with zero hint finds a free range. **§4.3.5** `vm_reserve` requires `mem_reserve` right — returns `E_PERM` without it. **§4.3.6** `vm_reserve` with zero size returns `E_INVAL`. **§4.3.7** `vm_reserve` with non-page-aligned size returns `E_INVAL`. **§4.3.8** `vm_reserve` with `shareable` + `mmio` both set returns `E_INVAL`. **§4.3.9** `vm_reserve` with `write_combining` without `mmio` returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion or `E_MAXCAP` when the permissions table is full.

### §4.4 vm_perms(vm_handle, offset, size, perms) → result

Adjusts effective access rights on a sub-range within a VM reservation. **§4.4.1** `vm_perms` returns `E_OK` on success. **§4.4.2** `vm_perms` with invalid handle returns `E_BADHANDLE`. **§4.4.3** `vm_perms` with non-`vm_reservation` handle returns `E_BADHANDLE`. **§4.4.4** `vm_perms` with non-page-aligned offset returns `E_INVAL`. **§4.4.5** `vm_perms` with zero size returns `E_INVAL`. **§4.4.6** `vm_perms` with non-page-aligned size returns `E_INVAL`. **§4.4.7** `vm_perms` with `shareable`/`mmio`/`write_combining` bits returns `E_INVAL`. **§4.4.8** `vm_perms` with out-of-bounds range returns `E_INVAL`. **§4.4.9** `vm_perms` with perms exceeding `max_rights` returns `E_PERM`. **§4.4.10** `vm_perms` on a range containing SHM or MMIO nodes returns `E_INVAL`.

### §4.5 shm_create(size, rights) → handle

Creates a shared memory region backed by eagerly allocated zeroed pages. **§4.5.1** `shm_create` returns handle ID (positive) on success. **§4.5.2** `shm_create` requires `shm_create` right — returns `E_PERM` without it. **§4.5.3** `shm_create` with zero size returns `E_INVAL`. **§4.5.4** `shm_create` with zero rights returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion or `E_MAXCAP` when the permissions table is full.

### §4.6 shm_map(shm_handle, vm_handle, offset) → result

Maps a full SHM region into a reservation at the given offset. **§4.6.1** `shm_map` returns `E_OK` on success. **§4.6.2** `shm_map` with invalid `shm_handle` returns `E_BADHANDLE`. **§4.6.3** `shm_map` with invalid `vm_handle` returns `E_BADHANDLE`. **§4.6.4** `shm_map` without `shareable` right on reservation returns `E_PERM`. **§4.6.5** `shm_map` with SHM RWX exceeding reservation max returns `E_PERM`. **§4.6.6** `shm_map` with non-page-aligned offset returns `E_INVAL`. **§4.6.7** `shm_map` with out-of-bounds range returns `E_INVAL`. **§4.6.8** `shm_map` with duplicate SHM in same reservation returns `E_INVAL`. **§4.6.9** `shm_map` with committed pages in range returns `E_EXIST`.

### §4.7 shm_unmap(shm_handle, vm_handle) → result

Removes an SHM mapping from a reservation. The process retains the handle. **§4.7.1** `shm_unmap` returns `E_OK` on success. **§4.7.2** `shm_unmap` with invalid handle returns `E_BADHANDLE`. **§4.7.3** `shm_unmap` when SHM is not mapped returns `E_NOENT`. **§4.7.4** Process retains SHM handle after `shm_unmap`.

### §4.8 mmio_map(device_handle, vm_handle, offset) → result

Maps a device's MMIO region into a reservation. **§4.8.1** `mmio_map` returns `E_OK` on success. **§4.8.2** `mmio_map` with invalid `device_handle` returns `E_BADHANDLE`. **§4.8.3** `mmio_map` with invalid `vm_handle` returns `E_BADHANDLE`. **§4.8.4** `mmio_map` without `map` right returns `E_PERM`. **§4.8.5** `mmio_map` without `mmio` right on reservation returns `E_PERM`. **§4.8.6** `mmio_map` without `read` or `write` right on reservation returns `E_PERM`. **§4.8.7** `mmio_map` with non-page-aligned offset returns `E_INVAL`. **§4.8.8** `mmio_map` with out-of-bounds range returns `E_INVAL`. **§4.8.9** `mmio_map` with duplicate device region returns `E_INVAL`. **§4.8.10** `mmio_map` with non-MMIO device returns `E_INVAL`. **§4.8.11** `mmio_map` with committed pages in range returns `E_EXIST`.

### §4.9 mmio_unmap(device_handle, vm_handle) → result

**§4.9.1** `mmio_unmap` returns `E_OK` on success. **§4.9.2** `mmio_unmap` with invalid handle returns `E_BADHANDLE`. **§4.9.3** `mmio_unmap` when MMIO is not mapped returns `E_NOENT`.

### §4.10 proc_create(elf_ptr, elf_len, perms) → handle

Spawns a new child process from an ELF binary. The `perms` parameter sets the child's slot 0 `ProcessRights`. **§4.10.1** `proc_create` returns handle ID (positive) on success. **§4.10.2** `proc_create` child starts with only `HANDLE_SELF`. **§4.10.3** `proc_create` requires `spawn_process` right — returns `E_PERM` without it. **§4.10.4** `proc_create` with `restart` in perms without parent restart capability returns `E_PERM`. **§4.10.5** `proc_create` with invalid ELF returns `E_INVAL`. **§4.10.8** `proc_create` with invalid `elf_ptr` returns `E_BADADDR`. **§4.10.10** `proc_create` grants parent full `ProcessHandleRights` on the child handle. **§4.10.11** `proc_create` with child perms exceeding parent's own process rights returns `E_PERM`. Returns `E_NOMEM` on memory exhaustion, `E_MAXCAP` when the permissions table is full, or `E_NORES` on kernel stack exhaustion.

### §4.11 thread_create(entry, arg, num_stack_pages) → result

Creates a new thread within the calling process. **§4.11.1** `thread_create` returns `E_OK` on success. **§4.11.2** `thread_create` requires `spawn_thread` right — returns `E_PERM` without it. **§4.11.3** `thread_create` with invalid entry returns `E_BADADDR`. **§4.11.4** `thread_create` with zero stack pages returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion, `E_MAXTHREAD` at the thread limit, or `E_NORES` on kernel stack exhaustion.

### §4.12 thread_exit() → noreturn

**§4.12.1** `thread_exit` terminates the calling thread (does not return). **§4.12.2** `thread_exit` of the last thread triggers process exit.

### §4.13 thread_yield() → result

**§4.13.1** `thread_yield` returns `E_OK`.

### §4.14 set_affinity(core_mask) → result

Sets the calling thread's core affinity. **§4.14.1** `set_affinity` returns `E_OK` on success. **§4.14.2** `set_affinity` requires `set_affinity` right — returns `E_PERM` without it. **§4.14.3** `set_affinity` with empty mask returns `E_INVAL`. **§4.14.4** `set_affinity` with invalid core IDs returns `E_INVAL`.

### §4.15 pin_exclusive() → handle

Pins the calling thread exclusively to its current core. **§4.15.1** `pin_exclusive` returns core_pin handle ID (positive) on success. **§4.15.2** `pin_exclusive` requires `pin_exclusive` right — returns `E_PERM` without it. **§4.15.3** `pin_exclusive` without single-core affinity returns `E_INVAL`. **§4.15.4** `pin_exclusive` with multi-core affinity returns `E_INVAL`. **§4.15.5** `pin_exclusive` that would pin all cores returns `E_INVAL`. **§4.15.6** `pin_exclusive` on already-pinned core returns `E_BUSY`. Returns `E_MAXCAP` when the permissions table is full.

### §4.16 send(r13=target, r14=metadata, payload regs) → status

**§4.16.1** `send` returns `E_OK` on successful delivery. **§4.16.2** `send` with invalid target handle returns `E_BADHANDLE`. **§4.16.3** `send` to `dead_process` returns `E_BADHANDLE`. **§4.16.4** `send` without `send_words` right returns `E_PERM`. **§4.16.5** `send` cap transfer without appropriate `send_shm`/`send_process`/`send_device` right returns `E_PERM`. **§4.16.6** `send` device cap transfer not parent→child returns `E_PERM`. **§4.16.7** `send` device cap transfer: target lacks `device_own` returns `E_PERM`. **§4.16.8** `send` cap transfer: source lacks `grant` on transferred handle returns `E_PERM`. **§4.16.9** `send` with no receiver waiting returns `E_AGAIN`. Cap transfer with a full target table returns `E_MAXCAP`. **§4.16.11** `send` cap transfer with fewer than 2 words returns `E_INVAL`.

### §4.17 call(r13=target, r14=metadata, payload regs) → status + reply

**§4.17.1** `call` returns `E_OK` with reply payload on success. **§4.17.2** `call` with invalid target handle returns `E_BADHANDLE`. **§4.17.3** `call` to `dead_process` returns `E_BADHANDLE`. **§4.17.4** `call` without required rights returns `E_PERM`. **§4.17.5** `call`: target dies while caller is waiting returns `E_NOENT`. Cap transfer failure returns `E_MAXCAP`. **§4.17.7** `call` cap transfer invalid payload returns `E_INVAL`.

### §4.18 recv(r14=metadata) → status + message

**§4.18.1** `recv` returns `E_OK` with payload and r14 sender metadata on success. **§4.18.2** `recv` non-blocking with no message returns `E_AGAIN`. **§4.18.3** `recv` with pending reply returns `E_BUSY`. **§4.18.4** `recv` with another thread already blocked returns `E_BUSY`. Cap transfer failure returns `E_MAXCAP`.

### §4.19 reply(r14=metadata, payload regs) → status

**§4.19.1** `reply` returns `E_OK` on success. **§4.19.2** `reply` with no pending message returns `E_INVAL`. **§4.19.3** `reply` atomic recv (non-blocking) with no message returns `E_AGAIN`. **§4.19.4** `reply` with capability transfer flag transfers a capability to the caller.

### §4.20 revoke_perm(handle) → result

**§4.20.1** `revoke_perm` returns `E_OK` on success. **§4.20.2** `revoke_perm` with invalid handle returns `E_BADHANDLE`. **§4.20.3** `revoke_perm` on `HANDLE_SELF` returns `E_INVAL`.

### §4.21 disable_restart() → result

Permanently clears the `restart` bit and frees the restart context for the calling process and all descendants. **§4.21.1** `disable_restart` returns `E_OK` on success. **§4.21.2** `disable_restart` without restart context returns `E_PERM`. **§4.21.3** `disable_restart` clears restart for all descendants recursively.

### §4.22 futex_wait(addr, expected, timeout_ns) → result

Atomically checks the u64 at `addr` against `expected` and blocks if they match. **§4.22.1** `futex_wait` returns `E_OK` when woken. **§4.22.2** `futex_wait` returns `E_AGAIN` on value mismatch. **§4.22.3** `futex_wait` returns `E_TIMEOUT` on timeout expiry. **§4.22.4** `futex_wait` with non-8-byte-aligned addr returns `E_INVAL`. **§4.22.5** `futex_wait` with invalid addr returns `E_BADADDR`. Returns `E_NORES` on futex slot exhaustion.

### §4.23 futex_wake(addr, count) → result

**§4.23.1** `futex_wake` returns number of threads woken (non-negative). **§4.23.2** `futex_wake` with invalid addr returns `E_BADADDR`. **§4.23.3** `futex_wake` with non-8-byte-aligned addr returns `E_INVAL`.

### §4.24 clock_gettime() → nanoseconds

**§4.24.1** `clock_gettime` returns monotonic nanoseconds since boot.

### §4.25 dma_map(device_handle, shm_handle) → dma_addr

Maps SHM into the device's IOMMU address space. Requires an IOMMU. DMA mappings are tracked per-process and automatically unmapped on exit. **§4.25.1** `dma_map` returns DMA base address (positive) on success. **§4.25.2** `dma_map` with invalid device handle returns `E_BADHANDLE`. **§4.25.3** `dma_map` with invalid SHM handle returns `E_BADHANDLE`. **§4.25.4** `dma_map` without `dma` right returns `E_PERM`. **§4.25.6** `dma_map` with non-MMIO device returns `E_INVAL`. Returns `E_NORES` on DMA mapping table full. DMA mappings present contiguous addresses to the device.

### §4.26 dma_unmap(device_handle, shm_handle) → result

**§4.26.1** `dma_unmap` returns `E_OK` on success. **§4.26.2** `dma_unmap` with invalid handle returns `E_BADHANDLE`. **§4.26.3** `dma_unmap` with no mapping returns `E_NOENT`.

### §4.27 ioport_read(device_handle, port_offset, width) → value

Reads from a Port I/O device register. Width is 1, 2, or 4 bytes. **§4.27.1** `ioport_read` returns value (non-negative) on success. **§4.27.2** `ioport_read` with invalid handle returns `E_BADHANDLE`. **§4.27.3** `ioport_read` without `map` right returns `E_PERM`. **§4.27.4** `ioport_read` with bad width (not 1, 2, or 4) returns `E_INVAL`. **§4.27.5** `ioport_read` with `offset + width > port_count` returns `E_INVAL`. **§4.27.6** `ioport_read` on non-`port_io` device returns `E_INVAL`.

### §4.28 ioport_write(device_handle, port_offset, width, value) → result

Same validation as `ioport_read`. **§4.28.1** `ioport_write` returns `E_OK` on success. **§4.28.2** `ioport_write` with invalid handle returns `E_BADHANDLE`. **§4.28.3** `ioport_write` without `map` right returns `E_PERM`. **§4.28.4** `ioport_write` with bad width returns `E_INVAL`. **§4.28.5** `ioport_write` with `offset + width > port_count` returns `E_INVAL`. **§4.28.6** `ioport_write` on non-`port_io` device returns `E_INVAL`.

---

## §5 System Limits

| Limit | Value |
|-------|-------|
| Threads per process | 64 |
| Children per process | 64 |
| Permissions table entries | 128 |
| Devices (registry) | 128 |
| Max CPU cores | 64 |
| Max kernel stacks | 16,384 |
| Default user stack | 16 KiB (4 pages) |
| SHM max size | 1 MiB (256 pages) |
| Futex wait queue buckets | 256 |
| Futex timed waiter slots | 64 |
| User permissions view | 1 page (128 entries × 32 bytes) |
| DMA mappings per process | 16 |
