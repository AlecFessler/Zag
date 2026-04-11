# Zag Microkernel Specification

## §1 Scope

Zag is a microkernel. It provides the minimal set of abstractions needed for isolated userspace processes to communicate and share hardware: physical memory management, virtual memory management, execution management, inter-process communication via shared memory and synchronous message passing, device access, capability-based permission enforcement, and virtual machine hosting. Everything else lives in userspace.

---

## §2 Kernel Objects

### §2.0 Priority

Every thread has a priority level that determines its scheduling order relative to other threads.

**§2.0.1** There are five priority levels, represented as a `u3`:

| Value | Name | Behavior |
|-------|------|----------|
| 0 | `idle` | Only runs when no other thread is ready on any core |
| 1 | `normal` | Default for all newly created threads; round-robin among peers |
| 2 | `high` | Preempts normal; round-robin among peers |
| 3 | `realtime` | Preempts high and below; round-robin among peers |
| 4 | `pinned` | Non-preemptible; exclusive core ownership |

**§2.0.2** All newly created threads start at `normal` priority, including the initial thread of a new process.

**§2.0.3** Every process has a `max_thread_priority` ceiling. Threads in that process cannot set their priority above this ceiling.

**§2.0.4** `max_thread_priority` is set at `proc_create` time as an explicit parameter and is never implicitly inherited.

**§2.0.5** A parent cannot grant a child a `max_thread_priority` higher than its own.

**§2.0.6** Root service starts with `max_thread_priority` = `pinned`.

**§2.0.7** Priority inheritance is not implemented.

---

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

Each entry has a handle ID and a type tag. **§2.1.18** Each entry's handle field is a monotonic u64 ID; empty slots have handle = `U64_MAX`. **§2.1.19** Each entry has a type field: `process`, `vm_reservation`, `shared_memory`, `device_region`, `core_pin`, `dead_process`, or `thread`. **§2.1.20** Slot 0 (`HANDLE_SELF`) rights are encoded as `ProcessRights`; all other process handle slots use `ProcessHandleRights`. Thread handle slots use `ThreadHandleRights`.

The `field0` and `field1` fields carry type-specific metadata. For process entries: **§2.1.21** process entry `field0` encodes `fault_reason(u5, bits 0-4) | restart_count(u16, bits 16-31)`. **§2.1.22** On first boot, process entry `field0` = 0. **§2.1.23** After restart, `fault_reason` in `field0` reflects the triggering fault. **§2.1.24** After restart, `restart_count` in `field0` increments. **§2.1.25** `dead_process` entry has the same `field0` encoding as `process` (fault_reason + restart_count). **§2.1.26** Parent's `process` entry is converted to `dead_process` when the child dies without restarting.

For other types: **§2.1.27** `vm_reservation` entry: `field0` = start VAddr, `field1` = original size. **§2.1.28** `shared_memory` entry: `field0` = size. **§2.1.29** `device_region` entry: `field0` and `field1` follow §2.9 encoding.

**§2.1.30** The initial thread receives the user view pointer via the `arg` register at launch.

#### Address Space Layout

The user half of the virtual address space is split into two zones. The lower ASLR zone is where the kernel places ELF segments and stacks at a randomized base. The upper static reservation zone is for `mem_reserve` with an explicit hint address at deterministic locations.

**§2.1.31** User address space spans `[0, 0xFFFF_8000_0000_0000)`. **§2.1.32** ELF segments and stacks are never placed in the static reservation zone `[0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)`. **§2.1.33** `mem_reserve` with a hint in the static reservation zone uses that address (if no overlap). **§2.1.34** ELF segments and user stacks are placed in the ASLR zone `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` with a randomized base. **§2.1.35** The first 4 KiB `[0, 0x1000)` is unmapped; accessing address 0 causes a fault. **§2.1.36** The ASLR base address is page-aligned.

**§2.1.37** Thread entry `field0` is the thread's stable kernel-assigned thread id (`tid`, u64).

**§2.1.38** Thread entry `field1` exposes the fault-handler exclude flags: bit 0 = `exclude_oneshot`, bit 1 = `exclude_permanent`. All other bits are reserved (zero). These flags let a userspace fault handler observe the result of `fault_set_thread_mode` and `fault_reply` with `FAULT_EXCLUDE_*` flags.

**§2.1.39** The user permissions view is kept in sync with the kernel permissions table.

---

### §2.2 Virtual Memory

Virtual memory is managed per-process through **VM reservations** — contiguous ranges of virtual address space that a process explicitly claims. Within a reservation, memory can be private (demand-paged), backed by shared memory, or mapped to device MMIO.

`VmReservationRights` bits: `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4), `write_combining`(5). `shareable` and `mmio` are mutually exclusive. `write_combining` requires `mmio`.

`mem_perms` adjusts the effective access rights on a sub-range within a reservation. **§2.2.1** Setting RWX = 0 via `mem_perms` decommits the range: pages are freed and the VA range returns to demand-paged state. **§2.2.2** Pages demand-paged after decommit are guaranteed to be zeroed. **§2.2.3** `mem_perms` with non-zero RWX takes effect: accessing the range respects the new permissions (e.g., writing to a read-only range faults).

`mem_shm_map` maps a shared memory region into a reservation at a specified offset. The reservation must have the `shareable` right, and the SHM's RWX rights must not exceed the reservation's max rights. **§2.2.4** `mem_shm_map` maps the full SHM region at the specified offset. SHM pages are eagerly mapped — they're immediately accessible without demand-paging.

**§2.2.6** `mem_shm_unmap` removes the SHM mapping from the reservation. **§2.2.7** After `mem_shm_unmap`, the range reverts to private with max RWX rights.

`mem_mmio_map` maps a device's MMIO region into a reservation. The reservation must have the `mmio` right plus at least `read` or `write`. MMIO mappings use uncacheable attributes by default; if the reservation has the `write_combining` right, write-combining attributes are used instead.

**§2.2.10** After `mem_mmio_unmap`, the range reverts to private with max RWX rights.

---

### §2.3 Permissions

All access to kernel objects is mediated by **capabilities** — handles with associated rights. A process can only perform an operation if it holds a handle with the required rights. Capabilities flow downward through the process tree via `proc_create` and laterally via IPC capability transfer. There is no dedicated grant syscall.

**§2.3.1** Handles are monotonically increasing u64 IDs, unique per process lifetime. **§2.3.2** Handle 0 (`HANDLE_SELF`) exists at process creation and cannot be revoked.

There are five rights types. **ProcessRights** (u16, slot 0 only): `spawn_thread`(0), `spawn_process`(1), `mem_reserve`(2), `set_affinity`(3), `restart`(4), `mem_shm_create`(5), `device_own`(6), `fault_handler`(7), `pmu`(8). **ProcessHandleRights** (u16, other process handles): `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5), `fault_handler`(6). When `fault_handler` is set on a handle to process P, the holder receives P's fault messages in the holder's own fault box. At most one external process may hold this bit for any given process at a time. **SharedMemoryRights** (u8): `read`(0), `write`(1), `execute`(2), `grant`(3). **DeviceRegionRights** (u8): `map`(0), `grant`(1), `dma`(2). **ThreadHandleRights** (u8): `suspend`(0), `resume`(1), `kill`(2), `pmu`(4). 4 bits reserved. The `pmu` bit gates access to a specific thread's performance monitoring state (§2.14).

**§2.3.3** `restart` can only be granted by a parent that itself has restart capability. **§2.3.4** Once cleared via `disable_restart`, the restart capability cannot be re-enabled.

#### Transfer Rules

**§2.3.5** VM reservation handles are not transferable via message passing. **§2.3.6** SHM handles are transferable if the `grant` bit is set. **§2.3.7** SHM transfer is non-exclusive (both sender and target retain handles). **§2.3.8** Process handles are transferable if the `grant` bit is set. **§2.3.9** Device transfer is exclusive (removed from sender on transfer). **§2.3.10** Transferred rights must be a subset of source rights.

**§2.3.19** Thread handles are not transferable via message passing. The kernel is the sole distributor of thread handles — processes receive handles for their own threads via `thread_create`, and a fault handler receives handles for a debuggee's threads when `fault_handler` is acquired.

#### Revoke

Revoking a capability removes it from the permissions table. The cleanup depends on the type: **§2.3.11** revoking a VM reservation frees all pages in the range and clears the perm slot. **§2.3.12** Revoking SHM unmaps it from all reservations, reverts to private, and clears the slot. **§2.3.13** Revoking a device handle unmaps MMIO, returns handle up the process tree (§2.1), and clears the slot. **§2.3.14** Revoking a core pin unpins the thread, restores the thread's pre-pin affinity mask, drops the thread's priority to its pre-pin level, and clears the slot. **§2.3.15** Revoking a process handle with `kill` right recursively kills the child's subtree. **§2.3.16** Revoking a process handle without `kill` right drops the handle without killing. **§2.3.17** Revoking a `dead_process` handle clears the slot. **§2.3.18** Sending `HANDLE_SELF` via capability transfer gives the recipient a process handle to the sender.

**§2.3.20** Revoking a thread handle removes it from the permissions table without affecting the thread's execution or state.

---

### §2.4 Thread

A thread is a unit of execution belonging to a process. All threads within a process share the same address space and permissions table. Observable states: running, ready, blocked (on futex or IPC), faulted, suspended, exited.

- `.faulted`: the thread has experienced a fault and is suspended awaiting fault handler reply; it is not scheduled.
- `.suspended`: the thread has been explicitly suspended via stop-all or `thread_suspend`; it is not scheduled.

**§2.4.1** `thread_create` returns the new thread's handle ID (positive u64) on success rather than `E_OK`. The handle is inserted into the calling process's permissions table with full `ThreadHandleRights`.

**§2.4.2** `thread_create` inserts a thread handle into the calling process's permissions table with full `ThreadHandleRights` and returns the handle ID (positive u64) on success.

**§2.4.3** The initial thread's handle is inserted at slot 1 of the child process's permissions table during `proc_create`, with `ThreadHandleRights` as specified by the `thread_rights` parameter to `proc_create`.

**§2.4.4** `thread_self` returns the handle ID of the calling thread as it appears in the calling process's own permissions table. Always succeeds.

**§2.4.5** Revoking a thread handle via `revoke_perm` removes the handle from the permissions table without killing or suspending the thread.

**§2.4.6** When a thread exits, its handle entry is cleared from its owning process's permissions table. If an external process holds `fault_handler` for that process, the thread handle is also cleared from the handler's permissions table. `syncUserView` is called on all affected tables.

**§2.4.7** A thread entry's `field0` in the user view exposes the thread's stable kernel-assigned thread id. Transient scheduling state is not published via the user view; observable thread state transitions are reported through their own channels (`fault_recv` for faults, the `thread_suspend` return code for suspension, and permission-entry removal for exit).

**§2.4.8** `thread_suspend` requires the `suspend` right on the thread handle; returns `E_PERM` without it.

**§2.4.9** `thread_suspend` on a `.running` thread causes it to enter `.suspended` state; if running on a remote core, a scheduling IPI is issued to force the transition at the next scheduling point.

**§2.4.10** `thread_suspend` on a `.ready` thread removes it from the run queue and enters `.suspended`.

**§2.4.11** `thread_suspend` on a `.faulted` or `.blocked` thread returns `E_BUSY`. A `.blocked` thread (waiting on a futex or IPC) can be suspended after it leaves `.blocked` by retrying the call.

**§2.4.12** `thread_suspend` on an already-`.suspended` thread returns `E_BUSY`.

**§2.4.13** `thread_resume` requires the `resume` right on the thread handle; returns `E_PERM` without it.

**§2.4.14** `thread_resume` on a `.suspended` thread moves it to `.ready` and re-enqueues it on the scheduler.

**§2.4.15** `thread_resume` on a thread not in `.suspended` state returns `E_INVAL`.

**§2.4.16** `thread_kill` requires the `kill` right on the thread handle; returns `E_PERM` without it.

**§2.4.17** `thread_kill` on a `.faulted` thread returns `E_BUSY`; the fault must be resolved via `fault_reply` with `FAULT_KILL` before the thread can be killed.

**§2.4.18** `thread_kill` on the last non-exited thread in a process triggers process exit or restart per §2.6 semantics.

**§2.4.19** `set_affinity` is self-only (no thread handle parameter). It requires `ProcessRights.set_affinity` on slot 0; returns `E_PERM` if absent. Returns `E_BUSY` if the calling thread is currently pinned.

**§2.4.20** `set_priority` is self-only (no thread handle parameter). It requires `ProcessRights.set_affinity` on slot 0 and is bounded by the process's `max_thread_priority` ceiling; returns `E_PERM` if the right is absent or the requested priority exceeds the ceiling.

**§2.4.21** A `.faulted` thread is not scheduled and does not appear on any run queue.

**§2.4.22** A `.suspended` thread is not scheduled and does not appear on any run queue.

**§2.4.23** When a thread calls `set_priority(.pinned)`, the kernel scans the thread's current affinity mask in ascending core ID order for a core with no pinned owner. The first available core is claimed; a `core_pin` handle is inserted into the process's permissions table, and the syscall returns the handle ID. If no core in the affinity mask is available, returns `E_BUSY`. If the affinity mask is empty, returns `E_INVAL`.

**§2.4.24** A pinned thread cannot call `set_affinity`; attempting it returns `E_BUSY`.

**§2.4.25** There are two ways to unpin: (1) call `revoke_perm` on the `core_pin` handle, which restores the pre-pin affinity mask and drops priority to the pre-pin level; (2) call `set_priority` with any non-pinned level, which implicitly revokes the `core_pin` handle, restores affinity, and applies the new priority.

**§2.4.26** When a pinned thread blocks (on a futex or IPC recv), it temporarily releases its core. Other threads may execute on that core while the pinned thread is blocked. The pin relationship persists.

**§2.4.27** When a pinned thread becomes ready again (futex wake or IPC delivery), the kernel immediately preempts whatever thread is running on the pinned core regardless of that thread's priority. The preempted thread is migrated to an affinity-eligible non-pinned core if one exists; otherwise it remains in the pinned core's run queue until the pinned thread next blocks.

**§2.4.28** `set_affinity` constrains the calling thread's core affinity; the change takes effect at the next scheduling decision.

---

### §2.5 Futex

The futex mechanism bridges userspace synchronization with the kernel scheduler. A thread atomically checks a memory location and sleeps if the value matches, avoiding busy-waiting.

**§2.5.1** `futex_wait` blocks the calling thread when value at `addr` matches `expected`. **§2.5.2** `futex_wait` with timeout=0 returns `E_TIMEOUT` immediately (try-only). **§2.5.3** `futex_wait` with timeout=`MAX_U64` blocks indefinitely until woken. **§2.5.4** `futex_wait` with a finite timeout blocks for at least `timeout_ns` nanoseconds; actual expiry may be delayed until the next scheduler tick. **§2.5.5** Cross-process futexes work over shared memory (two processes mapping the same SHM can synchronize via the same address). **§2.5.6** `futex_wake` wakes up to `count` threads blocked on `addr`. **§2.5.7** Futex waiters are woken in priority order (highest priority first), with FIFO ordering among waiters of the same priority level.

---

### §2.6 Process Lifecycle

#### Restart

A process with a **restart context** (set at creation time via the `restart` bit) doesn't die on termination — it restarts. The kernel reloads its ELF, reinitializes its data segment, allocates a fresh stack, and launches a new initial thread. **§2.6.1** Restart is triggered when a process with a restart context terminates by voluntary exit (last thread calls `thread_exit`). **§2.6.2** Restart is triggered when a process with a restart context terminates by a fault. **§2.6.3** Restart is triggered when a process with a restart context terminates by parent-initiated kill.

**§2.6.4** A restarting process remains alive throughout (IPC to it does not return `E_BADHANDLE`).

Most state survives a restart. **§2.6.5** Permissions table persists across restart (except VM reservation entries). **§2.6.7** Restart count increments on each restart. Restart count wraps to zero on u16 overflow. **§2.6.9** Fault reason is recorded in slot 0 `field0` on restart. Code and rodata mappings persist across restart. **§2.6.11** Data mappings persist across restart; content is reloaded from original ELF. **§2.6.12** SHM handle entries persist across restart. **§2.6.13** Device handle entries persist across restart. Core_pin handles and thread handles do not persist across restart; they are cleared alongside VM reservation entries. **§2.6.14** Process tree position and children persist across restart. **§2.6.15** Restart context persists (process can restart again). **§2.6.16** Pending callers (received but not yet replied to) persist across restart. **§2.6.17** User permissions view (mapped read-only region) persists across restart.

What doesn't persist: **§2.6.6** VM reservation entries are cleared on restart. **§2.6.18** User-created VM reservations do not persist across restart. User stacks do not persist — a fresh one is allocated. **§2.6.20** SHM/MMIO mappings within freed reservations do not persist across restart. **§2.6.21** BSS is decommitted on restart. **§2.6.22** All threads are removed on restart; only a fresh initial thread runs.

A restarted process can detect that it restarted by checking slot 0: **§2.6.23** on first boot, only `HANDLE_SELF` exists with `field0` = 0. **§2.6.24** A process can detect restart via slot 0 `field0` (fault_reason or restart_count non-zero).

#### Kill and Death

When a process is killed, the kernel records why and notifies the parent through the user permissions view. **§2.6.25** When a fault kills a process, the fault reason is recorded. **§2.6.26** On restart, fault reason and restart count are written to both the process's own slot 0 and the parent's entry for the child. **§2.6.27** The kernel issues a futex wake on the parent's user view `field0` for a restarted child. **§2.6.28** Non-restartable dead process: parent's entry converts to `dead_process` with fault reason and restart count. **§2.6.29** The kernel issues a futex wake on the parent's user view `field0` for a dead child.

**§2.6.30** Non-parent holders' entries are lazily converted to `dead_process` on IPC attempt (`send`/`call` returns `E_BADHANDLE`).

Recursive kill walks the subtree depth-first. **§2.6.31** Non-recursive kill of a non-restartable process with children makes it a zombie. **§2.6.32** Recursive kill traverses the entire subtree (depth-first post-order). **§2.6.33** Restartable processes in recursive kill restart and keep device handles. **§2.6.34** Non-restartable processes in recursive kill die; device handles return up tree.

**§2.6.35** On restart of a process that has an external fault handler: all thread handles for that process are bulk-revoked from the handler's permissions table; the fresh initial thread handle is immediately inserted into the handler's permissions table with full `ThreadHandleRights`; the `fault_handler` relationship (fault_handler_proc pointer) persists across restart without requiring re-transfer.

---

### §2.7 Shared Memory

A shared memory region is a set of physical pages that can be mapped into multiple processes' address spaces — the primary mechanism for bulk data transfer. SHM pages are eagerly allocated on creation. **§2.7.2** SHM pages are zeroed on creation. **§2.7.3** SHM is freed when the last handle holder revokes or exits.

---

### §2.8 Stack

Each user stack is flanked by unmapped guard pages that catch overflow and underflow. **§2.8.4** Fault on the underflow guard (below stack) kills with fault reason `stack_overflow` (§3). **§2.8.5** Fault on the overflow guard (above stack) kills with fault reason `stack_underflow` (§3).

---

### §2.9 Device Region

A device region represents a hardware device. Two types: **MMIO** (memory-mapped, accessed via `mem_mmio_map`) and **Port I/O** (accessed via `ioport_read`/`ioport_write`). **§2.9.1** Device access is exclusive (only one process holds the handle at a time).

Device entries in the user view encode hardware identification: **§2.9.2** device user view `field0` encodes: `device_type(u8) | device_class(u8) << 8 | size_or_port_count(u32) << 32`. **§2.9.3** Device user view `field1` encodes: `pci_vendor(u16) | pci_device(u16) << 16 | pci_class(u8) << 32 | pci_subclass(u8) << 40`.

**§2.9.4** At boot, the kernel inserts all device handles into the root service's permissions table. **§2.9.5** Kernel-internal devices (HPET, LAPIC, I/O APIC) are not exposed in the user view.

---

### §2.10 Core Pin

A core pin grants a thread exclusive, non-preemptible ownership of a CPU core. The pin is created by calling `set_priority(.pinned)` and revoked via `revoke_perm` on the core_pin handle or by calling `set_priority` with any non-pinned level. **§2.10.1** `set_priority(.pinned)` grants exclusive, non-preemptible core ownership. **§2.10.2** Core pin is created via `set_priority(.pinned)` and revoked via `revoke_perm` or `set_priority` with a non-pinned level. **§2.10.3** The core_pin handle is a revocation token only; it carries no rights bits (rights = 0). The only syscall that accepts it as input is `revoke_perm`. **§2.10.4** While pinned, only the pinned thread executes on that core (except when the pinned thread is blocked, during which other threads may be work-stolen onto the core). **§2.10.5** Core pin user view `field0` = `core_id`. **§2.10.6** Core pin user view `field1` = 0.

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

**§2.11.21** The call wait queue is priority ordered (highest priority first), with FIFO ordering among callers of the same priority level. **§2.11.22** `send` never queues — it returns `E_AGAIN` if no receiver is waiting.

#### Capability Transfer

When the capability transfer flag is set, the last two payload words are interpreted as a handle and a rights mask. The kernel looks up the handle in the sender's table and inserts a new entry into the receiver's table with the specified (subset) rights. Validation happens at delivery time — immediately for direct delivery, at recv time for queued callers.

**§2.11.23** Capability transfer uses the last 2 payload words as handle + rights. **§2.11.25** SHM capability transfer requires the `grant` bit on the SHM handle. **§2.11.26** SHM capability transfer is non-exclusive (both sender and target retain handles). **§2.11.27** Process capability transfer inserts with `ProcessHandleRights` encoding. **§2.11.28** Device capability transfer is exclusive (removes from sender). **§2.11.29** Device capability transfer requires the target to have `device_own`.

#### Process Death and IPC Cleanup

When a process dies, blocked IPC threads are cleaned up. **§2.11.32** When a process dies, queued callers in its wait queue are unblocked with `E_NOENT`. **§2.11.33** If a caller is blocked waiting for a reply, it is unblocked with `E_NOENT` on server death. **§2.11.34** A restarting process is a valid IPC target.

---

### §2.12 Fault Handling

Zag provides a unified fault handling mechanism covering both in-process fault recovery and external process debugging. Every process has a **fault box** — a message box distinct from its IPC message box — to which fault messages are delivered. The `fault_handler` capability bit controls which process receives a given process's fault messages. Fault handling uses `fault_recv` and `fault_reply` syscalls that are entirely separate from `recv` and `reply`; their state does not interact.

#### fault_handler Capability

**§2.12.1** `ProcessRights` bit 7 is `fault_handler`. When set on a process's slot 0, the process handles its own faults in its own fault box. This bit is granted at `proc_create` time if included in the `process_rights` parameter.

**§2.12.2** `ProcessHandleRights` bit 6 is `fault_handler`. When set on a handle to process P, the holder receives P's fault messages in the holder's own fault box. At most one process may hold `fault_handler` for a given process at a time.

**§2.12.3** Transferring `HANDLE_SELF` via capability transfer with the `fault_handler` bit set atomically: if the recipient already holds a process handle to the sender, the `fault_handler` bit is added to that existing entry; otherwise a new process handle entry is inserted into the recipient's permissions table with `fault_handler` set. In both cases, `fault_handler` is cleared from the sender's slot 0 `ProcessRights`, and all subsequent faults from the sender are routed to the recipient's fault box. The sender's `syncUserView` is updated to reflect the cleared bit.

**§2.12.4** When a process acquires `fault_handler` for a target, the kernel immediately inserts thread handles for all of the target's current threads into the acquirer's permissions table with full `ThreadHandleRights`.

**§2.12.5** While a process holds `fault_handler` for a target, any new threads created in the target are immediately inserted into the handler's permissions table with full `ThreadHandleRights` upon `thread_create`.

**§2.12.6** When `fault_handler` is released or the handler process dies, all thread handles belonging to the target are bulk-revoked from the handler's permissions table and `syncUserView` is called on the handler.

#### Fault Delivery

**§2.12.7** When a thread faults and the process is its own fault handler and only one thread exists (the faulting thread), the process is killed or restarted immediately per §2.6 semantics; no fault message is delivered.

**§2.12.8** When a thread faults and the process is its own fault handler and multiple threads exist, the faulting thread enters `.faulted` state and a fault message is enqueued in the process's own fault box; all other threads continue running normally.

**§2.12.9** When all threads in a self-handling process are simultaneously in `.faulted` state, the process is killed or restarted per §2.6 semantics; no additional fault messages are delivered.

**§2.12.10** When a thread faults and an external process holds `fault_handler` for it, the faulting thread enters `.faulted` state; all other threads in the process that are `.running` or `.ready` enter `.suspended` state (stop-all); a fault message is enqueued in the handler's fault box.

**§2.12.11** Before applying stop-all on an external fault, the kernel checks the faulting thread's `exclude_oneshot` and `exclude_permanent` flags on the thread's perm entry in the handler's permissions table. If either flag is set, only the faulting thread enters `.faulted` and all other threads continue running. If `exclude_oneshot` was set, it is cleared after the check (one-shot consumption); `exclude_permanent` is never cleared by the fault mechanism itself.

**§2.12.12** A `#BP` (int3) exception delivers a fault message with `fault_reason = breakpoint` (14) rather than killing the process immediately. `fault_addr` contains the RIP at the time of the exception.

#### FaultMessage Layout

The `FaultMessage` struct written to the userspace buffer on `fault_recv`:

```
FaultMessage (extern struct):
    process_handle: u64         // handle ID of source process in handler's perm table
    thread_handle:  u64         // handle ID of faulting thread in handler's perm table
    fault_reason:   u8          // FaultReason value
    _pad:           [7]u8
    fault_addr:     u64         // CR2 for page faults; RIP for all others
    regs:           arch.SavedRegs  // arch-specific full register snapshot
```

**§2.12.13** `FaultMessage.process_handle` is the handle ID of the source process as it appears in the handler's own permissions table.

**§2.12.14** `FaultMessage.thread_handle` is the handle ID of the faulting thread as it appears in the handler's own permissions table. This value is also the fault token returned by `fault_recv`.

#### fault_recv

**§2.12.15** `fault_recv` with the blocking flag set blocks until a fault message is available in the calling process's fault box.

**§2.12.16** `fault_recv` with the blocking flag clear returns `E_AGAIN` if no fault message is pending.

**§2.12.17** `fault_recv` returns `E_BUSY` if the fault box is already in `pending_reply` state.

**§2.12.18** `fault_recv` returns `E_PERM` if the calling process holds neither its own `fault_handler` ProcessRights bit nor `fault_handler` on any process handle.

**§2.12.19** On success, `fault_recv` writes a `FaultMessage` to the provided userspace buffer, transitions the fault box to `pending_reply` state, and returns the fault token (equal to `FaultMessage.thread_handle`) in `rax`.

#### fault_reply

Reply actions (encoded in r14 bits after the fault flag):
- `FAULT_KILL` (0): kill the faulting thread.
- `FAULT_RESUME` (1): resume the faulting thread with saved register state unchanged.
- `FAULT_RESUME_MODIFIED` (2): resume the faulting thread with registers replaced from `modified_regs_ptr`.

Reply flags (additional r14 bits):
- `FAULT_EXCLUDE_NEXT`: sets `exclude_oneshot` on the faulting thread's perm entry; clears `exclude_permanent`.
- `FAULT_EXCLUDE_PERMANENT`: sets `exclude_permanent` on the faulting thread's perm entry; clears `exclude_oneshot`.

**§2.12.20** `fault_reply` returns `E_INVAL` if the fault box is not in `pending_reply` state.

**§2.12.21** `fault_reply` returns `E_NOENT` if the fault token does not match the currently pending thread (i.e., the thread was killed externally while the fault was pending).

**§2.12.22** `fault_reply` with both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` set returns `E_INVAL`.

**§2.12.23** On any `fault_reply`, all threads in the target process that are in `.suspended` state are moved to `.ready` and re-enqueued before the action on the faulting thread is applied.

**§2.12.24** `fault_reply` with `FAULT_KILL` kills the faulting thread. If it is the last non-exited thread, process exit or restart proceeds per §2.6.

**§2.12.25** `fault_reply` with `FAULT_RESUME` resumes the faulting thread with its register state unchanged.

**§2.12.26** `fault_reply` with `FAULT_RESUME_MODIFIED` resumes the faulting thread with its register state replaced by the contents of `modified_regs_ptr` (must be a readable region of `sizeof(arch.SavedRegs)` bytes).

**§2.12.27** `fault_reply` with `FAULT_EXCLUDE_NEXT` sets `exclude_oneshot` on the faulting thread's perm entry in the handler's table and clears `exclude_permanent`. `syncUserView` is called on the handler.

**§2.12.28** `fault_reply` with `FAULT_EXCLUDE_PERMANENT` sets `exclude_permanent` on the faulting thread's perm entry in the handler's table and clears `exclude_oneshot`. `syncUserView` is called on the handler.

#### fault_set_thread_mode

**§2.12.29** `fault_set_thread_mode` with mode `stop_all` clears both `exclude_oneshot` and `exclude_permanent` on the thread's perm entry in the caller's permissions table.

**§2.12.30** `fault_set_thread_mode` with mode `exclude_next` sets `exclude_oneshot` and clears `exclude_permanent`.

**§2.12.31** `fault_set_thread_mode` with mode `exclude_permanent` sets `exclude_permanent` and clears `exclude_oneshot`.

**§2.12.32** `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread (the thread handle appears in the caller's perm table as a thread-type entry belonging to a process whose `fault_handler_proc == caller`). Returns `E_PERM` otherwise.

#### Memory Access

**§2.12.33** `fault_read_mem` reads bytes from the target process's virtual address space into the caller's buffer. Requires the `fault_handler` ProcessHandleRights bit on `proc_handle`. Valid regardless of target thread states.

**§2.12.34** `fault_write_mem` writes bytes from the caller's buffer into the target process's virtual address space via physmap, bypassing the target's page table permission bits. Requires the `fault_handler` ProcessHandleRights bit on `proc_handle`. Writes to pages mapped read-only in the target succeed. Valid regardless of target thread states.

#### Handler Death

**§2.12.35** When the handler process dies, all processes that had it as fault handler revert to self-fault-handling: their `fault_handler` ProcessRights bit is restored and their `fault_handler_proc` is cleared. Pending fault messages in the dead handler's fault box are discarded. Threads in `.faulted` state in those processes are re-evaluated under self-handling semantics (§2.12.7 and §2.12.9). Threads in `.suspended` state are moved to `.ready` and re-enqueued.

**§2.12.36** The fault box state is fully independent from the IPC message box state. `fault_recv` and `fault_reply` do not interact with `recv`/`reply` pending state; both boxes may be in `pending_reply` simultaneously.

---

### §2.13 Virtual Machine

Zag supports hosting virtual machines via kernel-managed VM primitives. A userspace VM manager process creates and manages a VM, handles VM exits that require policy decisions or device emulation, and communicates with other Zag services for device I/O. The kernel handles low-level VM mechanics; policy lives in userspace.

**§2.13.1** All VM syscalls (except `vm_create`) return `E_INVAL` if the calling process has no VM.

**§2.13.2** When the VM manager process exits or is killed, the kernel destroys its VM as part of process cleanup: all vCPU threads are killed, guest memory is freed, and the VM is deallocated. This happens before the process's own address space is freed.

#### vCPU

A vCPU represents a virtual CPU. vCPU threads are created internally by the kernel during `vm_create`, not via `thread_create`. The scheduler treats vCPU threads like any other thread.

**§2.13.3** vCPU threads appear in the VM manager process's permissions table as normal thread handles with full `ThreadHandleRights`.

#### VmExitBox

The VM has a dedicated exit box, separate from the VM manager process's fault box and IPC message box.

**§2.13.4** Multiple vCPUs can exit simultaneously. Each exit is tracked independently per vCPU. The VM manager dequeues exits via `vm_recv` and replies to each via `vm_reply` using the exit token (the vCPU's thread handle ID).

**§2.13.5** `vm_recv` writes a `VmExitMessage` to the caller's buffer and returns the exit token.

#### VmExitMessage

The `VmExitMessage` struct written to userspace on `vm_recv`:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | `thread_handle` — vCPU thread handle ID in caller's perm table |
| 8 | variable | `exit_info` — arch-specific exit reason and qualification (`arch.VmExitInfo`) |
| 8+exit_info | variable | `guest_state` — full guest register snapshot (`arch.GuestState`) |

**§2.13.6** The exit token returned by `vm_recv` equals `VmExitMessage.thread_handle`.

#### VmReplyAction

The action passed to `vm_reply`:

| Variant | Payload | Behavior |
|---------|---------|----------|
| `resume_guest` | `arch.GuestState` | Resume with possibly modified guest state |
| `inject_interrupt` | `arch.GuestInterrupt` | Resume with virtual interrupt pending |
| `inject_exception` | `arch.GuestException` | Resume with exception pending |
| `map_memory` | `host_vaddr: u64, guest_addr: u64, size: u64, rights: u8` | Map host memory as guest physical memory, then resume |
| `kill` | (none) | Terminate the vCPU |

**§2.13.7** A `vm_reply` with `map_memory` action maps host memory as guest physical memory at the specified address and resumes the vCPU.

#### Guest Memory

**§2.13.8** Guest memory access faults on unmapped guest physical regions are delivered to the VMM as exits, allowing the VMM to map the region or inject a fault.

#### Kernel-Handled vs VMM-Handled Exits

**§2.13.9** The kernel handles some exits inline without VMM involvement: CPU feature queries covered by the VM policy return the configured response and advance RIP. Privileged register accesses covered by the VM policy are also handled inline.

**§2.13.10** All other exits are delivered to the VMM via the VmExitBox: device I/O, unmapped memory access, uncovered privileged register accesses, guest halt, guest shutdown, and unrecoverable faults.

#### Interrupt Injection

**§2.13.11** `vm_vcpu_interrupt` injects a virtual interrupt into a vCPU. If the vCPU is running, the kernel IPIs its core, injects the interrupt, and immediately resumes.

**§2.13.12** If the vCPU is not currently running, the kernel writes the pending interrupt into the vCPU's arch state for delivery on next resume.

**§2.13.13** The `VmExitMessage.guest_state` snapshot reflects the guest register state at the point of exit, including the instruction pointer of the exiting instruction.

#### In-Kernel LAPIC and IOAPIC

The kernel emulates a single-vCPU Local APIC at guest physical `0xFEE00000` and a 24-pin I/O APIC at guest physical `0xFEC00000` for every VM. Guest reads and writes to either page are decoded and handled inline by the kernel without producing VM exits to the VMM. The LAPIC timer ticks against the host TSC each time a vCPU re-enters guest mode, and pending interrupt vectors are injected via the standard event-injection path. Because the kernel owns these pages, `vm_guest_map` refuses any request whose guest physical region overlaps either of them (§4.40.8).

#### MSR Passthrough

The VMM can request that specific MSRs be made directly accessible to the guest (no VM exit on RDMSR/WRMSR) via `vm_msr_passthrough` (§4.47). The kernel maintains a hard blocklist of security-critical MSRs that must always be intercepted regardless of what the VMM requests:

`EFER` (`0xC0000080`), `STAR` (`0xC0000081`), `LSTAR` (`0xC0000082`), `CSTAR` (`0xC0000083`), `SFMASK` (`0xC0000084`), `IA32_APIC_BASE` (`0x1B`), `KERNEL_GS_BASE` (`0xC0000102`), `IA32_SYSENTER_CS` (`0x174`), `IA32_SYSENTER_ESP` (`0x175`), `IA32_SYSENTER_EIP` (`0x176`).

#### Userspace IRQ Assertion

`vm_ioapic_assert_irq` (§4.48) and `vm_ioapic_deassert_irq` (§4.49) let userspace device emulators drive the in-kernel IOAPIC directly. After a successful assert or de-assert, the kernel sends an inter-processor interrupt to any core currently running one of the VM's vCPUs so the vCPU re-enters its scheduling loop and observes the new interrupt state. This kick is what lets guests in tight polling loops see freshly asserted IRQs without waiting for a timer-induced exit; the end-to-end behavior is exercised by the Linux boot integration test (`./test.sh linux`).

---

### §2.14 Performance Monitoring Unit

Zag exposes hardware performance counters to userspace as a kernel-managed per-thread resource. The PMU model is intentionally generic: userspace requests counter configurations in terms of named event types, and the kernel maps them onto whatever performance monitoring hardware the machine actually has. No arch-specific detail (model-specific registers, event select encodings, vendor quirks) is visible through the syscall interface.

Two use cases drive the design. **Precise counting** is a thread configuring counters on itself, running a unit of work, reading the counters back, and inspecting the exact event totals — the measurement target is always the caller itself, and no thread suspension occurs beyond the normal syscall boundary. **Sample-based profiling** configures counters with an overflow threshold; when a counter crosses the threshold the thread faults, a fault message is delivered to the fault handler (typically an external profiler), and the profiler reads the instruction pointer out of the fault message's register snapshot to record a sample before resetting the counters and resuming. Both use cases share the same `pmu_start` / `pmu_read` / `pmu_reset` / `pmu_stop` primitives; whether sampling occurs is determined solely by whether a counter's overflow threshold is set.

PMU counters measure events at user privilege only (ring 3 on x86). Kernel-mode time spent handling syscalls, interrupts, or faults on a thread's core is not included in that thread's counts, so cross-thread bleed from incidental kernel activity cannot pollute per-thread measurements.

#### Capability Model

PMU access is dual-gated. **§2.14.1** `ProcessRights.pmu` gates whether a process may call any PMU syscall that operates on thread state; without it, `pmu_start`, `pmu_read`, `pmu_reset`, and `pmu_stop` return `E_PERM`. The informational `pmu_info` syscall is not gated. **§2.14.2** `ThreadHandleRights.pmu` gates whether the caller may operate on a specific thread's PMU state; it is required in addition to `ProcessRights.pmu` for every PMU syscall that takes a thread handle. **§2.14.3** Root service holds `ProcessRights.pmu` at boot. **§2.14.4** `ProcessRights.pmu` flows to child processes via the `process_rights` parameter of `proc_create` under the usual subset rule.

**§2.14.5** A thread may profile itself by passing its own handle from `thread_self` to the PMU syscalls, but this still requires `ProcessRights.pmu` on the calling process — there is no special self-access path. **§2.14.6** The only way a process may hold `ThreadHandleRights.pmu` on another process's threads is to hold `fault_handler` for that process. When `fault_handler` is acquired, the thread handles the kernel inserts into the handler's permissions table carry full `ThreadHandleRights` including `pmu`. Thread handles are not transferable via IPC, so this is the sole mechanism.

#### Observable Types

`PmuEvent` is the set of named event types the kernel understands. Userspace selects events by variant; the kernel maps each variant to the appropriate hardware configuration for the host machine.

```
PmuEvent = enum {
    cycles,
    instructions,
    cache_references,
    cache_misses,
    branch_instructions,
    branch_misses,
    bus_cycles,
    stalled_cycles_frontend,
    stalled_cycles_backend,
}
```

`PmuCounterConfig` describes one counter. A null `overflow_threshold` means the counter is used for precise counting and never overflows; a non-null threshold selects sample-based profiling, with a PMI-driven fault delivered when the counter reaches the threshold.

```
PmuCounterConfig (extern struct) {
    event:              PmuEvent
    overflow_threshold: ?u64
}
```

The concrete userspace ABI encodes the optional `overflow_threshold` as an explicit `has_threshold: bool` discriminator alongside a plain `overflow_threshold: u64`, since `?u64` is not FFI-safe in an `extern struct`. `has_threshold == false` denotes precise counting (the `overflow_threshold` field is ignored); `has_threshold == true` denotes sample-based profiling at the given threshold. The struct is 24 bytes: an 8-byte `event` slot (one byte of `PmuEvent` plus padding), an 8-byte `has_threshold` slot (one byte of `bool` plus padding), and the 8-byte `overflow_threshold`.

`PmuInfo` describes the hardware's capabilities; userspace queries this before configuring counters.

```
PmuInfo (extern struct) {
    num_counters:     u8     // number of hardware counters available
    supported_events: u64    // bitmask, one bit per PmuEvent variant
    overflow_support: bool   // whether overflow interrupts are supported
}
```

`PmuSample` is the snapshot of counter state returned by `pmu_read`.

```
PmuSample (extern struct) {
    counters:  [MAX_COUNTERS]u64   // one u64 per configured counter, in config order
    timestamp: u64                  // monotonic nanoseconds at time of read
}
```

`MAX_COUNTERS` is fixed at the kernel's maximum counter count across supported architectures. Entries beyond the hardware's `num_counters` are zero. Userspace should use `PmuInfo.num_counters` to know how many slots are meaningful.

**§2.14.7** `PmuSample.timestamp` is a monotonic nanosecond reading consistent with `clock_gettime`, sampled at the moment the counters are read.

#### State Model

**§2.14.8** PMU state on a thread is created lazily. A thread that has never called `pmu_start` has no PMU state and no PMU-related context switch overhead. `pmu_start` allocates PMU state for the thread on first call. `pmu_stop` frees it. **§2.14.9** A thread's PMU state is automatically released on thread exit.

**§2.14.10** PMU counters on a thread are preserved across context switches: when the thread is descheduled the current counter values are saved, and when it is redispatched they are restored. Counts are therefore per-thread, not per-core, and unrelated threads cannot corrupt one another's counters.

#### pmu_read Constraints

**§2.14.11** `pmu_read` is only valid when the target thread is in `.faulted` or `.suspended` state. Reading counters from a running thread on another core would require a cross-core IPI and mid-execution snapshot; this complexity is avoided because profilers always have a natural suspension point at which to read — either the PMU overflow fault, or an explicit `thread_suspend`. Reading a running thread returns `E_BUSY`.

#### PMU Overflow Fault Delivery

**§2.14.12** When a counter configured with an overflow threshold reaches that threshold the hardware raises a PMU interrupt. The kernel disables all of the thread's counters, transitions the thread to `.faulted`, and delivers a fault to the thread's fault handler with `fault_reason = pmu_overflow` (§3). The faulting thread's full register snapshot is included in the fault message, so the profiler reads the instruction pointer at the time of overflow directly from `FaultMessage.regs` — no separate sample ring buffer is required or provided.

**§2.14.13** On a PMU overflow fault, a profiler typically calls `pmu_read` to retrieve the final counter values, `pmu_reset` to reconfigure counters with the next threshold, and `fault_reply` with `FAULT_RESUME` to resume the thread. Counter configurations set by `pmu_reset` take effect when the thread is resumed.

**§2.14.14** A single-threaded process that is its own fault handler cannot use sample-based profiling: when its only thread overflows, the normal single-thread-fault semantics (§2.12.7) apply and the process is killed (or restarted). Sample-based self-profiling requires either at least two threads in the process, or an external fault handler. Precise counting, which does not set any overflow threshold, has no such limitation.

---

### §2.15 System Information

Zag exposes a read-only view of system-wide and per-core hardware and scheduler state through a single syscall, `sys_info`. The data is split into two structs: a system-wide `SysInfo` and an array of per-core `CoreInfo` entries. The call is unprivileged — any process may read system information without holding any capability.

The design deliberately exposes raw scheduler accounting rather than precomputed percentages. Userspace decides the sampling window (by choosing how often to poll), divides `busy_ns / (idle_ns + busy_ns)` to get utilization, and picks whatever smoothing or rate-conversion strategy it prefers. The kernel never computes a utilization percentage on userspace's behalf.

#### Observable Types

`SysInfo` — system-wide static and dynamic properties:

```
SysInfo (extern struct) {
    core_count: u64    // number of active CPU cores
    mem_total:  u64    // total physical pages
    mem_free:   u64    // currently free physical pages
}
```

`CoreInfo` — per-core dynamic properties, one entry per core indexed by core ID:

```
CoreInfo (extern struct) {
    idle_ns: u64    // nanoseconds spent idle in the last accounting window
    busy_ns: u64    // nanoseconds spent busy in the last accounting window
    freq_hz: u64    // current CPU frequency in Hz
    temp_mc: u32    // current temperature in milli-celsius
    c_state: u8     // current C-state idle level (0 = active)
}
```

**§2.15.1** `SysInfo.core_count` is the number of active CPU cores the kernel scheduled on at boot. It is a static property of a given boot and does not change between calls.

**§2.15.2** `SysInfo.mem_total` is the total physical page count managed by the kernel.

**§2.15.3** `SysInfo.mem_free` is the number of physical pages currently free for allocation, sampled at the time of the call.

**§2.15.4** `CoreInfo` entries are indexed by core ID: entry `i` describes core `i` for `i` in `[0, core_count)`.

**§2.15.5** `CoreInfo.freq_hz` is the current CPU frequency of the core in hertz.

`CoreInfo.temp_mc` is the current temperature of the core in milli-celsius (e.g. `45000` = 45.0°C). Milli-celsius is used in place of floating point so that sub-degree precision is preserved when the hardware exposes it.

`CoreInfo.c_state` is the current CPU idle C-state level for the core. **§2.15.6** A value of `0` means the core is active; higher values indicate progressively deeper idle states.

`CoreInfo.idle_ns` and `CoreInfo.busy_ns` are the nanoseconds the core spent running the idle thread and running real threads, respectively, accumulated since the last `sys_info` call that read per-core data for this core. Userspace computes utilization as `busy_ns / (idle_ns + busy_ns)`.

#### Accounting Windows

`idle_ns` and `busy_ns` are accumulated by the scheduler and delivered as raw counts; the kernel does not compute utilization percentages.

On every `sys_info` call with a non-null `cores_ptr`, each core's `idle_ns` and `busy_ns` are read and reset atomically before the values are returned to userspace. The next call therefore sees the accounting window that started at the previous call's return. A call with a null `cores_ptr` does not touch per-core accounting and does not reset the counters.

The accounting window size is userspace-controlled: the interval between consecutive `sys_info` calls with `cores_ptr != null` is the window over which `idle_ns` and `busy_ns` are reported.

---

## §3 Fault Reasons

Each fault or termination records a `FaultReason` (u5) in the process's slot 0 `field0` and the parent's user view entry:

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
| 14 | `breakpoint` | int3 / #BP exception |
| 15 | `pmu_overflow` | PMU counter overflow (sample-based profiling, §2.14) |

**§3.1** Fault with no VMM node kills the process with `unmapped_access`. **§3.2** Fault on SHM/MMIO region kills with `invalid_read`/`invalid_write`/`invalid_execute` based on access type. **§3.3** Fault on a private region with wrong permissions kills with `invalid_read`/`invalid_write`/`invalid_execute`. **§3.4** Demand-paged private region: allocate zeroed page, map, resume. **§3.5** Demand page allocation failure kills with `out_of_memory`. **§3.6** Divide-by-zero kills with `arithmetic_fault`. **§3.7** Invalid opcode kills with `illegal_instruction`. **§3.8** Alignment check exception kills with `alignment_fault`. **§3.9** General protection fault kills with `protection_fault`. **§3.10** All user faults are non-recursive: killing a faulting process does not propagate to children. **§3.11** A counter overflow on a thread with PMU state configured for sample-based profiling delivers a fault with reason `pmu_overflow`; `FaultMessage.fault_addr` contains the faulting RIP and the full register snapshot in `FaultMessage.regs` is the sample.

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

### §4.3 mem_reserve(hint, size, max_perms) → handle

Reserves a contiguous VA range, creating a private demand-paged region and a permissions table entry. **§4.3.1** `mem_reserve` returns handle ID (positive) on success. **§4.3.2** `mem_reserve` returns vaddr via second return register. **§4.3.3** `mem_reserve` with hint in the static reservation zone uses that address (if no overlap). **§4.3.4** `mem_reserve` with zero hint finds a free range. **§4.3.5** `mem_reserve` requires `mem_reserve` right — returns `E_PERM` without it. **§4.3.6** `mem_reserve` with zero size returns `E_INVAL`. **§4.3.7** `mem_reserve` with non-page-aligned size returns `E_INVAL`. **§4.3.8** `mem_reserve` with `shareable` + `mmio` both set returns `E_INVAL`. **§4.3.9** `mem_reserve` with `write_combining` without `mmio` returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion or `E_MAXCAP` when the permissions table is full.

### §4.4 mem_perms(vm_handle, offset, size, perms) → result

Adjusts effective access rights on a sub-range within a VM reservation. **§4.4.1** `mem_perms` returns `E_OK` on success. **§4.4.2** `mem_perms` with invalid handle returns `E_BADHANDLE`. **§4.4.3** `mem_perms` with non-`vm_reservation` handle returns `E_BADHANDLE`. **§4.4.4** `mem_perms` with non-page-aligned offset returns `E_INVAL`. **§4.4.5** `mem_perms` with zero size returns `E_INVAL`. **§4.4.6** `mem_perms` with non-page-aligned size returns `E_INVAL`. **§4.4.7** `mem_perms` with `shareable`/`mmio`/`write_combining` bits returns `E_INVAL`. **§4.4.8** `mem_perms` with out-of-bounds range returns `E_INVAL`. **§4.4.9** `mem_perms` with perms exceeding `max_rights` returns `E_PERM`. **§4.4.10** `mem_perms` on a range containing SHM or MMIO nodes returns `E_INVAL`.

### §4.5 mem_shm_create(size, rights) → handle

Creates a shared memory region backed by eagerly allocated zeroed pages. **§4.5.1** `mem_shm_create` returns handle ID (positive) on success. **§4.5.2** `mem_shm_create` requires `mem_shm_create` right — returns `E_PERM` without it. **§4.5.3** `mem_shm_create` with zero size returns `E_INVAL`. **§4.5.4** `mem_shm_create` with zero rights returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion or `E_MAXCAP` when the permissions table is full.

### §4.6 mem_shm_map(shm_handle, vm_handle, offset) → result

Maps a full SHM region into a reservation at the given offset. **§4.6.1** `mem_shm_map` returns `E_OK` on success. **§4.6.2** `mem_shm_map` with invalid `shm_handle` returns `E_BADHANDLE`. **§4.6.3** `mem_shm_map` with invalid `vm_handle` returns `E_BADHANDLE`. **§4.6.4** `mem_shm_map` without `shareable` right on reservation returns `E_PERM`. **§4.6.5** `mem_shm_map` with SHM RWX exceeding reservation max returns `E_PERM`. **§4.6.6** `mem_shm_map` with non-page-aligned offset returns `E_INVAL`. **§4.6.7** `mem_shm_map` with out-of-bounds range returns `E_INVAL`. **§4.6.8** `mem_shm_map` with duplicate SHM in same reservation returns `E_INVAL`. **§4.6.9** `mem_shm_map` with committed pages in range returns `E_EXIST`.

### §4.7 mem_shm_unmap(shm_handle, vm_handle) → result

Removes an SHM mapping from a reservation. The process retains the handle. **§4.7.1** `mem_shm_unmap` returns `E_OK` on success. **§4.7.2** `mem_shm_unmap` with invalid handle returns `E_BADHANDLE`. **§4.7.3** `mem_shm_unmap` when SHM is not mapped returns `E_NOENT`. **§4.7.4** Process retains SHM handle after `mem_shm_unmap`.

### §4.8 mem_mmio_map(device_handle, vm_handle, offset) → result

Maps a device's MMIO region into a reservation. **§4.8.1** `mem_mmio_map` returns `E_OK` on success. **§4.8.2** `mem_mmio_map` with invalid `device_handle` returns `E_BADHANDLE`. **§4.8.3** `mem_mmio_map` with invalid `vm_handle` returns `E_BADHANDLE`. **§4.8.4** `mem_mmio_map` without `map` right returns `E_PERM`. **§4.8.5** `mem_mmio_map` without `mmio` right on reservation returns `E_PERM`. **§4.8.6** `mem_mmio_map` without `read` or `write` right on reservation returns `E_PERM`. **§4.8.7** `mem_mmio_map` with non-page-aligned offset returns `E_INVAL`. **§4.8.8** `mem_mmio_map` with out-of-bounds range returns `E_INVAL`. **§4.8.9** `mem_mmio_map` with duplicate device region returns `E_INVAL`. **§4.8.10** `mem_mmio_map` with non-MMIO device returns `E_INVAL`. **§4.8.11** `mem_mmio_map` with committed pages in range returns `E_EXIST`.

### §4.9 mem_mmio_unmap(device_handle, vm_handle) → result

**§4.9.1** `mem_mmio_unmap` returns `E_OK` on success. **§4.9.2** `mem_mmio_unmap` with invalid handle returns `E_BADHANDLE`. **§4.9.3** `mem_mmio_unmap` when MMIO is not mapped returns `E_NOENT`.

### §4.10 proc_create(elf_ptr, elf_len, process_rights, thread_rights, max_thread_priority) → handle

Spawns a new child process from an ELF binary. The `process_rights` parameter sets the child's slot 0 `ProcessRights`. The `thread_rights` parameter specifies the `ThreadHandleRights` the child receives for its own thread handles (its initial thread handle at slot 1, and all subsequent thread handles from `thread_create`). The `max_thread_priority` parameter sets the ceiling for thread priority in the child process. **§4.10.1** `proc_create` returns handle ID (positive) on success. **§4.10.2** `proc_create` child starts with `HANDLE_SELF` at slot 0 and its initial thread handle at slot 1 with rights = `thread_rights`. **§4.10.3** `proc_create` requires `spawn_process` right — returns `E_PERM` without it. **§4.10.4** `proc_create` with `restart` in perms without parent restart capability returns `E_PERM`. **§4.10.5** `proc_create` with invalid ELF returns `E_INVAL`. **§4.10.8** `proc_create` with invalid `elf_ptr` returns `E_BADADDR`. **§4.10.10** `proc_create` grants parent every `ProcessHandleRights` bit on the child handle except `fault_handler` (exclusive: only one process holds it for a given target, and it must be explicitly transferred via `HANDLE_SELF` cap transfer). **§4.10.11** `proc_create` with child perms exceeding parent's own process rights returns `E_PERM`. **§4.10.12** `proc_create` with `thread_rights` containing undefined bits returns `E_INVAL`. **§4.10.13** `proc_create` with `max_thread_priority` exceeding the parent's own `max_thread_priority` returns `E_PERM`. **§4.10.14** `proc_create` with an invalid `max_thread_priority` value returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion, `E_MAXCAP` when the permissions table is full, or `E_NORES` on kernel stack exhaustion.

### §4.11 thread_create(entry, arg, num_stack_pages) → handle

Creates a new thread within the calling process. **§4.11.1** `thread_create` returns the new thread's handle ID (positive u64) on success. **§4.11.2** `thread_create` requires `spawn_thread` right — returns `E_PERM` without it. **§4.11.3** `thread_create` with invalid entry returns `E_BADADDR`. **§4.11.4** `thread_create` with zero stack pages returns `E_INVAL`. Returns `E_NOMEM` on memory exhaustion, `E_MAXTHREAD` at the thread limit, or `E_NORES` on kernel stack exhaustion.

### §4.12 thread_exit() → noreturn

**§4.12.1** `thread_exit` terminates the calling thread (does not return). **§4.12.2** `thread_exit` of the last thread triggers process exit.

### §4.13 thread_yield() → result

**§4.13.1** `thread_yield` returns `E_OK`.

### §4.14 set_affinity(core_mask) → result

Sets the calling thread's core affinity. Self-only; no thread handle parameter. **§4.14.1** `set_affinity` returns `E_OK` on success. **§4.14.2** `set_affinity` requires `ProcessRights.set_affinity` on slot 0; returns `E_PERM` if absent. **§4.14.3** `set_affinity` with empty mask returns `E_INVAL`. **§4.14.4** `set_affinity` with invalid core IDs returns `E_INVAL`. **§4.14.5** `set_affinity` returns `E_BUSY` if the calling thread is currently pinned.

### §4.15 set_priority(priority) → result

Sets the calling thread's priority. Self-only; no thread handle parameter. **§4.15.1** `set_priority` requires `ProcessRights.set_affinity` on slot 0; returns `E_PERM` if absent. **§4.15.2** `set_priority` with a priority exceeding the process's `max_thread_priority` returns `E_PERM`. **§4.15.3** For non-pinned levels, `set_priority` returns `E_OK` on success. The new priority takes effect at the next scheduling decision. **§4.15.4** For `pinned`, `set_priority` scans the calling thread's affinity mask in ascending core ID order for a core with no pinned owner; returns the `core_pin` handle ID (positive) on success. **§4.15.5** `set_priority(.pinned)` returns `E_BUSY` if all cores in the affinity mask are already owned by pinned threads. **§4.15.6** `set_priority(.pinned)` returns `E_INVAL` if the affinity mask is empty. **§4.15.7** `set_priority(.pinned)` returns `E_MAXCAP` if the permissions table is full. **§4.15.8** `set_priority` with a non-pinned level while currently pinned implicitly revokes the `core_pin` handle, restores the pre-pin affinity mask, and applies the new priority. **§4.15.9** `set_priority` with an invalid priority value returns `E_INVAL`.

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

### §4.25 mem_dma_map(device_handle, shm_handle) → dma_addr

Maps SHM into the device's IOMMU address space. Requires an IOMMU. DMA mappings are tracked per-process and automatically unmapped on exit. **§4.25.1** `mem_dma_map` returns DMA base address (positive) on success. **§4.25.2** `mem_dma_map` with invalid device handle returns `E_BADHANDLE`. **§4.25.3** `mem_dma_map` with invalid SHM handle returns `E_BADHANDLE`. **§4.25.4** `mem_dma_map` without `dma` right returns `E_PERM`. **§4.25.6** `mem_dma_map` with non-MMIO device returns `E_INVAL`. Returns `E_NORES` on DMA mapping table full. DMA mappings present contiguous addresses to the device.

### §4.26 mem_dma_unmap(device_handle, shm_handle) → result

**§4.26.1** `mem_dma_unmap` returns `E_OK` on success. **§4.26.2** `mem_dma_unmap` with invalid handle returns `E_BADHANDLE`. **§4.26.3** `mem_dma_unmap` with no mapping returns `E_NOENT`.

### §4.27 ioport_read(device_handle, port_offset, width) → value

Reads from a Port I/O device register. Width is 1, 2, or 4 bytes. **§4.27.1** `ioport_read` returns value (non-negative) on success. **§4.27.2** `ioport_read` with invalid handle returns `E_BADHANDLE`. **§4.27.3** `ioport_read` without `map` right returns `E_PERM`. **§4.27.4** `ioport_read` with bad width (not 1, 2, or 4) returns `E_INVAL`. **§4.27.5** `ioport_read` with `offset + width > port_count` returns `E_INVAL`. **§4.27.6** `ioport_read` on non-`port_io` device returns `E_INVAL`.

### §4.28 ioport_write(device_handle, port_offset, width, value) → result

Same validation as `ioport_read`. **§4.28.1** `ioport_write` returns `E_OK` on success. **§4.28.2** `ioport_write` with invalid handle returns `E_BADHANDLE`. **§4.28.3** `ioport_write` without `map` right returns `E_PERM`. **§4.28.4** `ioport_write` with bad width returns `E_INVAL`. **§4.28.5** `ioport_write` with `offset + width > port_count` returns `E_INVAL`. **§4.28.6** `ioport_write` on non-`port_io` device returns `E_INVAL`.

### §4.29 thread_self() → handle

**§4.29.1** `thread_self` returns the handle ID of the calling thread as it appears in the calling process's permissions table. No rights check required. Always succeeds with a positive u64.

### §4.30 thread_suspend(thread_handle) → result

**§4.30.1** `thread_suspend` returns `E_OK` on success. **§4.30.2** `thread_suspend` requires the `suspend` right on `thread_handle`; returns `E_PERM` without it. **§4.30.3** `thread_suspend` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.30.4** `thread_suspend` on a thread in `.faulted` state returns `E_BUSY`. **§4.30.5** `thread_suspend` on a thread already in `.suspended` state returns `E_BUSY`. **§4.30.6** `thread_suspend` on a thread in `.exited` state returns `E_BADHANDLE`.

### §4.31 thread_resume(thread_handle) → result

**§4.31.1** `thread_resume` returns `E_OK` on success. **§4.31.2** `thread_resume` requires the `resume` right on `thread_handle`; returns `E_PERM` without it. **§4.31.3** `thread_resume` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.31.4** `thread_resume` on a thread not in `.suspended` state returns `E_INVAL`.

### §4.32 thread_kill(thread_handle) → result

**§4.32.1** `thread_kill` returns `E_OK` on success. **§4.32.2** `thread_kill` requires the `kill` right on `thread_handle`; returns `E_PERM` without it. **§4.32.3** `thread_kill` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.32.4** `thread_kill` on a thread in `.faulted` state returns `E_BUSY`. **§4.32.5** If the killed thread is the last non-exited thread in the process, process exit or restart proceeds per §2.6.

### §4.33 fault_recv(buf_ptr, blocking) → fault_token

**§4.33.1** `fault_recv` returns the fault token (positive u64, equal to the faulting thread's handle ID in the caller's perm table) on success and writes a `FaultMessage` to `buf_ptr`. **§4.33.2** `fault_recv` with `buf_ptr` not pointing to a writable region of at least `sizeof(FaultMessage)` bytes returns `E_BADADDR`. **§4.33.3** `fault_recv` with blocking flag set blocks when the fault box is empty. **§4.33.4** `fault_recv` with blocking flag clear returns `E_AGAIN` when the fault box is empty. **§4.33.5** `fault_recv` returns `E_BUSY` if the fault box is already in `pending_reply` state. **§4.33.6** `fault_recv` returns `E_PERM` if the calling process holds neither its own `fault_handler` ProcessRights nor `fault_handler` on any process handle.

### §4.34 fault_reply(fault_token, action, modified_regs_ptr) → result

`action` values: `FAULT_KILL` (0), `FAULT_RESUME` (1), `FAULT_RESUME_MODIFIED` (2). Flags in r14: `FAULT_EXCLUDE_NEXT`, `FAULT_EXCLUDE_PERMANENT`.

**§4.34.1** `fault_reply` returns `E_OK` on success. **§4.34.2** `fault_reply` returns `E_INVAL` if the fault box is not in `pending_reply` state, if `action` is not a valid value (0, 1, or 2), or if both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` flags are set simultaneously. **§4.34.3** `fault_reply` returns `E_NOENT` if `fault_token` does not match the currently pending thread. **§4.34.4** `fault_reply` with `FAULT_RESUME_MODIFIED` and an unreadable or insufficiently sized `modified_regs_ptr` returns `E_BADADDR`.

### §4.35 fault_read_mem(proc_handle, vaddr, buf_ptr, len) → result

**§4.35.1** `fault_read_mem` returns `E_OK` on success. **§4.35.2** `fault_read_mem` requires the `fault_handler` bit on `proc_handle`; returns `E_PERM` without it. **§4.35.3** `fault_read_mem` with invalid or wrong-type `proc_handle` returns `E_BADHANDLE`. **§4.35.4** `fault_read_mem` with `vaddr` not mapped in the target's address space returns `E_BADADDR`. **§4.35.5** `fault_read_mem` with `buf_ptr` not writable in the caller's address space returns `E_BADADDR`. **§4.35.6** `fault_read_mem` with `len` = 0 returns `E_INVAL`.

### §4.36 fault_write_mem(proc_handle, vaddr, buf_ptr, len) → result

**§4.36.1** `fault_write_mem` returns `E_OK` on success. **§4.36.2** `fault_write_mem` requires the `fault_handler` bit on `proc_handle`; returns `E_PERM` without it. **§4.36.3** `fault_write_mem` with invalid or wrong-type `proc_handle` returns `E_BADHANDLE`. **§4.36.4** `fault_write_mem` with `vaddr` not mapped in the target's address space returns `E_BADADDR`. **§4.36.5** `fault_write_mem` with `buf_ptr` not readable in the caller's address space returns `E_BADADDR`. **§4.36.6** `fault_write_mem` with `len` = 0 returns `E_INVAL`. **§4.36.7** `fault_write_mem` writes to pages mapped read-only in the target succeed; the write is performed via physmap and bypasses the target's page table permission bits.

### §4.37 fault_set_thread_mode(thread_handle, mode) → result

`mode` values: `stop_all` (0), `exclude_next` (1), `exclude_permanent` (2).

**§4.37.1** `fault_set_thread_mode` returns `E_OK` on success. **§4.37.2** `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread; returns `E_PERM` otherwise. **§4.37.3** `fault_set_thread_mode` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.37.4** `fault_set_thread_mode` with invalid `mode` value returns `E_INVAL`.

### §4.38 vm_create(vcpu_count, policy_ptr) → result

Creates a VM with the specified number of vCPUs and a static policy table. Creates vCPU threads with fixed kernel-managed entry points and inserts thread handles for all vCPUs into the calling process's permissions table with full `ThreadHandleRights`. Sets `proc.vm`.

**§4.38.1** `vm_create` returns `E_OK` on success. **§4.38.2** `vm_create` with `vcpu_count` = 0 returns `E_INVAL`. **§4.38.3** `vm_create` with `vcpu_count` exceeding `MAX_VCPUS` (64) returns `E_INVAL`. **§4.38.4** `vm_create` when the calling process already has a VM returns `E_INVAL`. **§4.38.5** `vm_create` returns `E_NODEV` if hardware virtualization is not supported. **§4.38.6** `vm_create` returns `E_MAXCAP` if the permissions table cannot fit all vCPU thread handles. **§4.38.7** `vm_create` reads an `arch.VmPolicy` struct from `policy_ptr`. Returns `E_BADADDR` if `policy_ptr` is not readable.

### §4.39 vm_destroy() → result

Destroys the calling process's VM. Kills all vCPU threads, tears down guest memory mappings, frees arch-specific virtualization structures, and clears `proc.vm`.

**§4.39.1** `vm_destroy` returns `E_OK` on success. **§4.39.2** `vm_destroy` with no VM returns `E_INVAL`. **§4.39.3** `vm_destroy` with running vCPUs returns `E_OK` and cleanly tears down the VM.

### §4.40 vm_guest_map(host_vaddr, guest_addr, size, rights) → result

Maps a host virtual memory range as guest physical memory at the specified guest address. The kernel resolves the host pages and wires them into the guest's physical address space. The VMM process retains host access to the pages.

**§4.40.1** `vm_guest_map` returns `E_OK` on success. **§4.40.2** `vm_guest_map` with zero size returns `E_INVAL`. **§4.40.3** `vm_guest_map` with non-page-aligned `guest_addr` returns `E_INVAL`. **§4.40.4** `vm_guest_map` with non-page-aligned `size` returns `E_INVAL`. **§4.40.5** `vm_guest_map` with invalid rights bits returns `E_INVAL`. **§4.40.6** `vm_guest_map` with non-page-aligned `host_vaddr` returns `E_INVAL`. **§4.40.7** `vm_guest_map` with `host_vaddr` not pointing to a valid mapped region in the caller's address space returns `E_BADADDR`. **§4.40.8** `vm_guest_map` with a guest physical region overlapping the in-kernel LAPIC page (`0xFEE00000`) or IOAPIC page (`0xFEC00000`) returns `E_INVAL`.

### §4.41 vm_recv(buf_ptr, blocking) → exit_token

Reads a VM exit from the calling process's VmExitBox. Writes a `VmExitMessage` to `buf_ptr`. Returns the exit token (vCPU thread handle ID) on success.

**§4.41.1** `vm_recv` returns the exit token (positive u64) on success. **§4.41.2** `vm_recv` with blocking flag set blocks when no exits are pending. **§4.41.3** `vm_recv` with blocking flag clear returns `E_AGAIN` when no exits are pending. **§4.41.4** `vm_recv` with `buf_ptr` not pointing to a writable region of `sizeof(VmExitMessage)` bytes returns `E_BADADDR`.

### §4.42 vm_reply(exit_token, action_ptr) → result

Resolves a pending VM exit identified by `exit_token`. `action_ptr` points to a `VmReplyAction`.

**§4.42.1** `vm_reply` returns `E_OK` on success. **§4.42.2** `vm_reply` with `exit_token` not matching any pending exit returns `E_NOENT`. **§4.42.3** `vm_reply` with `action_ptr` not readable returns `E_BADADDR`. **§4.42.4** `vm_reply` with invalid action type returns `E_INVAL`. **§4.42.5** `vm_reply` with `resume_guest` action resumes the guest with the provided guest state. The VMM is responsible for advancing RIP past the exiting instruction if needed. **§4.42.6** `vm_reply` with `resume_guest` applies modified guest state, including GPR changes, before resuming execution.

### §4.43 vm_vcpu_set_state(thread_handle, guest_state_ptr) → result

Sets the full guest register state for a vCPU. Only valid when the vCPU is in `idle` state (before `vm_vcpu_run`).

**§4.43.1** `vm_vcpu_set_state` returns `E_OK` on success. **§4.43.2** `vm_vcpu_set_state` with `thread_handle` not referring to a vCPU thread returns `E_BADHANDLE`. **§4.43.3** `vm_vcpu_set_state` when the vCPU is not in `idle` state returns `E_BUSY`. **§4.43.4** `vm_vcpu_set_state` with `guest_state_ptr` not pointing to a readable region of `sizeof(arch.GuestState)` bytes returns `E_BADADDR`.

### §4.44 vm_vcpu_get_state(thread_handle, guest_state_ptr) → result

Reads the full guest register state for a vCPU. If running, the kernel IPIs its core, suspends, snapshots, writes, and resumes.

**§4.44.1** `vm_vcpu_get_state` returns `E_OK` on success. **§4.44.2** `vm_vcpu_get_state` with `thread_handle` not referring to a vCPU thread returns `E_BADHANDLE`. **§4.44.3** `vm_vcpu_get_state` with `guest_state_ptr` not pointing to a writable region of `sizeof(arch.GuestState)` bytes returns `E_BADADDR`. **§4.44.4** `vm_vcpu_get_state` after `vm_vcpu_set_state` returns the same register values that were set.

### §4.45 vm_vcpu_run(thread_handle) → result

Transitions a vCPU from `idle` to `running`, making its thread eligible for scheduling.

**§4.45.1** `vm_vcpu_run` returns `E_OK` on success. **§4.45.2** `vm_vcpu_run` with `thread_handle` not referring to a vCPU thread returns `E_BADHANDLE`. **§4.45.3** `vm_vcpu_run` when the vCPU is not in `idle` state returns `E_BUSY`.

### §4.46 vm_vcpu_interrupt(thread_handle, interrupt_ptr) → result

Injects a virtual interrupt into a vCPU.

**§4.46.1** `vm_vcpu_interrupt` returns `E_OK` on success. **§4.46.2** `vm_vcpu_interrupt` with `thread_handle` not referring to a vCPU thread returns `E_BADHANDLE`. **§4.46.3** `vm_vcpu_interrupt` with `interrupt_ptr` not readable returns `E_BADADDR`.

### §4.47 vm_msr_passthrough(msr_num, allow_read, allow_write) → result

Configures the calling process's VM to allow the guest to RDMSR and/or WRMSR the specified MSR directly without exiting. The kernel rejects security-critical MSRs (see the MSR Passthrough subsection of §2.13).

**§4.47.1** `vm_msr_passthrough` returns `E_OK` on success. **§4.47.2** `vm_msr_passthrough` with no VM returns `E_INVAL`. **§4.47.3** `vm_msr_passthrough` with `msr_num` outside the 32-bit MSR address range returns `E_INVAL`. **§4.47.4** `vm_msr_passthrough` with an MSR in the security blocklist returns `E_PERM`.

### §4.48 vm_ioapic_assert_irq(irq_num) → result

Asserts an IRQ line on the calling process's VM's in-kernel IOAPIC and kicks any running vCPU so the new interrupt state is observed promptly (see the Userspace IRQ Assertion subsection of §2.13).

**§4.48.1** `vm_ioapic_assert_irq` returns `E_OK` on success. **§4.48.2** `vm_ioapic_assert_irq` with no VM returns `E_INVAL`. **§4.48.3** `vm_ioapic_assert_irq` with `irq_num` greater than or equal to 24 returns `E_INVAL`.

### §4.49 vm_ioapic_deassert_irq(irq_num) → result

De-asserts an IRQ line on the calling process's VM's in-kernel IOAPIC and kicks any running vCPU so the new interrupt state is observed promptly (see the Userspace IRQ Assertion subsection of §2.13).

**§4.49.1** `vm_ioapic_deassert_irq` returns `E_OK` on success. **§4.49.2** `vm_ioapic_deassert_irq` with no VM returns `E_INVAL`. **§4.49.3** `vm_ioapic_deassert_irq` with `irq_num` greater than or equal to 24 returns `E_INVAL`.

### §4.50 pmu_info(info_ptr) → result

Writes a `PmuInfo` describing the hardware PMU capabilities of the host machine into `info_ptr`. Any process may call this syscall regardless of rights — the returned information is required in order to decide whether PMU features are worth attempting.

**§4.50.1** `pmu_info` returns `E_OK` on success. **§4.50.2** `pmu_info` requires no rights and is callable by any process. **§4.50.3** `pmu_info` with `info_ptr` not pointing to a writable region of `sizeof(PmuInfo)` bytes returns `E_BADADDR`. **§4.50.4** On hardware with no supported performance counters, `pmu_info` succeeds and writes `num_counters = 0`, `supported_events = 0`, `overflow_support = false`.

### §4.51 pmu_start(thread_handle, configs_ptr, count) → result

Configures and starts PMU counters on the target thread, allocating PMU state for the thread if it has none. `configs_ptr` points to an array of `count` `PmuCounterConfig` structs; each entry maps to one hardware counter in array order.

**§4.51.1** `pmu_start` returns `E_OK` on success. **§4.51.2** `pmu_start` requires `ProcessRights.pmu` on slot 0; returns `E_PERM` without it. **§4.51.3** `pmu_start` requires the `pmu` right on `thread_handle`; returns `E_PERM` without it. **§4.51.4** `pmu_start` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.51.5** `pmu_start` with `count == 0` returns `E_INVAL`. **§4.51.6** `pmu_start` with `count` exceeding `PmuInfo.num_counters` returns `E_INVAL`. **§4.51.7** `pmu_start` with an event not set in `PmuInfo.supported_events` returns `E_INVAL`. **§4.51.8** `pmu_start` with a non-null `overflow_threshold` when `PmuInfo.overflow_support` is false returns `E_INVAL`. **§4.51.9** `pmu_start` with `configs_ptr` not pointing to a readable region of `count * sizeof(PmuCounterConfig)` bytes returns `E_BADADDR`. **§4.51.10** `pmu_start` returns `E_NOMEM` if allocation of PMU state for the target thread fails. **§4.51.11** `pmu_start` on a target thread that is not the caller and not in `.faulted` or `.suspended` state returns `E_BUSY`. A remote target must be observably stopped so the kernel can stamp its PMU state without racing the save/restore hooks on the target's core; self-profiling is always permitted regardless of thread state.

### §4.52 pmu_read(thread_handle, sample_ptr) → result

Reads the current counter values for the target thread into a `PmuSample` at `sample_ptr`. The target thread must be in `.faulted` or `.suspended` state (§2.14.11) — reading counters from a running thread is not supported.

**§4.52.1** `pmu_read` returns `E_OK` on success. **§4.52.2** `pmu_read` requires `ProcessRights.pmu` on slot 0; returns `E_PERM` without it. **§4.52.3** `pmu_read` requires the `pmu` right on `thread_handle`; returns `E_PERM` without it. **§4.52.4** `pmu_read` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.52.5** `pmu_read` on a thread that is not in `.faulted` or `.suspended` state returns `E_BUSY`. **§4.52.6** `pmu_read` on a thread that has no PMU state (no prior `pmu_start`) returns `E_INVAL`. **§4.52.7** `pmu_read` with `sample_ptr` not pointing to a writable region of `sizeof(PmuSample)` bytes returns `E_BADADDR`. **§4.52.8** Counter entries beyond `PmuInfo.num_counters` in the returned `PmuSample` are zero.

### §4.53 pmu_reset(thread_handle, configs_ptr, count) → result

Resets counters and applies new overflow thresholds on the target thread. Typically called by a profiler during fault handling before replying to resume the thread after a `pmu_overflow` fault. The target thread must be in `.faulted` state — `pmu_reset` is only meaningful when the thread is suspended in fault delivery. Validation of `configs_ptr` and its contents follows the same rules as `pmu_start`.

**§4.53.1** `pmu_reset` returns `E_OK` on success. **§4.53.2** `pmu_reset` requires `ProcessRights.pmu` on slot 0; returns `E_PERM` without it. **§4.53.3** `pmu_reset` requires the `pmu` right on `thread_handle`; returns `E_PERM` without it. **§4.53.4** `pmu_reset` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.53.5** `pmu_reset` on a thread not in `.faulted` state returns `E_INVAL`. **§4.53.6** `pmu_reset` on a thread with no PMU state returns `E_INVAL`. **§4.53.7** `pmu_reset` with invalid configuration (same rules as `pmu_start`: bad `count`, unsupported event, overflow unsupported) returns `E_INVAL`. **§4.53.8** `pmu_reset` with `configs_ptr` not pointing to a readable region of `count * sizeof(PmuCounterConfig)` bytes returns `E_BADADDR`.

### §4.54 pmu_stop(thread_handle) → result

Stops counters on the target thread and frees its PMU state. A thread may always stop its own PMU state, and a thread that holds `pmu` rights on a *remote* thread may stop that thread's PMU state only while the remote thread is `.faulted` or `.suspended` — otherwise the remote core's save/restore hooks would race the state teardown. See §4.54.7.

**§4.54.1** `pmu_stop` returns `E_OK` on success. **§4.54.2** `pmu_stop` requires `ProcessRights.pmu` on slot 0; returns `E_PERM` without it. **§4.54.3** `pmu_stop` requires the `pmu` right on `thread_handle`; returns `E_PERM` without it. **§4.54.4** `pmu_stop` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`. **§4.54.5** `pmu_stop` on a thread with no PMU state (never started, or already stopped) returns `E_INVAL`. **§4.54.6** A thread's PMU state is automatically released on thread exit, so an explicit `pmu_stop` is not required before exit. **§4.54.7** `pmu_stop` on a target thread that is not the caller and not in `.faulted` or `.suspended` state returns `E_BUSY`. A remote target must be observably stopped so that clearing its PMU state does not race the save/restore hooks on the target's core; a thread may always stop its own PMU state.

### §4.55 sys_info(info_ptr, cores_ptr) → result

Writes system-wide information to `info_ptr` and, optionally, per-core information to `cores_ptr`. Any process may call this syscall regardless of rights — the returned information is purely observational and does not reveal any capability-gated state.

Typical usage is a two-call pattern: first call with `cores_ptr = null` to obtain `SysInfo` and learn `core_count`, then allocate a buffer sized for `core_count` `CoreInfo` entries and call again in a poll loop with both pointers set to obtain live per-core data. The interval between consecutive calls with `cores_ptr != null` is the accounting window over which `idle_ns` and `busy_ns` are reported (§2.15).

**§4.55.1** `sys_info` returns `E_OK` on success. **§4.55.2** `sys_info` requires no rights and is callable by any process. **§4.55.3** `sys_info` with `info_ptr` not pointing to a writable region of `sizeof(SysInfo)` bytes returns `E_BADADDR`. **§4.55.4** `sys_info` with `cores_ptr` null writes only `SysInfo`; no per-core data is written and no scheduler accounting counters are reset. **§4.55.5** `sys_info` with `cores_ptr` non-null must point to a writable region of `core_count * sizeof(CoreInfo)` bytes, where `core_count` is the value written to `info_ptr.core_count` by the same call; otherwise returns `E_BADADDR`. **§4.55.6** On success with `cores_ptr` non-null, `sys_info` writes `SysInfo` to `info_ptr` and a fully populated `CoreInfo` array to `cores_ptr`, and resets each core's `idle_ns` and `busy_ns` atomically as they are read.

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
| Thread handle rights bits | 4 (suspend, resume, kill, pmu) |
| Max vCPUs per VM | 64 |
| PMU counters per thread | `PmuInfo.num_counters` (hardware-dependent) |
| PMU counter slots in `PmuSample` | `MAX_COUNTERS` (kernel compile-time maximum across supported arches) |
| Max `SysInfo.core_count` | 64 (matches Max CPU cores) |
