# Zag Microkernel Specification

---

## 1. Scope

Zag is a microkernel. Its responsibilities are:

1. **Physical memory management** — Tracking, allocating, and freeing physical pages.
2. **Virtual memory management** — Page tables, mappings, permissions, VA reservation tracking, address space lifecycle.
3. **Execution management** — Scheduling, thread and process lifecycles.
4. **Inter-process communication** — Shared memory regions and synchronous message passing.
5. **Device access** — Enumerating devices, mapping MMIO regions, device handle return via process tree.
6. **Permission enforcement** — Capability-based access control over kernel objects.

Everything else lives in userspace.

---

## 2. Kernel Objects

### 2.1 Process

An isolated execution environment.

#### Process Tree

Processes form a tree via parent/children links. A process is a **leaf** if its children list is empty. Non-leaf processes that exit become **zombies**: address space torn down, permissions table cleaned up, but process struct, tree position, and children list persist. Zombies hold no resources. Zombies never have restart contexts (a process with a restart context restarts instead of dying, so it never reaches zombie state).

**Reference counting:** Process structs are reference-counted by the number of handle entries (`.process` or `.dead_process`) across all processes' permission tables. The struct is freed only when cleanup is complete AND the reference count reaches zero. This prevents dangling pointers when process handles are transferred via message passing.

**Device handle return:** When a device handle is returned (revoke, exit, cleanup), the kernel walks parent pointers to find the nearest ancestor that is alive and inserts the handle there. Zombies are always skipped. A process mid-restart is alive and is a valid destination. If the walk reaches root with no valid destination, the handle is dropped.

**Root service:** Created by the kernel at boot with all ProcessRights bits set — if a permission is not granted at boot, no process can ever use it. The root service may clear its own `restart` bit via `disable_restart`.

#### User Permissions View

Read-only region mapped into the process's address space, mirroring the permissions table. Sized to maximum permissions table capacity, all pages eagerly allocated at creation. The kernel updates this view on every permissions table mutation.

Each entry is 32 bytes and contains:
- `handle: u64` — monotonic ID. `U64_MAX` = empty slot.
- `type: enum { process, vm_reservation, shared_memory, device_region, core_pin, dead_process }`.
- `rights: u16`.

Type-specific fields:
- `process`: `field0` encodes `crash_reason(u5, bits 0-4) | restart_count(u16, bits 16-31)`. On first boot, field0 = 0. After a restart, crash_reason reflects the fault that triggered the restart and restart_count increments.
- `dead_process`: Same field0 encoding as `process`. This entry type replaces a `process` entry when the referenced process dies without restarting. Any handle holder may inspect the crash reason and restart count, then revoke the handle at its convenience to free the slot.
- `vm_reservation`: `start: VAddr`, `size: u64` (original range).
- `shared_memory`: `size: u64`.
- `device_region`: `field0: u64`, `field1: u64` (see §2.7 Device Region for encoding).

The user view pointer is passed to the initial thread via the `arg` register at launch.

#### User Address Space Layout and ASLR

The user address space `[0x0000_0000_0000_0000, 0xFFFF_8000_0000_0000)` is divided into two zones:

1. **Static reservation zone** — `[0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)`. Reserved for userspace `vm_reserve` calls using hint addresses. The kernel never places ELF segments or stacks in this zone. Userspace may rely on hint addresses within this zone being available (subject to overlap checks).

2. **ASLR zone** — `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)`. The kernel randomizes the base address of ELF segments and user stacks within this zone.

The first 4 KiB `[0, 0x1000)` is unmapped (null guard page). The randomized base is page-aligned.

---

### 2.2 Virtual Memory

Virtual memory is managed per-process. The observable behavior is described here; the syscall interface is in §4.

#### Rights

**VmReservationRights:** `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4). `shareable` and `mmio` are mutually exclusive.

#### vm_perms Behavior

Adjusts the effective rights on a sub-range within a VM reservation. The new rights must be RWX-only and must not exceed the reservation's max rights. Setting RWX = 0 decommits the range: pages are freed and the VA range returns to demand-paged state. Recommitting demand-pages fresh zeroed pages.

Only private regions can have their permissions changed. SHM and MMIO mapped sub-regions within a reservation cannot be modified via `vm_perms`.

#### shm_map Behavior

Maps a full shared memory region into a VM reservation at a given offset. The reservation must have the `shareable` max right. The SHM handle's RWX rights must not exceed the reservation's max RWX rights. The target range must contain only uncommitted private pages. No duplicate SharedMemory within a single reservation. SHM pages are eagerly mapped.

#### shm_unmap Behavior

Removes an SHM mapping from within a reservation. The SHM PTEs are removed and the range reverts to private with max RWX rights. The process retains its SHM handle.

#### mmio_map Behavior

Maps an MMIO device region into a VM reservation at a given offset. The reservation must have the `mmio` max right and both `read` and `write`. The device handle must have the `map` right. The target range must contain only uncommitted private pages. No duplicate DeviceRegion within a single reservation. MMIO pages are eagerly mapped with uncacheable attributes.

#### mmio_unmap Behavior

Removes an MMIO mapping from within a reservation. The MMIO PTEs are removed and the range reverts to private with max RWX rights.

---

### 2.3 Permissions

#### Handle Model

Handle = monotonic u64 ID, unique across the lifetime of the process. Handle 0 (`HANDLE_SELF`) is reserved for the process's own Process object; auto-populated at creation, not grantable, not revocable. Syscalls accept and return handles as u64 IDs.

#### Rights

**ProcessRights:** `spawn_thread`(0), `spawn_process`(1), `mem_reserve`(2), `set_affinity`(3), `restart`(4), `shm_create`(5), `device_own`(6), `pin_exclusive`(7). Stored as `u16`. ProcessRights apply only to `HANDLE_SELF` (the process's own capability).

- `restart`: can only be granted by a parent that itself has `restart`. Once cleared via `disable_restart`, cannot be re-enabled.
- `shm_create`: required to create shared memory regions.
- `device_own`: required to receive device handles via message passing. The kernel checks this on the target process during device transfer.
- `pin_exclusive`: required to pin a thread exclusively to a core, making it non-preemptible.

**ProcessHandleRights:** `send_words`(0), `send_shm`(1), `send_process`(2), `send_device`(3), `kill`(4), `grant`(5). Stored as `u16`. These rights apply to handles referencing *other* processes (not `HANDLE_SELF`). They control what operations the handle holder may perform on the target process via message passing or revoke. `proc_create` grants the parent full `ProcessHandleRights` on the child handle.

- `send_words`: can send word messages to this process.
- `send_shm`: can pass SHM handles to this process via message passing.
- `send_process`: can pass process handles to this process via message passing.
- `send_device`: can pass device handles to this process via message passing (parent→child only).
- `kill`: can trigger recursive kill of this process's subtree (via `revoke_perm`). Without this bit, revoking a process handle just drops the handle without killing.
- `grant`: can re-transfer this process handle to another process via message passing capability transfer.

**VmReservationRights:** `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4). `shareable` and `mmio` are mutually exclusive.

**SharedMemoryRights:** `read`(0), `write`(1), `execute`(2), `grant`(3).

**DeviceRegionRights:** `map`(0), `grant`(1), `dma`(2).

#### Permission Rules

1. **VM reservation handles** — acquired via `vm_reserve`. Not transferable.
2. **Shared memory handles** — acquired via `shm_create` or message passing. Transferable via message passing if `grant` bit set. Transfer creates a copy in the target.
3. **Process handles** — acquired by spawning. Transferable via message passing if `grant` bit set (§2.11). Rights use `ProcessHandleRights` encoding.
4. **Device region handles** — distributed to root service at boot. Exclusive: transfer removes from source. Parent→child only. Target must have `device_own`.
5. **Subsets only** — transferred rights must be a subset of source rights.

All capability transfer is done via message passing (§2.11). There is no dedicated grant syscall.

#### Revoke

Cannot revoke `HANDLE_SELF`. By type:
- **VM reservation:** Free all pages in range, clear slot.
- **Shared memory:** Unmap SHM PTEs within any reservation referencing this SharedMemory, revert to private. Clear slot.
- **Device region:** Unmap MMIO PTEs, return handle up process tree (§2.1 device handle return). Clear slot in source.
- **Process (with `kill` right):** Recursively kill child's entire subtree (§2.6). Clear slot.
- **Process (without `kill` right):** Drop handle only, no kill. Clear slot.

---

### 2.4 Thread

A unit of execution belonging to a Process.

#### Observable States

- **running** — actively executing on a core.
- **ready** — waiting to be scheduled.
- **blocked** — waiting on a futex or message passing operation.
- **exited** — terminated.

#### Operations

**create(entry_addr, arg: u64, num_stack_pages: u32)** — Create a new thread in the calling process. Allocates user and kernel stacks, prepares CPU context, and enqueues for scheduling.

**exit()** — Terminate the calling thread. If it is the last thread, triggers process exit.

**yield()** — Relinquish the current timeslice.

**set_affinity(core_mask)** — Set core affinity. Takes effect at next scheduling decision.

---

### 2.5 Futex

The futex mechanism allows userspace synchronization primitives (mutexes, condition variables, semaphores) to integrate with the kernel scheduler, avoiding busy-waiting.

**wait(addr, expected, timeout_ns):** Compare the 64-bit value at `addr` against `expected`. If not equal: return `E_AGAIN`. If equal: block the calling thread until woken or the timeout expires. Address must be 8-byte aligned. Timeout: 0 = try-only (return `E_TIMEOUT` immediately), `MAX_U64` = indefinite wait, any other value = block for at most `timeout_ns` nanoseconds then return `E_TIMEOUT`. Timed waiters are checked every scheduler tick (~2ms). Cross-process futexes work over shared memory (two processes mapping the same SHM can synchronize via the same address).

**wake(addr, count):** Wake up to `count` threads blocked on the physical address corresponding to `addr`. Waiters are woken in FIFO order. Returns number of threads woken.

---

### 2.6 Process Lifecycle

#### Restart

Triggered when a process with a restart context terminates for any reason (last thread exits, fault kill, parent-initiated kill).

The process remains alive throughout. Its permissions table and user view remain intact (except VM reservation entries, which are cleared). Each restart increments a restart count (`u16`, wraps to zero on overflow). The crash reason from the triggering fault is recorded in the process's user view field0.

**Persists across restart:** code/rodata/data mappings (data content reloaded from original), user permissions view, BSS region (decommitted), SHM and device handle permissions table entries, process tree position, children, restart context, message passing wait queue. If a message was delivered but not replied to, the pending caller is re-enqueued at the head of the wait queue so the restarted process can `recv` it again.

**Does not persist:** user-created VM reservations, VM reservation permissions table entries, user stacks, SHM/MMIO mappings within freed reservations, committed pages in decommitted regions, threads.

**First boot vs restart:** On first boot, only slot 0 (`HANDLE_SELF`) exists and field0 = 0. On restart, SHM and device handles persist. VM reservation handles do not. The process can detect a restart by inspecting its own slot 0 field0 — if crash_reason is non-zero or restart_count is non-zero, it has been restarted.

#### Kill

A process terminates only by: (a) last thread voluntarily exiting, (b) a fault, or (c) any handle holder with the `kill` right revoking a process handle. There is no `proc_kill` syscall.

When a process is killed by a fault, the kernel records a **crash reason** (see §3 for the mapping). If the process has a restart context, it restarts and the crash reason and incremented restart count are written to both the process's own user view (slot 0 field0) and the parent's user view entry for this child. The kernel issues a futex wake on the parent's user view field0 for this entry.

If the process does not have a restart context, it undergoes cleanup. The parent's permissions table entry is converted from `process` to `dead_process`, preserving the crash reason and restart count. The kernel issues a futex wake on the parent's user view field0. Any handle holder may inspect the crash info via its user view and revoke the handle at its convenience to free the slot. Non-parent handle holders' entries are also converted to `dead_process` when they attempt IPC to the dead process (the entry type check in `send`/`call` returns `E_BADCAP`).

**Non-recursive kill** (fault, voluntary exit): All threads are stopped and removed. If the process has a restart context, it restarts. Otherwise, it undergoes cleanup (becoming a zombie if it has children).

**Recursive kill** (handle holder with `kill` right revokes process handle): Depth-first post-order traversal of the entire subtree. For each process: stop all threads, then either restart (if restartable) or cleanup. Restartable processes get a forced restart, keeping device handles. Non-restartable processes die; device handles return up tree.

---

### 2.7 Shared Memory Region

Reference-counted physical pages, eagerly allocated. The only mechanism for ahead-of-use physical allocation.

**create(size):** Allocate and zero pages.

Shared memory is freed when the last handle holder revokes or exits.

---

### 2.8 Stack

#### User Stacks

Each user stack consists of a usable region flanked by guard pages:

1. **Underflow guard** — 1 page, unmapped.
2. **Usable region** — N pages, read-write. First page eagerly mapped, rest demand-paged.
3. **Overflow guard** — 1 page, unmapped.

Faults on guard pages kill the process with a specific crash reason: `stack_overflow` if the fault is on the guard below the usable stack (stack grew past bottom), or `stack_underflow` if the fault is on the guard above the usable stack.

---

### 2.9 Device Region

A hardware device region. Two types: **MMIO** (memory-mapped I/O, mappable into process address space) and **Port I/O** (x86 port instructions, accessed via `ioport_read`/`ioport_write` syscalls). Exclusive access is enforced by the permissions table. Handle return walks the process tree (§2.1).

#### Properties

- `device_type: enum { mmio, port_io }`.
- `device_class: enum { network, serial, storage, display, timer, usb, unknown }`.
- MMIO: `phys_base`, `size` (page-aligned).
- Port I/O: `base_port: u16`, `port_count: u16`.
- PCI metadata: `pci_vendor: u16`, `pci_device: u16`, `pci_class: u8`, `pci_subclass: u8`. Zero for non-PCI devices.

#### User View Encoding

- `field0`: `device_type(u8) | device_class(u8) << 8 | size_or_port_count(u32) << 32`.
- `field1`: `pci_vendor(u16) | pci_device(u16) << 16 | pci_class(u8) << 32 | pci_subclass(u8) << 40`.

---

### 2.10 Core Pin

A core pin object represents exclusive, non-preemptible ownership of a CPU core by a thread. Created via `pin_exclusive`, revoked via `revoke_perm`. While pinned, the scheduler skips preemption on that core — the thread runs uninterrupted until it voluntarily yields or is unpinned. Other threads are migrated off the pinned core's run queue.

**Constraints:**
- The calling thread must have single-core affinity set (exactly one bit in the mask).
- The target core must not already be pinned by another thread.
- At least one core must remain unpinned for preemptive scheduling.

**User View Encoding:**
- `field0`: `core_id` (the pinned core index).
- `field1`: `thread_tid` (the pinned thread's TID).

---

### 2.11 Message Passing

Synchronous, zero-buffered message passing between processes. Messages are transferred directly from sender registers to receiver registers with no kernel-internal queuing.

#### Register Convention

5 payload registers: `rdi`, `rsi`, `rdx`, `r8`, `r9` (in order, words 0-4). `r13` = target process handle (for `send`/`call`). `r14` = metadata flags. `rax` = syscall number (input) / status code (output). `rcx` and `r11` are reserved for future `syscall` instruction migration. Only caller-saved registers are used for payload to avoid save/restore overhead in userspace.

#### r14 Metadata Encoding

**For send/call (input):**
- bits [2:0] — word count (0-5, number of payload registers to transfer)
- bit 3 — capability transfer flag

**For recv (output, set by kernel):**
- bit 0 — 0 = message from `send`, 1 = message from `call`
- bits [3:1] — word count

**For reply (input):**
- bit 0 — atomic recv flag (reply then immediately block on recv)
- bit 1 — blocking flag for the atomic recv
- bits [4:2] — reply word count

#### Syscall Semantics

**send** — Non-blocking fire-and-forget. If the target process has a thread blocked on `recv`, the payload is copied directly from the sender's registers to the receiver's registers. Otherwise returns `E_AGAIN`. The sender continues running.

**call** — Blocking synchronous RPC. Same as `send` but the caller blocks until the receiver calls `reply`. The kernel performs a direct context switch to the receiver, giving it the caller's timeslice. If no receiver is waiting, the caller is added to the target's FIFO wait queue. Returns with the reply payload in the payload registers.

**recv** — Receive a message. If the process's wait queue has a blocked `call` sender, dequeues the first one and copies its payload. If the queue is empty, blocks (if blocking flag set) or returns `E_AGAIN` (if non-blocking). Returns `E_BUSY` if a previous message has not been replied to. Only one thread per process may be blocked on `recv` at a time; a second thread calling `recv` gets `E_BUSY`.

**reply** — Respond to a pending message. If the pending message was from a `call`, copies reply payload to the caller's registers and unblocks the caller via direct context switch. If from a `send`, clears the pending state (no one to unblock). The process must call `reply` before calling `recv` again. If the atomic recv flag is set, `reply` atomically transitions into a `recv` (reply to the current caller, then immediately wait for the next message).

#### Wait Queue

Each process has a FIFO queue of threads blocked on `call` to it. When a receiver calls `recv`, it dequeues the first waiter. The `send` syscall never queues — it returns `E_AGAIN` if no receiver is waiting.

#### Capability Transfer

When r14 bit 3 is set on `send` or `call`, the last 2 of the N payload words are interpreted as handle + rights. The kernel validates the sender's permissions and transfers the capability into the target process's permissions table at send time. The sender must have the appropriate `ProcessHandleRights` bit:
- `send_shm` for shared memory handles (validates `grant` bit, rights subset, increments refcount)
- `send_process` for process handles (inserts with `ProcessHandleRights` encoding)
- `send_device` for device handles (parent→child only, exclusive transfer — removes from sender)

#### Direct Context Switch

`call` performs a direct context switch to the receiver, and `reply` performs a direct context switch back to the caller. This makes message passing behave like a userspace syscall — the caller's timeslice is donated to the server. The kernel respects thread core affinity: if the target thread requires a different core, the kernel enqueues it on the correct core and sends an IPI to preempt that core's current thread. If all cores in the target's affinity mask have pinned threads, the syscall returns `E_BUSY`.

#### Process Death Cleanup

When a process dies, all threads in its message wait queue are unblocked with `E_NOENT`. If a caller is blocked waiting for a reply (`pending_caller`), it is also unblocked with `E_NOENT`. Back-pointers (`ipc_server` on Thread) ensure bidirectional cleanup regardless of whether the server or caller dies first.

A restarting process (`alive` remains true throughout restart) is always a valid message passing target. Messages queued in the wait list persist across restart (§2.6). IPC to a dead process (handle entry is `dead_process` type, not `process`) returns `E_BADCAP`.

---

#### Enumeration

At boot, the kernel enumerates devices (PCI bus walk, legacy serial port probing) and inserts all handles into the root service's permissions table. Kernel-internal devices (HPET, LAPIC, I/O APIC) are not exposed.

---

## 3. Page Fault Handling

### User Faults

Each fault that kills a process records a `CrashReason` (u5):

| Value | Name | Trigger |
|-------|------|---------|
| 0 | `none` | No crash (sentinel) |
| 1 | `stack_overflow` | Guard page fault below stack |
| 2 | `stack_underflow` | Guard page fault above stack |
| 3 | `invalid_read` | Read fault with no read permission |
| 4 | `invalid_write` | Write fault with no write permission |
| 5 | `invalid_execute` | Execute fault with no execute permission |
| 6 | `unmapped_access` | No VMM node for faulting address |
| 7 | `out_of_memory` | Demand page allocation failed |

Fault handling:

1. No VMM node found for the fault address: **kill** (`unmapped_access`).
2. Shared memory or MMIO region: **kill** (`invalid_read`/`invalid_write`/`invalid_execute` based on access type).
3. Private region, access type not permitted by current rights: if the faulting node is a stack guard page, **kill** (`stack_overflow` or `stack_underflow`); otherwise **kill** (`invalid_read`/`invalid_write`/`invalid_execute`).
4. Private region, access permitted: **demand-page** (allocate zeroed page, map, resume). If allocation fails: **kill** (`out_of_memory`).

Any other user-triggerable CPU exception (divide-by-zero, invalid opcode, GPF, etc.) kills the faulting process.

All user faults are non-recursive: killing a faulting process does not propagate to children.

---

## 4. Syscall API

Syscalls validate userspace inputs. All sizes and offsets must be page-aligned. Handles are `u64` monotonic IDs.

### 4.1 Error Codes

All syscalls return `i64`. Non-negative = success. Negative = error.

| Code | Value | Meaning |
|------|-------|---------|
| `E_OK` | 0 | Success. |
| `E_INVAL` | -1 | Invalid argument. |
| `E_PERM` | -2 | Permission denied. |
| `E_BADCAP` | -3 | Invalid handle. |
| `E_NOMEM` | -4 | Out of physical memory or VA space. |
| `E_MAXCAP` | -5 | Permissions table full. |
| `E_MAXTHREAD` | -6 | Thread limit reached. |
| `E_BADADDR` | -7 | Invalid virtual address. |
| `E_TIMEOUT` | -8 | Timed out. |
| `E_AGAIN` | -9 | Transient failure, retry. |
| `E_NOENT` | -10 | Entry not found. |
| `E_BUSY` | -11 | Resource already in use (e.g. core already pinned). |
| `E_EXIST` | -12 | Committed pages in range must be decommitted first. |

---

### write(ptr, len) → bytes_written

Debug serial output. Copies `len` bytes from user address `ptr` to the kernel debug console.

**Returns:** Number of bytes written (positive).
**Errors:** `E_INVAL` (len > 4096 or len == 0).

### vm_reserve(hint, size, max_perms) → handle

Reserve VA range. Creates one private region and one permissions table entry. `size` must be page-aligned and non-zero. `shareable` and `mmio` bits in `max_perms` are mutually exclusive. If `hint` is non-zero and page-aligned with no overlap, the kernel uses it; otherwise the kernel advances the VMM cursor to find a free range.

**Permission:** `HANDLE_SELF.mem_reserve`.
**Returns:** Handle ID (positive), plus vaddr via second return register.
**Errors:** `E_PERM`, `E_INVAL` (bad alignment, zero size, `shareable`/`mmio` mutual exclusion), `E_NOMEM`, `E_MAXCAP`.

### vm_perms(vm_handle, offset, size, perms) → result

Adjust effective rights on a sub-range within a VM reservation. `offset` and `size` must be page-aligned. `perms` must be RWX-only (no `shareable`/`mmio` bits) and must not exceed `max_rights`. Range `[original_start + offset, ... + size)` must be within bounds. If RWX = 0, decommit: unmap pages and free physical memory; recommitting demand-pages fresh zeroed pages. See §2.2 for full behavior.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_INVAL` (bad alignment, out of bounds, `shareable`/`mmio` bits set), `E_PERM` (exceeds `max_rights`, range contains SHM/MMIO nodes).

### shm_create(size, rights) → handle

Create shared memory. Eagerly allocates zeroed pages. `rights` specifies the SharedMemoryRights for the handle (read, write, execute, grant bits).

**Permission:** `HANDLE_SELF.shm_create`.
**Returns:** Handle ID (positive).
**Errors:** `E_PERM`, `E_INVAL`, `E_NOMEM`, `E_MAXCAP`.

### shm_map(shm_handle, vm_handle, offset) → result

Map full SHM region into reservation at the given offset. See §2.2 shm_map behavior.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM` (`shareable` missing, SHM RWX exceeds `max_rights`), `E_INVAL` (bad offset, out of bounds, duplicate SHM), `E_EXIST` (committed pages in range).

### shm_unmap(shm_handle, vm_handle) → result

Unbind SHM mapping. Process retains handle. See §2.2 shm_unmap behavior.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_NOENT`.

### mmio_map(device_handle, vm_handle, offset) → result

Map MMIO with uncacheable attributes. See §2.2 mmio_map behavior.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM` (missing `map`, `mmio`/R/W not in `max_rights`), `E_INVAL` (bad offset, out of bounds, nodes missing R/W, duplicate MMIO), `E_EXIST` (committed pages in range).

### mmio_unmap(device_handle, vm_handle) → result

Unbind MMIO mapping. See §2.2 mmio_unmap behavior.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_NOENT`.

### proc_create(elf_ptr, elf_len, perms) → handle

Spawn child. `perms` = child's slot 0 rights. Child starts with only self-handle. Only a parent with `restart` can include `restart` in child's `perms`. All ELF pages must be committed; fault on invalid pointer kills caller.

**Permission:** `HANDLE_SELF.spawn_process`.
**Returns:** Handle ID (positive).
**Errors:** `E_PERM`, `E_INVAL` (bad ELF/perms), `E_NOMEM`, `E_MAXCAP`, `E_BADADDR`.

### thread_create(entry, arg: u64, num_stack_pages: u32) → result

**Permission:** `HANDLE_SELF.spawn_thread`.
**Returns:** `E_OK`.
**Errors:** `E_PERM`, `E_INVAL` (entry not in user VA, zero stack pages), `E_NOMEM`, `E_MAXTHREAD`.

### thread_exit() → noreturn

If last thread, triggers process exit.

### thread_yield() → result

**Returns:** `E_OK`.

### set_affinity(core_mask) → result

Sets core affinity for calling thread. Yield after for immediate effect.

**Permission:** `HANDLE_SELF.set_affinity`.
**Returns:** `E_OK`.
**Errors:** `E_PERM`, `E_INVAL` (empty mask, invalid core IDs).

### pin_exclusive() → handle

Pin the calling thread exclusively to its current core. The thread becomes non-preemptible — the scheduler timer still fires (for futex expiry) but skips the context switch. Returns a core_pin handle that can be revoked to unpin.

The thread must have single-core affinity set. The target core must not already be pinned. At least one core must remain unpinned. Any other threads on the core's run queue are migrated to unpinned cores.

**Permission:** `HANDLE_SELF.pin_exclusive`.
**Returns:** Core pin handle ID (positive).
**Errors:** `E_PERM` (no `pin_exclusive` right), `E_INVAL` (no affinity set, multi-core affinity, would pin all cores), `E_BUSY` (core already pinned), `E_MAXCAP`.

### send(r13=target_handle, r14=metadata, payload regs) → status

Non-blocking message send. See §2.11 for register convention and semantics.

**Permission:** Target process handle must have `send_words` right. If capability transfer (r14 bit 3): `send_shm`, `send_process`, or `send_device` as appropriate.
**Returns:** `E_OK` (message delivered to receiver).
**Errors:** `E_BADCAP` (invalid target handle), `E_PERM` (missing rights), `E_AGAIN` (no receiver waiting), `E_MAXCAP` (capability transfer failed, target perm table full), `E_INVAL` (invalid capability transfer).

### call(r13=target_handle, r14=metadata, payload regs) → status + reply payload

Blocking synchronous RPC. See §2.11. Caller blocks until receiver replies. Direct context switch to receiver.

**Permission:** Same as `send`.
**Returns:** `E_OK` with reply payload in payload registers.
**Errors:** `E_BADCAP`, `E_PERM`, `E_NOENT` (target process died while waiting), `E_BUSY` (target's affinity cores all pinned), `E_MAXCAP`, `E_INVAL`.

### recv(r14=metadata) → status + message payload

Receive a message. r14 bit 1 = blocking flag (1 = block if no message, 0 = return immediately).

**Returns:** `E_OK` with message in payload registers and r14 set with sender metadata (send-vs-call indicator, word count).
**Errors:** `E_AGAIN` (non-blocking, no message), `E_BUSY` (pending reply not cleared, or another thread already blocked on recv).

### reply(r14=metadata, payload regs) → status

Reply to a pending message. r14 bit 0 = atomic recv flag, r14 bit 1 = blocking flag for atomic recv, r14 bits [4:2] = reply word count.

**Returns:** `E_OK`.
**Errors:** `E_INVAL` (no pending message to reply to), `E_BUSY` (atomic recv: target affinity cores all pinned).

---

### revoke_perm(handle) → result

Cannot revoke `HANDLE_SELF`. Per-type behavior (§2.3):

- **VM reservation:** Free all pages in range, clear slot.
- **SHM:** Unmap SHM PTEs, revert mapped regions to private, clear slot.
- **Device:** Unmap MMIO PTEs, return handle up process tree (§2.1 device handle return), clear slot in source.
- **Core pin:** Unpin the thread, restore preemptive scheduling on the core, clear slot.
- **Process (with `kill` right):** Recursively kill child's entire subtree (§2.6). Restartable children restart; non-restartable die. Clear slot.
- **Process (without `kill` right):** Drop handle only, no kill. Clear slot.
- **Dead process:** Clear slot (process already dead, no further cleanup needed).

**Returns:** `E_OK`.
**Errors:** `E_BADCAP` (invalid handle), `E_INVAL` (attempted `HANDLE_SELF`).

### disable_restart() → result

Permanently clear `restart` bit and free restart context for calling process and all descendants recursively. Mid-restart descendants complete before the operation proceeds.

**Permission:** Requires restart context to be present.
**Returns:** `E_OK`.
**Errors:** `E_PERM` (already cleared).

### futex_wait(addr, expected, timeout_ns) → result

Compare 64-bit value at `addr` against `expected`. If not equal: `E_AGAIN`. If equal: block until woken or timeout expires. Address must be 8-byte aligned. Timeout: 0 = try-only, `MAX_U64` = indefinite, other = nanosecond deadline. Cross-process futexes work over SHM.

**Returns:** `E_OK` (woken), `E_AGAIN` (mismatch), `E_TIMEOUT`.
**Errors:** `E_BADADDR`, `E_INVAL` (alignment).

### futex_wake(addr, count) → result

Wake up to `count` threads blocked on `addr`.

**Returns:** Number woken (non-negative).
**Errors:** `E_BADADDR`, `E_INVAL` (alignment).

### clock_gettime() → nanoseconds

**Returns:** Monotonic nanoseconds since boot.

### dma_map(device_handle, shm_handle) → dma_addr

Map all pages of a shared memory region into the device's IOMMU address space. Returns a base DMA address that the device should use in its DMA descriptors. The IOMMU translates DMA addresses to physical addresses, isolating each device's memory access. Scattered physical pages appear contiguous to the device.

**Permission:** device handle must have `dma` right, device must be MMIO type. IOMMU must be present.
**Returns:** DMA base address (positive).
**Errors:** `E_BADCAP`, `E_PERM` (no `dma` right or no IOMMU present), `E_INVAL` (device not MMIO), `E_NOMEM`.

DMA mappings are tracked per-process. On process exit, all DMA mappings are automatically unmapped from the IOMMU.

### dma_unmap(device_handle, shm_handle) → result

Remove the SHM pages from the device's IOMMU address space. Invalidates the IOMMU TLB.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM`.

### pci_enable_bus_master(device_handle) → result

Enable PCI bus mastering for the device. Sets the bus master bit in the PCI command register, allowing the device to initiate DMA transactions.

**Permission:** device handle must have `dma` right.
**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM` (no `dma` right).

### ioport_read(device_handle, port_offset, width) → value

Read from a Port I/O device. `width` must be 1 (byte), 2 (word), or 4 (dword). `port_offset + width` must not exceed `port_count`. The `map` right on the device handle governs access.

**Returns:** Value read (non-negative).
**Errors:** `E_BADCAP`, `E_PERM` (no `map` right), `E_INVAL` (bad width, bad offset, device is not port_io type).

### ioport_write(device_handle, port_offset, width, value) → result

Write to a Port I/O device. Same validation as `ioport_read`.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM`, `E_INVAL`.

---

## 5. System Limits

| Resource | Limit |
|----------|-------|
| Threads per process | 64 |
| Children per process | 64 |
| Permissions table entries | 128 |
| Devices (registry) | 128 |
| Max CPU cores | 64 |
| Max kernel stacks | 16,384 |
| SHM max size | 1 MiB (256 pages) |
| Default user stack | 16 KiB (4 pages) |
| Futex wait queue buckets | 256 |
| Futex timed waiter slots | 64 |
| User permissions view | 1 page (128 entries x 32 bytes) |
| DMA mappings per process | 16 |
