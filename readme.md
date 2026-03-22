# Zag Microkernel Specification

---

## 1. Scope

Zag is a microkernel. Its responsibilities are:

1. **Physical memory management** — Tracking, allocating, and freeing physical pages.
2. **Virtual memory management** — Page tables, mappings, permissions, VA reservation tracking, address space lifecycle.
3. **Execution management** — Scheduling, thread and process lifecycles.
4. **Inter-process communication** — Shared memory regions mappable into multiple address spaces.
5. **Device access** — Enumerating devices, mapping MMIO regions, device handle return via process tree.
6. **Permission enforcement** — Capability-based access control over kernel objects.

Everything else lives in userspace.

### Page Ownership Rule

SHM physical pages are owned by their SharedMemory object and freed only when its refcount reaches zero. MMIO physical pages are hardware regions and never freed. Unmap operations on SHM/MMIO pages only remove PTEs (`arch.unmapPage`), never free the underlying physical pages. This rule applies throughout and is not restated at each operation.

---

## 2. Kernel Objects

### 2.1 Physical Memory Manager

Kernel-internal. Not exposed to userspace.

**alloc() → PhysicalPage** — Allocate a single zeroed physical page.

**free(PhysicalPage) → void** — Return a physical page to the free pool.

---

### 2.2 Process

An isolated execution environment. Access to mutable fields is protected by a per-process lock.

#### Fields

- `addr_space_root: PAddr` — root page table physical address.
- `vmm: VMM` — virtual memory manager (§2.3).
- `perm_table: PermissionsTable` — capabilities (§2.4).
- `thread_list: List(*Thread)` — all threads belonging to this process.
- `parent: ?*Process` — null only for the root service.
- `children: List(*Process)` — child processes.
- `restart_context: ?*RestartContext` — present iff the process is restartable. Its presence is the flag that determines restartability.
- `alive: bool` — false iff `thread_list` is empty and the process has completed exit (cleanup path). Always true during restart.
- `perm_view_vaddr: VAddr` — base address of the user permissions view mapping.
- `lock: Lock` — per-process lock.

**Locking order:** Parent before child. All multi-process operations (grant, device handle return, disable_restart, recursive kill) acquire locks in parent-to-child order.

#### Process Tree

Processes form a tree via `parent`/`children`. A process is a **leaf** if its children list is empty. Only leaves can be fully freed. Non-leaf processes that exit become **zombies** (`alive = false`): address space torn down, permissions table cleaned up, but Process struct, tree position, and children list persist. Zombies hold no resources. Zombies never have restart contexts (a process with a restart context restarts instead of dying, so it never reaches `alive = false`).

**Device handle return:** When a device handle is returned (revoke, exit, cleanup), the kernel walks `parent` pointers to find the nearest ancestor that is `alive` and inserts the handle there. Zombies are always skipped. A process mid-restart keeps `alive = true` and is a valid destination. If the walk reaches root with no valid destination, the handle is dropped.

**Root service:** Created by the kernel at boot with all ProcessRights bits set — if a permission isn't granted at boot, no process can ever use it. The root service may clear its own `restart` bit via `disable_restart`.

#### User Permissions View

Read-only region mapped into the process's address space, mirroring the permissions table. Sized to maximum permissions table capacity, all pages eagerly allocated at creation. The kernel writes via physmap on every permissions table mutation.

Allocated as a kernel-internal VMM node (`handle = null`, `restart_policy = preserve`). This is separate from ELF loading — it is a kernel data structure mapped into the process, not an ELF segment.

Each entry contains:
- `handle: u64` — monotonic ID. `U64_MAX` = empty slot.
- `type: enum { process, vm_reservation, shared_memory, device_region }`.
- `rights: u8`.

Type-specific field:
- `vm_reservation`: `start: VAddr`, `size: u64` (original range).
- `shared_memory`: `size: u64`.
- `device_region`: `size: u64`.

The user view pointer is passed to the initial thread via the `arg` register at launch.

#### ELF Loading

The kernel loads ELF binaries into the process's address space. Each segment is inserted as a kernel-internal VMM node (`handle = null`):

1. **Code segment** — RX. Eagerly mapped. `restart_policy = preserve`.
2. **Read-only data segment** — R. Eagerly mapped. `restart_policy = preserve`.
3. **Data segment** — RW. Eagerly mapped. `restart_policy = preserve` (overwritten from ghost copy on restart).
4. **BSS segment** — RW. Demand-paged. `restart_policy = decommit`.

Not all segments are present in every binary. The VMM cursor is bumped past each region. All pages in `[elf_ptr, elf_ptr + elf_len)` must be committed in the calling process's address space (see §3).

#### User Address Space Layout and ASLR

The user address space `[0x0000_0000_0000_0000, 0xFFFF_8000_0000_0000)` is divided into two zones:

1. **Static reservation zone** — `[0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)`. Reserved for userspace `vm_reserve` calls using hint addresses. The kernel never places ELF segments or stacks in this zone. Userspace may rely on hint addresses within this zone being available (subject to overlap checks).

2. **ASLR zone** — `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)`. The kernel randomizes the base address of ELF segments and user stacks within this zone. The VMM cursor starts at a random page-aligned offset within the ASLR zone during process creation.

The first 4 KiB `[0, 0x1000)` is unmapped (null guard page). ASLR randomization uses a kernel PRNG seeded at boot. The randomized base is page-aligned. User stacks are allocated sequentially from the VMM cursor after ELF segments.

#### Restart Context

Allocated at process creation if `perms` includes `restart`. Contains:

- `entry_point: VAddr` — ELF entry point.
- `data_segment: { vaddr, size, ghost: []u8 }` — ghost copy of the original data segment for restoration.
- `code_range: { vaddr, size }` — code segment VA range.
- `rodata_range: { vaddr, size }` — read-only data segment VA range.
- `perm_view_range: { vaddr, size }` — user permissions view VA range.

Freed immediately and permanently when the process clears its `restart` bit. Processes without a restart context have no ELF segment tracking beyond page tables.

#### Operations

**create(elf_binary, perms: ProcessRights) → Process, Handle**
Create address space (PMM alloc root page table, `arch.copyKernelMappings`). Init VMM. Load ELF segments as kernel-internal nodes. Allocate and map user permissions view as kernel-internal node. If `perms` includes `restart`, allocate restart context. Only a parent with `restart` can grant `restart` to a child. Init permissions table with `perms` at slot 0. Create initial thread with `arg` = user view pointer. Set `alive = true`. Add to parent's children, insert process handle in parent's permissions table.

**exit(Process) → void**
Called when the last thread exits. If `restart_context` present: perform restart (§2.11). Otherwise: perform cleanup.

**Cleanup** applies only to non-restartable processes. Two phases:

**Phase 1 (always):** Set `alive = false`. Update parent's user view. VMM deinit (§2.3). Permissions table deinit (§2.4). Process is now a zombie.

**Phase 2 (leaf-only):** Remove from parent's children list, clear parent's handle and user view entry, free restart context if present, free Process struct. If parent is now a zombie leaf, recursively run Phase 2 on parent.

**kill(Process) → void**
Remove all threads from queues (§2.12), destroy stacks, deregister stack guards, then run exit logic.

---

### 2.3 Virtual Memory Manager

Per-Process. Red-black tree of variable-size VmNodes sorted by start address, no overlaps. Bump cursor for sequential allocation.

**Two-layer model:** The permissions table (§2.4) holds each reservation's capability: max rights and original range. The VMM tree holds operational state: current rights per sub-region, node type, and backing objects. Page tables are the sole source of truth for which physical pages are mapped.

#### VmNode

Each node represents a contiguous VA region with uniform type and permissions.

- `start: VAddr`, `size: u64` — page-aligned, size > 0.
- `node_type: enum { private, shared_memory, mmio }`.
- `current_rights: VmReservationRights` — for `private`: mutable via `vm_perms`, ≤ `max_rights`. For `shared_memory`: set at map time, immutable. For `mmio`: always RW.
- `handle: ?Handle` — back-reference to the owning permissions table entry. Null for kernel-internal nodes.
- `restart_policy: enum { free, decommit, preserve }` — user-created: always `free`. Kernel-internal: set at creation.

Type-specific: `shared_memory` → `shm: *SharedMemory`. `mmio` → `device: *DeviceRegion`.

**Kernel-internal nodes** are VMM tree nodes with `handle = null`. They are tracked by the VMM for address space management (fault handling, teardown, restart) but have no permissions table entry and are invisible to userspace. Examples: ELF segments, BSS, user permissions view, user stacks.

**Tree invariants:** Sorted by `start`, no overlaps. Nodes with the same non-null `handle` are contained within the reservation's original range (stored in the permissions table). SHM/MMIO nodes are always eagerly and fully mapped — faults on them are always kill.

**Merge rule:** Two adjacent nodes merge iff: both `private`, same `handle`, same `current_rights`, same `restart_policy`, contiguous. Never across reservation boundaries.

#### VMM Operations

**init(start, end) → VMM** — Set VA bounds, cursor at start, empty tree.

**insertNode(...) → VmNode** — Insert. Error if overlap.

**removeNode(VmNode) → void** — Remove from tree.

**findNode(VAddr) → VmNode?** — Find containing node.

**rangeQuery(start, size) → Iterator(VmNode)** — All nodes overlapping `[start, start + size)`.

**reserve(hint, size, max_rights) → VmNode, VAddr**
Validate `shareable`/`mmio` mutual exclusion. Hint: verify no overlap with existing nodes. No hint: advance cursor, skip existing nodes. Insert single `private` node with `current_rights = max_rights` RWX, `restart_policy = free`.

**bump(size) → VAddr** — Advance cursor (page-aligned), skip existing nodes. No tree node created. Used during process creation to position the cursor past kernel-internal nodes.

**splitNode(VmNode, split_offset) → (VmNode, VmNode)** — Split at page-aligned offset. Both halves inherit type, rights, handle, restart_policy.

#### vm_perms(handle, offset, size, new_rights)

Operates on `[original_start + offset, original_start + offset + size)` (original range from permissions table).

1. Validate: `new_rights` is RWX-only, ≤ `max_rights` RWX.
2. Range query. Every node must be `private` and belong to `handle`. Error if any SHM/MMIO node, or if range extends beyond existing nodes.
3. Split boundary nodes as needed.
4. Set `current_rights` on affected nodes.
5. Walk PTEs: `arch.updatePagePerms` for present pages. If RWX = 0 (decommit): `arch.unmapPage` + PMM free for each present PTE.
6. Merge at boundaries.

#### shm_map(shm_handle, vm_handle, offset)

1. Resolve handles. Compute range: `[original_start + offset, ... + shm.size)`.
2. Validate: `max_rights` includes `shareable`. SHM handle RWX ≤ `max_rights` RWX. Range within bounds.
3. All nodes in range must be `private`, same `handle`, no committed pages (PTE walk). No duplicate SharedMemory in reservation.
4. Split boundaries, replace with single `shared_memory` node (`current_rights = shm_rights`, `restart_policy = free`).
5. Eagerly map all SHM pages with node's `current_rights`.

#### shm_unmap(shm_handle, vm_handle)

1. Find `shared_memory` node in reservation referencing this SharedMemory. Error if not found.
2. Unmap all PTEs.
3. Replace with `private` node (`current_rights = max_rights` RWX, `restart_policy = free`). Merge with neighbors.

#### mmio_map(device_handle, vm_handle, offset)

1. Resolve handles. Compute range: `[original_start + offset, ... + device.size)`.
2. Validate: device has `map` right. `max_rights` includes `mmio`, R, and W. All affected nodes' `current_rights` include R and W. Range within bounds.
3. All nodes in range must be `private`, same `handle`, no committed pages. No duplicate DeviceRegion in reservation.
4. Split boundaries, replace with single `mmio` node (`current_rights = RW`, `restart_policy = free`).
5. Eagerly map with RW + uncacheable attributes.

#### mmio_unmap(device_handle, vm_handle)

1. Find `mmio` node in reservation referencing this DeviceRegion. Error if not found.
2. Unmap all PTEs.
3. Replace with `private` node (`current_rights = max_rights` RWX, `restart_policy = free`). Merge with neighbors.

#### resetForRestart(restart_context)

Walk all tree nodes by `restart_policy`:
- `free`: walk PTEs (`arch.unmapPage`, free private pages, unmap SHM/MMIO PTEs), remove node.
- `decommit`: walk PTEs (`arch.unmapPage`, free pages). Keep node, rights unchanged.
- `preserve`: skip (PTEs and pages left intact).

Clear all VM reservation permissions table entries (all user-created reservations are `free` and have been removed). Overwrite data segment pages in place from restart context ghost copy (data segment is `preserve`, so pages remain mapped — kernel writes via physmap). Reset cursor past last surviving node.

#### deinit(addr_space_root)

Walk tree: unmap SHM/MMIO PTEs. Then `arch.freeUserAddrSpace` (frees all remaining user pages and page tables indiscriminately — only safe in full-teardown path). Free all tree nodes.

---

### 2.4 Permissions Table

Fixed-size array of permission entries per Process. Array size is implementation-defined. The kernel writes the user permissions view (§2.2) on every mutation.

#### Rights

**ProcessRights:** `grant_to`(0), `spawn_thread`(1), `spawn_process`(2), `mem_reserve`(3), `set_affinity`(4), `restart`(5), `shm_create`(6), `device_own`(7), `shutdown`(8). Stored as `u16`.

- `restart`: can only be granted by a parent that itself has `restart`. Once cleared via `disable_restart`, cannot be re-enabled.
- `shm_create`: required to create shared memory regions.
- `device_own`: required to receive device handles via grant. The kernel checks this on the target process during device grant.
- `shutdown`: required to invoke the `shutdown` syscall. Only the root service should hold this.

**VmReservationRights:** `read`(0), `write`(1), `execute`(2), `shareable`(3), `mmio`(4). `shareable` and `mmio` are mutually exclusive.

**SharedMemoryRights:** `read`(0), `write`(1), `execute`(2), `grant`(3).

**DeviceRegionRights:** `map`(0), `grant`(1).

#### Handle Model

Handle = monotonic u64 ID from a global counter, unique across the lifetime of the process. Handle 0 (`HANDLE_SELF`) is reserved for the process's own Process object; auto-populated at creation, not grantable, not revocable. Syscalls accept and return handles as u64 IDs.

#### Permission Table Entry Types

All entries share: `handle: Handle`, `type: enum`, `rights: u8`.

**VM reservation entries** additionally store: `max_rights: VmReservationRights` (immutable ceiling), `original_start: VAddr`, `original_size: u64`. The VMM tree nodes reference the entry via `handle` and do not duplicate these fields.

**Shared memory entries** store: `shm: *SharedMemory`.

**Device region entries** store: `device: *DeviceRegion`.

**Process entries** store: `child: *Process`.

#### Permission Rules

1. **VM reservation handles** — acquired via `vm_reserve`. Not grantable.
2. **Shared memory handles** — acquired via `shm_create` or grant. Grantable if `grant` bit set. Granting increments refcount.
3. **Process handles** — acquired by spawning. Not grantable. **Revoking kills the child's entire subtree** (§2.12).
4. **Device region handles** — distributed to root service at boot. Exclusive: grant removes from parent, return walks up tree. Target must have `device_own`.
5. **Downward only** — grants go parent → child (via process handles).
6. **Subsets only** — granted rights ≤ source rights.

#### Operations

**init(Process, perms) → void** — Clear all slots (`handle = U64_MAX` sentinel), place self-handle at slot 0.

**insert(PermissionEntry) → Handle** — Find empty slot, assign next monotonic ID, insert. Error if full.

**get(Handle) → PermissionEntry?** — Lookup by ID.

**revoke(Handle) → void**
Cannot revoke `HANDLE_SELF`. By type:
- **Shared memory:** Walk VMM tree for SHM nodes referencing this SharedMemory, unmap PTEs, revert to private (`current_rights = max_rights` RWX), merge. Decrement refcount unconditionally. Clear slot.
- **Device region:** Walk VMM tree for MMIO nodes referencing this DeviceRegion, unmap PTEs, revert to private, merge. Return handle up tree (§2.2 Device Handle Return). Clear slot in source; insert in destination.
- **VM reservation:** Walk all tree nodes in `[original_start, original_start + original_size)`. Per type: private — walk PTEs, free pages; SHM — unmap PTEs; MMIO — unmap PTEs. Remove all nodes. Clear slot.
- **Process:** Recursively kill child's subtree (§2.12), clear slot.

**grant(src, target_process, granted_rights) → void**
Validate: subset of source rights, source has `grant` bit, target has `grant_to`. Device grants additionally require target has `device_own`. SHM: insert in target, increment refcount. Device: remove from source, insert in target (exclusive).

**clearByObject(Object) → void** — Clear entries pointing to given object. Used when a child is freed.

**deinit() → void** — Decrement SHM refcounts, return device handles up tree. Runs during cleanup Phase 1, after VMM deinit.

---

### 2.5 Thread

A unit of execution belonging to a Process. Access to mutable fields is protected by a per-thread lock.

#### Fields

- `process: *Process` — owning process.
- `state: enum { running, ready, blocked, exited }`.
- `user_stack: Stack` — user-mode stack (§2.9).
- `kernel_stack: Stack` — kernel-mode stack (§2.9).
- `cpu_context: *CpuContext` — saved register state on the kernel stack.
- `core_affinity: ?CoreMask` — optional core restriction.
- `prev: ?*Thread`, `next: ?*Thread` — intrusive doubly-linked list pointers. Used by both run queues (§2.6) and futex buckets (§2.7); a thread is in at most one list at a time.
- `queue_lock: ?*Lock` — pointer to the lock of whichever queue/bucket this thread is currently in. Null when not in any list.
- `futex_key: ?PAddr` — physical address this thread is waiting on. Non-null only when `state = blocked`.

#### State Transitions

| State | Location | `queue_lock` | `prev`/`next` | `futex_key` |
|---|---|---|---|---|
| `running` | On a core | null | null | null |
| `ready` | Run queue | non-null | valid | null |
| `blocked` | Futex bucket | non-null | valid | non-null |
| `exited` | Nowhere | null | null | null |

#### Operations

**create(Process, entry_addr, arg: u64, num_stack_pages: u32) → Thread** — Allocate user stack (§2.9), allocate kernel stack, prepare CPU context (`arch.prepareThreadContext`), add to process thread list, enqueue on run queue.

**exit(Thread) → void** — Remove from thread list, destroy stacks, free Thread. If last thread, trigger Process exit.

**yield(Thread) → void** — Relinquish timeslice.

**set_affinity(Thread, core_mask) → void** — Set core mask. Takes effect at next scheduling decision.

---

### 2.6 Run Queue

Per-core doubly-linked intrusive list of `ready` threads, using each thread's `prev`/`next` pointers.

**enqueue(Thread) → void** — Append to tail, set thread's `queue_lock` to this queue's lock, set state to `ready`.

**dequeue() → Thread?** — Pop from head, clear thread's queue fields, set state to `running`.

**remove(Thread) → void** — Acquire `thread.queue_lock`, unlink, clear fields. O(1).

---

### 2.7 Futex Wait Queue

Global 256-bucket hash table, allocated at boot, never resized. Per-bucket lock, no global lock. Each bucket: doubly-linked intrusive list using each thread's `prev`/`next` pointers. Multiple physical addresses may hash to the same bucket; wake matches on `futex_key`.

The futex mechanism allows userspace synchronization primitives (mutexes, condition variables, semaphores) to integrate with the kernel scheduler, avoiding busy-waiting when a thread must wait for a condition that another thread will signal.

**wait(paddr, expected, timeout_ns, Thread) → result**
Hash to bucket, acquire lock, compare `*paddr` against `expected` as a 64-bit value (read via physmap). If not equal, return `E_AGAIN`. If equal, set thread's `futex_key` and `queue_lock`, append to bucket, set state to `blocked`, deschedule. Timeout: 0 = try-only, MAX_U64 = indefinite, else = bounded. Timeout expiration is implementation-defined.

**wake(paddr, count) → num_woken**
Hash to bucket, acquire lock, scan for matching `futex_key`, unlink up to `count`, enqueue on run queues.

**remove(Thread) → void** — Acquire `thread.queue_lock`, unlink, clear fields. O(1). Used by process kill.

---

### 2.8 Shared Memory Region

Reference-counted physical pages, eagerly allocated. The only mechanism for ahead-of-use physical allocation.

**create(size) → SharedMemory** — Allocate and zero pages, refcount = 1.

**incRef() → void** — Atomic increment.

**decRef() → void** — Atomic decrement. If zero: free pages, free object.

---

### 2.9 Stack

#### User Stacks

Allocated from the Process VMM as three contiguous kernel-internal tree nodes (`handle = null`, `restart_policy = free`):

1. **Underflow guard** — 1 page, `current_rights = 0`. Never mapped.
2. **Usable region** — N pages, `current_rights = RW`. First page eagerly mapped, rest demand-paged.
3. **Overflow guard** — 1 page, `current_rights = 0`. Never mapped.

Faults on guard nodes fail the rights check → kill path. The stack guard registry (search tree keyed by `(pid, guard_vaddr)`) provides overflow/underflow diagnostics on kill.

**createUserStack(Process, num_pages) → Stack** — Insert three VMM nodes, map first usable page, register guards.

**destroyUserStack(Stack, Process) → void** — Walk PTEs in usable range, unmap/free pages, remove all three nodes, deregister guards.

#### Kernel Stacks

Single large kernel VMM reservation divided into fixed-size slots (e.g. 1 guard + 4 usable + 1 guard). Slab allocator tracks free slots. Usable pages demand-paged. Guard detection via modular arithmetic — guard hit panics.

**createKernelStack() → Stack** — Allocate slot.

**destroyKernelStack(Stack) → void** — Free committed pages, return slot.

**isKernelStackPage(VAddr) → enum { usable, guard, not_stack }** — Arithmetic check.

---

### 2.10 Timer

Kernel-internal. **read() → u64** — Monotonic nanoseconds since boot.

---

### 2.11 Process Restart

Triggered when a process with a restart context terminates for any reason (last thread exits, fault kill, parent-initiated kill).

The process keeps `alive = true` throughout. Its permissions table and user view remain intact (except VM reservation entries, cleared by `resetForRestart`). The process is a valid device handle destination at all times during restart.

**Sequence:**

1. `VMM.resetForRestart` (§2.3) — frees `free` nodes and their pages, decommits `decommit` nodes, preserves `preserve` nodes (code, rodata, data, user view). Overwrites data segment pages from ghost copy. Clears VM reservation permissions table entries.
2. Deregister all stack guard entries for this process.
3. Create new initial thread from restart context (`arg` = user view pointer).

**Persists across restart:** code/rodata/data mappings (data content reloaded), user permissions view, BSS node (decommitted), SHM and device handle permissions table entries, process tree position, children, restart context.

**Does not persist:** user-created VMM reservations and tree nodes, VM reservation permissions table entries, user stacks, SHM/MMIO nodes within freed reservations, committed pages in decommitted nodes, threads, stack guard entries.

**First boot vs restart:** On first boot, only slot 0 (`HANDLE_SELF`) exists. On restart, SHM and device handles persist. VM reservation handles do not. No explicit kernel signal — the process inspects its user view.

---

### 2.12 Process Kill

Kernel-internal. Triggered by fault handlers (non-recursive) or by a parent revoking a child's process handle (recursive).

#### Non-Recursive Kill (fault, voluntary exit)

For each thread, acquire per-thread lock, read state:

- **running:** Mark exited, IPI the core (`arch.triggerSchedulerInterrupt`) — handler switches away.
- **ready/blocked:** Acquire `thread.queue_lock`, verify state unchanged, unlink, clear fields, mark exited.
- **exited:** Skip.

After all threads removed and stacks destroyed, process exit logic runs. Children unaffected. Restartable → restart. Non-restartable → cleanup (zombie if non-leaf).

#### Recursive Kill (parent revokes child process handle)

**Depth-first post-order** traversal of entire subtree. For each process:
1. Kill all threads (same per-thread logic).
2. Destroy stacks, deregister guards.
3. If `restart_context` present: **restart** (process survives, children stay attached). Otherwise: cleanup.

Restartable processes get a forced restart, keeping device handles. Non-restartable processes die; device handles return up tree.

There is no `proc_kill` syscall. A process terminates only by: (a) last thread voluntarily exiting, (b) a fault, or (c) parent revoking its process handle.

---

### 2.13 Device Region

Physical MMIO region. No internal ownership state — exclusive access enforced by permissions table. Handle return walks the process tree (§2.2).

- `phys_base: PAddr`, `size: u64` (page-aligned).

**create(phys_base, size) → DeviceRegion** — Kernel-internal, used at boot. The kernel calls `arch.parseFirmwareTables` to enumerate devices, creates DeviceRegions, and inserts handles into the root service's permissions table.

---

## 3. Page Fault Handling

### User Faults

1. Ring 0 fault on lower-half VA (kernel reading user memory during `proc_create`): **kill**.
2. `VMM.findNode(fault_addr)` → not found: **kill path**.
3. `shared_memory` or `mmio` node: **kill path** (all pages eagerly mapped).
4. `private` node, access type not in `current_rights`: **kill path**.
5. `private` node, access permitted: demand-page (alloc zeroed page, `arch.mapPage`, resume).

**Kill path:** Check stack guard registry for `(pid, fault_addr)`. Hit → stack overflow/underflow diagnostic. Miss → access violation.

### Other User Faults

Any user-triggerable CPU exception (divide-by-zero, invalid opcode, GPF, etc.) kills the faulting process. All user faults are non-recursive.

### Kernel Faults

`isKernelStackPage(fault_addr)` → usable: demand-page. Guard: panic. Not stack: panic.

---

## 4. Syscall API

Syscalls validate userspace inputs then call kernel object operations. Object operations re-validate as defense-in-depth. All sizes and offsets must be page-aligned. Handles are `u64` monotonic IDs.

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
| `E_BUSY` | -11 | Committed pages in range must be decommitted first. |

---

### write(ptr, len) → bytes_written

Debug serial output. Copies `len` bytes from user address `ptr` to the kernel debug console.

**Returns:** Number of bytes written (positive).
**Errors:** `E_INVAL` (len > 4096 or len == 0).

### vm_reserve(hint, size, max_perms) → handle

Reserve VA range. Creates one `private` tree node and one permissions table entry. `size` must be page-aligned and non-zero. `shareable` and `mmio` bits in `max_perms` are mutually exclusive. If `hint` is non-zero and page-aligned with no overlap, the kernel uses it; otherwise the kernel advances the VMM cursor to find a free range.

**Permission:** `HANDLE_SELF.mem_reserve`.
**Returns:** Handle ID (positive), plus vaddr via second return register.
**Errors:** `E_PERM`, `E_INVAL` (bad alignment, zero size, `shareable`/`mmio` mutual exclusion), `E_NOMEM`, `E_MAXCAP`.

### vm_perms(vm_handle, offset, size, perms) → result

Adjust `current_rights` on a sub-range within a VM reservation. `offset` and `size` must be page-aligned. `perms` must be RWX-only (no `shareable`/`mmio` bits) and ≤ `max_rights`. Range `[original_start + offset, ... + size)` must be within bounds. If RWX = 0, decommit: unmap pages and free physical memory; recommitting demand-pages fresh zeroed pages. See §2.3 vm_perms for full logic.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_INVAL` (bad alignment, out of bounds, `shareable`/`mmio` bits set), `E_PERM` (exceeds `max_rights`, range contains SHM/MMIO nodes).

### shm_create(size) → handle

Create shared memory. Eagerly allocates zeroed pages.

**Permission:** `HANDLE_SELF.shm_create`.
**Returns:** Handle ID (positive).
**Errors:** `E_PERM`, `E_INVAL`, `E_NOMEM`, `E_MAXCAP`.

### shm_map(shm_handle, vm_handle, offset) → result

Map full SHM region into reservation. See §2.3 shm_map for full logic.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM` (`shareable` missing, SHM RWX exceeds `max_rights`), `E_INVAL` (bad offset, out of bounds, duplicate SHM), `E_BUSY`.

### shm_unmap(shm_handle, vm_handle) → result

Unbind SHM mapping. Process retains handle. See §2.3 shm_unmap.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_NOENT`.

### mmio_map(device_handle, vm_handle, offset) → result

Map MMIO with uncacheable attributes. See §2.3 mmio_map for full logic.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_PERM` (missing `map`, `mmio`/R/W not in `max_rights`), `E_INVAL` (bad offset, out of bounds, nodes missing R/W, duplicate MMIO), `E_BUSY`.

### mmio_unmap(device_handle, vm_handle) → result

Unbind MMIO mapping. See §2.3 mmio_unmap.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP`, `E_NOENT`.

### proc_create(elf_ptr, elf_len, perms) → handle

Spawn child. `perms` = child's slot 0 rights. Child starts with only self-handle. Only a parent with `restart` can include `restart` in child's `perms`. All ELF pages must be committed; ring 0 fault on invalid pointer kills caller.

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

### grant_perm(src_handle, target_proc_handle, granted_rights) → result

Grant a capability to a child process. `target_proc_handle` must reference a process entry with `grant_to` set. `granted_rights ⊆ src_handle.rights`. Source must have `grant` bit set.

- **SHM:** Insert copy in target, increment refcount. Source retains handle.
- **Device:** Exclusive transfer — remove from source, insert in target. Target must have `device_own`.

Only SHM and device handles are grantable. VM reservation and process handles are not grantable.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP` (invalid src or target handle, target not a process), `E_PERM` (no `grant` bit, target lacks `grant_to`, target lacks `device_own` for device grants, rights exceed source), `E_MAXCAP` (target permissions table full), `E_INVAL` (non-grantable handle type).

### revoke_perm(handle) → result

Cannot revoke `HANDLE_SELF`. Per-type behavior (§2.4):

- **VM reservation:** Free all pages in range, remove all VMM nodes, clear slot.
- **SHM:** Unmap PTEs for SHM nodes referencing this SharedMemory, revert to private, decrement refcount, clear slot.
- **Device:** Unmap MMIO PTEs, return handle up process tree (§2.2 device handle return), clear slot in source.
- **Process:** Recursively kill child's entire subtree (§2.12). Restartable children restart; non-restartable die. Clear slot.

**Returns:** `E_OK`.
**Errors:** `E_BADCAP` (invalid handle), `E_INVAL` (attempted `HANDLE_SELF`).

### disable_restart() → result

Permanently clear `restart` bit and free restart context for calling process and **all descendants recursively**. Locks acquired parent-before-child. Mid-restart descendants complete before lock is granted.

**Permission:** Requires restart context to be present.
**Returns:** `E_OK`.
**Errors:** `E_PERM` (already cleared).

### futex_wait(addr, expected, timeout_ns) → result

Resolve vaddr → paddr. Compare `*paddr` against `expected` (64-bit, via physmap). If not equal: `E_AGAIN`. If equal: block keyed by paddr. Address must be 8-byte aligned. Timeout: 0 = try-only, MAX_U64 = indefinite. Physical-address keying enables cross-process futexes over SHM.

**Returns:** `E_OK` (woken), `E_AGAIN` (mismatch), `E_TIMEOUT`.
**Errors:** `E_BADADDR`, `E_INVAL` (alignment).

### futex_wake(addr, count) → result

Wake up to `count` threads blocked on paddr.

**Returns:** Number woken (non-negative).
**Errors:** `E_BADADDR`, `E_INVAL` (alignment).

### clock_gettime() → nanoseconds

**Returns:** Monotonic nanoseconds since boot.

### shutdown() → noreturn

Immediately halt the machine. Implementation-defined mechanism (e.g. ACPI S5 on x86).

**Permission:** `HANDLE_SELF.shutdown`.
**Errors:** `E_PERM`.

---

## 5. Architecture Interface

Portable across CPU architectures. Implementations handle TLB invalidation, cache management, and register formats internally. Page size is architecture-defined (typically 4096 bytes).

### Boot

**init() → void** — Interrupt tables, segment registers, CPU features. Once on bootstrap core.

**parseFirmwareTables(firmware_table_paddr: PAddr) → void** — Parse ACPI/device tree. Discover cores, interrupt controllers, timers, devices.

**smpInit() → void** — Bring up secondary cores. Each runs `init`, then enters scheduler.

**dropIdentityMapping() → void** — Remove identity map after kernel runs in higher-half.

### Memory

**mapPage(addr_space_root, phys, virt, perms) → void** — Map page, allocate intermediate levels as needed.

**unmapPage(addr_space_root, virt) → ?PAddr** — Unmap, return paddr (or null). Caller decides whether to free.

**updatePagePerms(addr_space_root, virt, new_perms) → void** — Update PTE permissions in place.

**resolveVaddr(addr_space_root, virt) → ?PAddr** — Page table walk, return paddr or null. Pure read.

**freeUserAddrSpace(addr_space_root) → void** — Free all mapped user pages and page tables indiscriminately. Caller must remove SHM/MMIO PTEs first. Full-teardown only.

**copyKernelMappings(new_root: VAddr) → void** — Copy kernel page table entries into new address space root.

### Execution

**prepareThreadContext(kstack_top, ustack_top, entry, arg: u64) → *CpuContext** — Set up initial CPU context for scheduler to switch into.

**switchTo(Thread) → void** — Save/restore context. Swap address space if crossing process boundaries.

**swapAddrSpace(root: PAddr) → void** — Load new page table root (CR3/TTBR).

### Interrupts

**enableInterrupts() → void**

**saveAndDisableInterrupts() → u64** — Returns opaque state. Used by spinlock acquire.

**restoreInterrupts(state: u64) → void** — Used by spinlock release.

**triggerSchedulerInterrupt(core_id: u64) → void** — IPI to trigger scheduler. Self-IPI for yield, remote IPI for kill.

### Timing

**getPreemptionTimer() → Timer** — Timer for periodic scheduler preemption.

### Identification

**coreCount() → u64** — Active cores. Available after `parseFirmwareTables`.

**coreID() → u64** — Current core's ID.

### Diagnostics

**print(format, args) → void** — Debug output. May be no-op in release.
