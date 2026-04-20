# Zag Microkernel Specification v2.0

## §[scope] Scope

## §[syscall_abi] Syscall ABI

All syscalls use up to 128 virtual registers (vregs) as payload. vreg[0] is always the syscall word.

Syscall word:

```
 63                  41 40         32 31   27 26  24 23   19 18    12 11    7 6     0
┌──────────────────────┬─────────────┬───────┬──────┬───────┬────────┬───────┬───────┐
│    _reserved (23)    │ tstart (9)  │rsvd(5)│act(3)│pcnt(5)│vcnt (7)│rsvd(5)│sysn(7)│
└──────────────────────┴─────────────┴───────┴──────┴───────┴────────┴───────┴───────┘
```

| Bits | Field | Purpose |
|---|---|---|
| 0-6 | syscall_num | identifies the syscall (128 max) |
| 7-11 | _reserved | growth room for syscall_num |
| 12-18 | vreg_count | number of vregs used by this syscall (payload + port/reply_cap) |
| 19-23 | pair_count | number of transfer pair vregs (for call/reply action=transfer); pairs live at vregs [128-pair_count..127] |
| 24-26 | action | syscall-specific action or flags (e.g., reply action) |
| 27-31 | _reserved | growth room for action |
| 32-40 | tstart | kernel-filled on delivery: start slot of transferred handles in the receiver's handle table (valid iff pair_count > 0) |
| 41-63 | _reserved | general growth room |

Vregs are 128 × u64 (1 KB total). Low-numbered vregs map to architecture GPRs; the rest spill to the thread's stack. Exact arch mapping is architecture-specific. Throughout this document, `[N]` refers to vreg index N in syscall signatures.

Optional arguments are always placed at the end of the argument list. A caller may either pass the sentinel value 0 for an optional argument (requesting the default behavior) or omit its vreg entirely by setting `vreg_count` to exclude it. Omitting a vreg is equivalent to passing 0. When a syscall has multiple optional arguments, a caller that wants to specify a later optional must pass explicit 0 for any earlier optionals it is defaulting, up to the last one it is setting.

All bits documented as `_reserved` in any syscall argument, bitfield, or handle field must be 0; a syscall that receives a non-zero reserved bit returns E_INVAL.
[test] any syscall that receives a non-zero reserved bit in one of its arguments or bitfields returns E_INVAL.

[test] for any syscall with an optional argument at position N, passing vreg_count that excludes position N behaves identically to passing 0 at position N.

Unresolved design questions are inline-tagged `[open]` in the section they arise in; they represent decisions still to be made before freezing the spec.

## §[capabilities] Capabilities

An unforgeable reference to a kernel object, paired with a set bits that gate operations on that object.

| Field | Bits | Purpose |
|---|---|---|
| id | 9 | handle id (table index, 0..511) |
| _reserved | 8 | reserved |
| type | 7 | kernel object type |
| _reserved | 24 | reserved |
| capabilities | 16 | type-dependent capabilities bitfield |
| field0 | 64 | type-dependent metadata |
| field1 | 64 | type-dependent metadata |

Handle types a process can hold:

| Type | How obtained |
|---|---|
| process_self | inherent (slot 0 at process creation) |
| process (IPC-handle) | create(process); received via call/reply transfer |
| thread | create(thread); received via call/reply transfer; acquire(threads) on IPC handle |
| page_frame | issued by kernel at boot to root service; received via call/reply transfer |
| virtual_address_range | create(virtual_address_range); received via call/reply transfer; acquire(vars) on IPC handle |
| device_region | kernel-issued at boot to root service; received via call/reply transfer |
| timer | issued by kernel at boot to root service; received via call/reply transfer |
| port | create(port); received via call/reply transfer |
| reply_cap | created by recv |
| virtual_machine | create(virtual_machine) |
| event_handler | create(event_handler) |

### create

```
create(action: object_type, [1] caps: u16, ...args) -> [1] handle
  syscall_num = [create]
  action = object type (see table)
  [1] caps is always the capabilities for the new handle
  Additional args are type-specific (see table below)
  Optional args go at the end; a caller can pass fewer vregs (vreg_count
  in the syscall word) to leave trailing args at their defaults.
```

| Action | Type | Self-handle cap | Input | Output |
|---|---|---|---|---|
| 0 | process | spawn_process | [1] child_self_caps(0:15) \| returned_ipc_caps(16:31) \| child_thread_ceiling(32:47) \| child_ipc_ceiling(48:63), [2] elf_var, [3+] handles to pass | [1] ipc_handle |
| 1 | thread | spawn_thread | [1] caps, [2] entry, [3] stack_var (VAR in target's VMM, mapped rw; must be 0 if [7] vm_handle is nonzero), [4] priority (optional, default 0; must be ≤ caller's self-handle priority cap), [5] target (optional, default self; else IPC handle with spawn_thread cap; must be 0 if [7] vm_handle is nonzero), [6] target_caps (required when [5] nonzero; must be absent if [7] vm_handle is nonzero), [7] vm_handle (optional, default 0 = native; nonzero = vCPU in that VM) | [1] handle |
| 2 | virtual_address_range | mem_reserve | [1] caps, [2] pages (page_size from caps), [3] preferred_base (optional, default 0 = kernel chooses), [4] target (optional, default self; else IPC handle with mem_reserve cap), [5] target_caps (required when [4] nonzero) | [1] handle |
| 3 | port | port_create | [1] caps | [1] handle |
| 4 | virtual_machine | vm_create | [1] caps | [1] handle |
| 5 | event_handler | — | [1] caps, [2] port_handle, [3] thread_handle, [4] event_type | [1] handle |

[test] create returns E_PERM if the calling process's self-handle lacks the cap listed above for the given action.
[test] create returns E_FULL if the calling process's handle table has no free slots.

#### action=0 (process)

[test] returns E_PERM if child_self_caps is not a subset of the caller's self-handle caps.
[test] returns E_PERM if child_thread_ceiling is not a subset of the caller's thread ceiling.
[test] returns E_PERM if child_ipc_ceiling is not a subset of the caller's IPC ceiling.
[test] returns E_PERM if returned_ipc_caps is not a subset of child_ipc_ceiling.
[test] returns E_BADCAP if elf_var is not a valid VAR handle.
[test] returns E_INVAL if the ELF header is malformed.
[test] returns E_NOMEM if insufficient memory to allocate the initial thread's stacks or kernel resources.
[test] the child's handle table is initialized with self-handle at slot 0, initial thread at slot 1, passed handles at slots 2+.
[test] the child's initial thread caps are set to child_thread_ceiling.
[test] every invocation refreshes the mapcnt field of each page_frame handle passed via [3+] to reflect the current total installation count across all processes.
[test] every invocation refreshes the restart_cnt and exit fields of each process_ipc handle passed via [3+] to reflect the target process's current state.
The perms table address is passed as the first argument to the child's entry point.
Entry point is read from the ELF header.

#### action=1 (thread)

[test] returns E_PERM if caps exceeds the target process's thread ceiling.
[test] returns E_BADCAP if vm_handle is nonzero and not a valid VM handle.
[test] returns E_INVAL if vm_handle is nonzero and any of entry, stack_var, target, or target_caps is nonzero/present.
[test] returns E_BADCAP if stack_var is nonzero and not a valid VAR handle in the caller's table.
[test] returns E_INVAL if stack_var is nonzero and does not belong to the target process's VMM.
[test] returns E_INVAL if stack_var is nonzero and its mapping_type is 0.
[test] returns E_INVAL if stack_var is nonzero and any page in its mapping has effective permissions lacking read or write.
[test] returns E_BADCAP if target is nonzero and not a valid self-handle or IPC handle.
[test] returns E_PERM if target is an IPC handle lacking the spawn_thread cap.
[test] returns E_INVAL if target is nonzero and target_caps is missing.
[test] returns E_PERM if target_caps exceeds the target process's thread ceiling.
[test] returns E_INVAL if priority is greater than 7.
[test] returns E_PERM if priority exceeds the caller's self-handle priority cap.
[test] returns E_NOMEM if insufficient kernel resources.
[test] on success, the created thread's prio is set to the priority argument (default 0 if omitted).
[test] if target is a process_ipc handle, every invocation refreshes its restart_cnt and exit fields to reflect the target process's current state.

The caller must set up the thread's stack before invoking thread create: create a VAR in the target's address space (via create action=2 with target set), create or obtain page_frame(s), and map them into the VAR via the map syscall. The caller retains its stack_var handle after thread create; the target also holds its own handle (from the VAR's cross-process creation).

When target is self (or 0), a single handle with [1] caps is placed in the caller's table. When target is nonzero, a handle with [1] caps is placed in the caller's table and an additional handle with target_caps is placed in the target's table.

The thread begins execution at entry immediately after creation. If vm_handle is nonzero, the thread executes as a vCPU in guest mode within that VM's guest physical address space; entry/stack_var/target/target_caps do not apply and must be 0/absent.

#### action=2 (virtual_address_range)

[test] returns E_INVAL if pages is 0.
[test] returns E_INVAL if preferred_base is nonzero and not aligned to the page size in caps.
[test] returns E_BADCAP if target is nonzero and not a valid self-handle or IPC handle.
[test] returns E_PERM if target is an IPC handle lacking the mem_reserve cap.
[test] returns E_INVAL if target is nonzero and target_caps is missing.
[test] returns E_NOMEM if the requested range cannot be reserved.
[test] if preferred_base is nonzero and the requested range is available in the target's address space, the kernel uses preferred_base as the base address.
[test] a newly created VAR has mapping_type 0.
[test] if target is a process_ipc handle, every invocation refreshes its restart_cnt and exit fields to reflect the target process's current state.
[open] what constrains target_caps — just the caps of [1] the caller supplied, or something configurable by the ipc_handle grantor?

When target is self (or 0), a single handle with [1] caps is placed in the caller's table. When target is nonzero, a handle with [1] caps is placed in the caller's table and an additional handle with target_caps is placed in the target's table.

If preferred_base is 0, the kernel selects the base address within the target's address space.
The assigned base address is observable in the handle's field0.

#### action=3 (port)

[test] returns E_INVAL if caps does not include recv.
[test] if a port has no remaining recv-cap holders, subsequent operations on any handle to the port return E_CLOSED and the port is destroyed.

#### action=4 (virtual_machine)

[test] returns E_INVAL if copy or move bits are set in caps.
The VM is created with an empty guest physical address space.

#### action=5 (event_handler)

[test] returns E_INVAL if copy or move bits are set in [1] caps.
[test] returns E_BADCAP if [2] is not a valid port handle.
[test] returns E_PERM if [2] does not have the thread_event cap.
[test] returns E_BADCAP if [3] is not a valid thread handle.
[test] returns E_PERM if [3] does not have the set_event_handler cap.
[test] returns E_INVAL if [4] is not a valid event_type value.
[test] returns E_BUSY if an event_handler already exists for ([3], [4]).
[test] on success, a handle with [1] caps is placed in the caller's table. Events of type [4] on thread [3] are routed to port [2] through this registration.

### mutate

```
mutate([1] handle, [2] caps: u16) -> void
  syscall_num = [mutate]
  Downgrade a handle's capabilities in place. Always allowed.
  New caps must be a subset of the current caps.
```

[test] returns E_BADCAP if [1] is not a valid handle.
[test] returns E_INVAL if [2] is not a subset of the handle's current caps.
[test] the handle's capabilities are updated to [2] in place.
[test] if [1] is a page_frame handle, every invocation refreshes its mapcnt field to reflect the current total installation count across all processes.
[test] if [1] is a process_ipc handle, every invocation refreshes its restart_cnt and exit fields to reflect the target process's current state.
[test] if [1] is a thread handle, every invocation refreshes its prio field to reflect the thread's current priority.

### delete

```
delete([1] handle) -> void
  syscall_num = [delete]
  Remove a handle from the calling process's capability table.
  Side effects are type-specific (see table below).
```

| Type | Delete behavior |
|---|---|
| process_self | terminate process |
| process_ipc | remove handle |
| thread | if the thread was created by the process that created the calling thread, terminate it and remove handle; otherwise just remove handle |
| page_frame | remove handle |
| virtual_address_range | unmap and free the reserved address range, remove handle |
| device_region | unmap MMIO, remove handle |
| timer | disarm, remove handle |
| vm | destroy VM, terminate all vCPU threads, remove handle |
| reply_cap | resolve suspended thread by event type (§[fault_handling]), remove handle |
| port | decrement send/recv ref counts based on handle caps; if recv ref hits 0, suspended callers are resumed with E_CLOSED, all other suspended threads are resolved by event type (§[fault_handling]); if send ref hits 0 and no active event_handler registrations target the port, suspended receivers are resumed with E_CLOSED; remove handle |
| event_handler | tear down the registration and remove handle |

[test] returns E_BADCAP if [1] is not a valid handle.

#### process_self

[test] the calling process is terminated.

#### process_ipc

[test] the handle is removed.

#### thread

[test] if the thread was created by the process that created the calling thread, it is terminated and the handle is removed.
[test] otherwise the handle is removed without terminating the thread.

#### page_frame

[test] the handle is removed.

#### timer

[test] the timer is disarmed.
[test] the handle is removed.

#### virtual_address_range

[test] the handle is removed.
The reserved range is unmapped and any physical or IOMMU backing is freed.

#### device_region

[test] the handle is removed.
[test] any VARs in the calling process that were mapped to this device transition to mapping_type 0 (unmapped).

#### vm

[test] the handle is removed.
[test] all vCPU threads associated with the VM are terminated.

#### reply_cap

[test] the handle is removed.
[test] if the event is a call, the caller is resumed with E_REFUSED.
[test] if the event is a fault or vm exit, the suspended thread is resolved per §[fault_handling].

#### port

[test] the handle is removed.
[test] if this was the last handle to the port with recv cap, suspended callers on the port are resumed with E_CLOSED and all other suspended threads are resolved per §[fault_handling].
[test] if this was the last handle to the port with send cap and no active event_handler registrations target the port, suspended receivers on the port are resumed with E_CLOSED.

#### event_handler

[test] the handle is removed.
[test] the registration is torn down; subsequent events of this type on the thread are routed per §[fault_handling].

### revoke

```
revoke([1] handle) -> void
  syscall_num = [revoke]
  Delete this handle and all handles derived from it across all processes.
```

[test] returns E_BADCAP if [1] is not a valid handle.
[test] the handle is removed from the calling process.
[test] all handles transitively derived from this handle via copy are removed from their respective processes with the same type-specific behavior as delete.
[test] a handle that was copied and then subsequently moved is still considered a derivation of the original copy source for revoke purposes; the move does not orphan it from its copy ancestry.

Moving a handle does not create a derivation — the moved handle is the same handle, in a new holder. Consequently, a process that `move`s a handle away loses the ability to `revoke` it (revoke requires holding the handle). The original issuer of the copy that produced the now-moved handle can still revoke and will reach the moved handle through the preserved copy chain.

### sync

```
sync([1] handle) -> void
  syscall_num = [sync]
  Refresh the handle's observable state from the underlying kernel object.
```

| Type | Sync behavior |
|---|---|
| process_ipc | refresh exit_reason and restart_count |
| thread | refresh prio |
| page_frame | refresh mapcnt |
| all others | no-op |

[test] returns E_BADCAP if [1] is not a valid handle.
[test] after sync, field0 and field1 of the handle reflect the current state of the underlying object.

## §[processes] Processes

### §[process] Process

A process is an isolated virtual address space paired with a table of capability handles.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                      21 20             5 4      0
┌──────────────────────────────────────────┬────────────────┬────────┐
│              _reserved (43)              │restart_cnt (16)│exit (5)│
└──────────────────────────────────────────┴────────────────┴────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘
```

Self-handle cap (word 0, bits 48-63):

```
 15   14 13       11 10  9   8   7   6   5   4   3   2   1   0
┌───────┬───────────┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│rsv(2) │  pri(3)   │rpl│pmu│pwr│stm│vmc│prt│mrs│sth│rst│spp│cpy│
└───────┴───────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

Self-handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | allow creation of new IPC handles to this process |
| 1 | spawn_process | create child processes |
| 2 | restart | be restarted after on exit for any reason |
| 3 | spawn_thread | spawn new threads in this process |
| 4 | mem_reserve | create address space reservations |
| 5 | port_create | create ports |
| 6 | vm_create | create virtual machines |
| 7 | set_time | set the wall clock |
| 8 | power | shut down, reboot, or manage CPU power |
| 9 | pmu | use performance monitoring counters |
| 10 | reply_policy | on restart, keep outstanding reply caps valid (1) vs. drop them (0) |
| 11-13 | priority | ceiling (0-7) for setting thread priorities via the `priority` syscall |
| 14-15 | _reserved | |

#### Restart semantics

When a process with the restart cap exits for any reason (voluntary exit, fault, kill), the kernel restarts it rather than tearing it down. Threads re-enter at their original entry points, the handle table survives, and each handle is processed per its type's restart_policy bits. Reply caps held by the restarting process are governed by the process-wide reply_policy bit above.

"drop" releases this handle. If it was the last reference to the underlying object, normal refcount teardown applies (e.g. a port closes only when its last send or recv handle is released).

Policies are ordered least-to-most privileged. The restart_policy cap bits are monotonic-reducing like all caps: a holder can reduce to any value at or below the current setting, so granting "snapshot" lets a downstream reduce to preserve, decommit, or free; granting "free" permits only free.

| Handle type | Policies (low → high privilege) | Notes |
|---|---|---|
| self (process) | always preserved | the restart target itself |
| thread | 00=kill / 01=restart_at_entry / 10=persist | persist requires the thread's stack VAR to have restart_policy = preserve at restart time; if it does not, the thread is downgraded to kill |
| VAR | 00=free / 01=decommit / 10=preserve / 11=snapshot | see §[var]; snapshot requires a bound source VAR via the `snapshot` syscall. A VAR lives in exactly one process's VMM; `restart_policy` on the owning process's handle dictates what happens to the VAR state on restart. Non-owner processes' handles to the same VAR (cross-process references) are unaffected — those handles treat policy as simply drop-or-keep (the handle itself) on their own process's restart. |
| page_frame | 0=drop / 1=keep |  |
| device_region | 0=drop / 1=keep |  |
| port | 0=drop / 1=keep |  |
| timer | 00=drop / 01=disarm / 10=keep-armed / 11=_reserved | disarm keeps the handle but cancels any pending fire; value 11 is reserved, `mutate` to 11 returns E_INVAL |
| ipc_handle | 0=drop / 1=keep |  |
| VM | 0=drop / 1=keep |  |
| reply_cap | governed process-wide by reply_policy (drop: pending callers resumed with E_REFUSED; keep: reply_cap survives, caller stays suspended) | one-shot by nature |
| event_handler | 0=drop / 1=keep |  |

[open] PCID / ASID-style address space tagging (PCID on x86-64, ASID on aarch64) is not exposed. Using these avoids full TLB flushes on context switch and significantly improves context-switch performance. Candidates: kernel auto-assigns per-process and hides the mechanism (not exposed at all, but implementation-internal), or exposes a per-process tag for cross-process patterns where a tag might want to be shared.

### §[thread] Thread

A thread is a schedulable execution context.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                             2    0
┌────────────────────────────────────────────────────────────────┬─────┐
│                      _reserved (61)                            │prio │
└────────────────────────────────────────────────────────────────┴─────┘

cap (word 0, bits 48-63):
 15                        7 6      5 4    3    2    1    0
┌───────────────────────────┬────────┬────┬────┬────┬────┬────┐
│      _reserved (9)        │rst_pol │sfh │term│susp│move│copy│
└───────────────────────────┴────────┴────┴────┴────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | copy this handle to another process |
| 1 | move | move this handle to another process |
| 2 | suspend | suspend the thread |
| 3 | terminate | terminate the thread |
| 4 | set_event_handler | create an event_handler registration for this thread via `create` |
| 5-6 | restart_policy | behavior on process restart (00=kill, 01=restart_at_entry, 10=persist) |
| 7-15 | _reserved | |

prio (field1 bits 0-2): thread's port-recv wake priority (0-7). Default 0 at create. Set via the `priority` syscall; any holder of the thread handle may raise or lower, bounded by the caller's self-handle priority cap. When multiple threads are suspended in `recv` on the same port, events are delivered to the highest-priority thread first; ties break in FIFO order of suspension. A priority change takes effect on the thread's next suspension on a port — if the thread is already suspended when its priority is changed, it stays in its current priority bucket until it wakes. prio is a snapshot refreshed on every operation against the thread handle; between operations the value may be stale if another holder has changed it. Use `sync` to refresh without other side effects.

[open] TLS register setup: how does a thread's TLS base register (FS_BASE on x86-64, TPIDR_EL0 on aarch64) get set? Candidates include a new syscall (`set_tls`), embedding it in the `create` thread args, or exposing it via the event delivery ABI so the thread itself sets it after some initialization.

[open] Hardware breakpoints / watchpoints (DR0-DR7 on x86-64, DBGBCR/DBGBVR on aarch64): software breakpoints via `write` on code VARs cover instruction-breakpoints, but data watchpoints require hardware. Needs a syscall to arm/disarm a hardware debug register against a thread; the watchpoint trap itself delivers as a `breakpoint` event_type (§[event_type]).

[open] "which core is this thread running on right now" is not queryable. On x86-64 userspace can use RDTSCP/RDPID directly at CPL3, but on aarch64 MPIDR_EL1 is EL1-only, so there is no portable path. Candidates: a new syscall (`current_cpu`), a thread-local vDSO-style page, or returning current core from `self`.

[open] direct MSR / sysreg access for native threads (not vCPUs) is not exposed. `virt(passthrough)` lets a guest bypass trapping for a given sysreg, but native threads have no equivalent — PMU, power, and clock MSRs are each wrapped by their own syscall. Decide whether userspace profilers / language runtimes ever need raw RDPMC / WRMSR-style access, or whether the wrappers are sufficient.

#### self

```
self() -> [1] thread_handle
  syscall_num = [self]
  Returns the calling thread's handle.
```

[test] returns the calling thread's handle.

#### terminate

```
terminate([1] thread_handle) -> void
  syscall_num = [terminate]
  Terminate the thread referenced by the handle.
```

[test] returns E_BADCAP if [1] is not a valid thread handle.
[test] returns E_PERM if the handle does not have the terminate cap.
[test] on success, the target thread is terminated.
[test] subsequent operations on any handle to the terminated thread return E_TERM.
[test] every invocation of this syscall refreshes the thread handle's prio field to reflect the thread's current priority.

#### suspend

```
suspend([1] thread_handle, [2] port_handle) -> void
  syscall_num = [suspend]
  Suspend the thread and deliver a suspension event to the port.
```

[test] returns E_BADCAP if [1] is not a valid thread handle.
[test] returns E_BADCAP if [2] is not a valid port handle.
[test] returns E_PERM if [1] does not have the suspend cap.
[test] returns E_PERM if [2] does not have the thread_event cap.
[test] the thread is suspended and a suspension event is delivered to the port.
[test] every invocation of this syscall refreshes the thread handle's prio field to reflect the thread's current priority.

#### yield

```
yield([1] thread_handle) -> void
  syscall_num = [yield]
  Yield the current thread's timeslice.
  [1] = 0: yield to scheduler. [1] = thread handle: yield to that thread, fall back to scheduler if not runnable.
```

If [1] is 0, the scheduler selects the next thread to run.
[test] if [1] is a valid handle to a runnable thread, the target thread is scheduled next.
If the target thread is not runnable, the scheduler selects.
The calling thread's timeslice is consumed.
[test] if [1] is a valid thread handle, every invocation of this syscall refreshes its prio field to reflect the thread's current priority.

#### priority

```
priority([1] thread_handle, [2] new_priority) -> void
  syscall_num = [priority]
  Set the thread's port-recv wake priority. Bounded by the caller's
  self-handle priority cap; may raise or lower.
```

[test] returns E_BADCAP if [1] is not a valid thread handle.
[test] returns E_INVAL if [2] is greater than 7.
[test] returns E_PERM if [2] is greater than the calling process's self-handle priority cap.
[test] on success, the target thread's priority is set to [2].
[test] on success, every invocation refreshes the thread handle's prio field to reflect the new value.
[test] if the target thread is currently suspended on a port, the new priority does not move it between priority buckets; it applies to its next suspension.

#### perf

```
perf(action: op, ...) -> variable
  syscall_num = [perf]
  action = PMU operation (see table)
```

| Action | Op | Input | Output |
|---|---|---|---|
| 0 | info | — | [1] num_counters \| overflow_support, [2] supported_events bitmask |
| 1 | start | [1] thread_handle, [2+] counter configs | void |
| 2 | read | [1] thread_handle | [1..num_counters] counter values, [num_counters+1] timestamp |
| 3 | stop | [1] thread_handle | void |

[test] returns E_PERM if the calling process's self-handle does not have the pmu cap.
[test] for actions other than info, returns E_BADCAP if [1] is not a valid thread handle.

#### action=0 (info)

Returns in vregs:
- [1]: num_counters (bits 0-7) | overflow_support (bit 8) | reserved (bits 9-63)
- [2]: supported_events (64-bit bitmask)

Event bitmask bit positions:

| Bit | Event |
|---|---|
| 0 | cycles |
| 1 | instructions |
| 2 | cache_references |
| 3 | cache_misses |
| 4 | branch_instructions |
| 5 | branch_misses |
| 6 | bus_cycles |
| 7 | stalled_cycles_frontend |
| 8 | stalled_cycles_backend |

[test] [1] bits 0-7 contain num_counters.
[test] [1] bit 8 is set if the hardware supports counter overflow.
[test] [2] is a bitmask of supported events indexed by the table above.

#### action=1 (start)

Counter configs packed into vreg pairs starting at [2]. Each config is 2 qwords:
- vreg[2+2i]: event (bits 0-7) | has_threshold (bit 8) | reserved
- vreg[3+2i]: overflow_threshold (u64)

vreg_count = 2 + 2N, where N is the number of counter configs.

[test] returns E_INVAL if N is 0 or exceeds num_counters.
[test] returns E_INVAL if any config's event is not in supported_events.
[test] returns E_INVAL if any config has has_threshold=true but the hardware does not support overflow.
[test] returns E_BUSY if the target thread is not the calling thread and not in a suspended state.
[test] on success, the first N PMU counters on the target thread begin counting the configured events.
[test] every invocation of this action refreshes the thread handle's prio field to reflect the thread's current priority.

#### action=2 (read)

Returns in vregs:
- [1] through [num_counters]: counter values
- [num_counters + 1]: monotonic timestamp (ns)

[test] returns E_INVAL if PMU was not started on this thread.
[test] returns E_BUSY if the target thread is not in a suspended state.
[test] [1] through [num_counters] contain the current counter values.
[test] [num_counters + 1] contains the monotonic timestamp atomically captured with the counter values.
[test] every invocation of this action refreshes the thread handle's prio field to reflect the thread's current priority.

#### action=3 (stop)

[test] returns E_INVAL if PMU was not started on this thread.
[test] returns E_BUSY if the target thread is not the calling thread and not in a suspended state.
[test] on success, counters stop counting and PMU state is released.
[test] every invocation of this action refreshes the thread handle's prio field to reflect the thread's current priority.

[open] hardware trace features (Intel PT / ARM ETM) are not exposed. PMU-overflow sampling covers much profiling, but dense instruction-trace capture requires PT/ETM. Candidates: new `perf` actions to configure a trace buffer page_frame and start/stop a trace, then read the ring buffer from userspace.

[open] PMU overflow reply semantics are not specified. Overflow delivery is defined: it surfaces as the `pmu_overflow` event_type (§[event_type]) via the thread's `event_handler` registration. What's unpinned is the reply behavior: whether `reply` continues counting, re-arms with the original threshold, or fully resets, and whether the handler can observe/reset the counter value as part of the reply.

### §[ipc_handle] IPC Handle

An IPC handle is held by another process and defines what operations that process can perform on the target.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                      21 20             5 4      0
┌──────────────────────────────────────────┬────────────────┬────────┐
│              _reserved (43)              │restart_cnt (16)│exit (5)│
└──────────────────────────────────────────┴────────────────┴────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15  14  13 12   11   10   9    8    7    6    5    4    3    2    1    0
┌──────────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│  rsv(3)  │rstp│term│avar│acqt│stmr│svar│sprt│sthr│sdev│spro│spgf│move│copy│
└──────────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | copy this handle to another process |
| 1 | move | move this handle to another process |
| 2 | send_page_frame | transfer a page_frame handle to this process |
| 3 | send_process | transfer a process handle to this process |
| 4 | send_device | transfer a device region handle to this process |
| 5 | send_thread | transfer a thread handle to this process |
| 6 | send_port | transfer a port handle to this process |
| 7 | send_var | transfer a VAR handle to this process |
| 8 | send_timer | transfer a timer handle to this process |
| 9 | acquire_threads | request thread handles for this process's threads |
| 10 | acquire_vars | acquire VAR handles for this process |
| 11 | terminate | terminate the target process |
| 12 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 13-15 | _reserved | |

#### acquire

```
acquire(action: kind, [1] ipc_handle) -> [1+] handles
  syscall_num = [acquire]
  action = kind of acquisition (see table)
```

| Action | Kind | Input | Output |
|---|---|---|---|
| 0 | threads | [1] ipc_handle | [1+] thread handles for the target process |
| 1 | vars | [1] ipc_handle | [1+] VAR handles for the target process |

[test] returns E_BADCAP if [1] is not a valid process_ipc handle.
[test] returns E_PERM if [1] lacks the required cap for the action (acquire_threads for 0, acquire_vars for 1).
[test] every invocation refreshes the [1] ipc_handle's restart_cnt and exit fields to reflect the target process's current state.

##### action=0 (threads)

[test] on success, handles to all of the target process's threads are placed in [1+]. The number of handles returned matches the current thread count.
[test] every invocation refreshes each returned thread handle's prio field to reflect each thread's current priority.
[open] what determines the caps on returned thread handles — the thread ceiling, something configured by the ipc_handle grantor, or something else?

##### action=1 (vars)

[test] on success, handles to all of the target process's VARs are placed in [1+]. The number of handles returned matches the current VAR count.
[open] what determines the caps on returned VAR handles — the VAR's ceiling, something configured by the ipc_handle grantor, or something else?

## §[memory] Memory

### §[page_frame] Page Frame

A page frame is a handle to one physical page at a specific page size.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                   physical_address (64)                            │
└────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                            10 9       2 1      0
┌────────────────────────────────────────────────┬─────────┬────────┐
│               _reserved (54)                   │mapcnt(8)│pg_size │
└────────────────────────────────────────────────┴─────────┴────────┘

cap (word 0, bits 48-63):
 15                                    6 5    4    3    2    1    0
┌───────────────────────────────────────┬────┬────┬────┬────┬────┬────┐
│            _reserved (10)             │rstp│exec│writ│read│move│copy│
└───────────────────────────────────────┴────┴────┴────┴────┴────┴────┘
```

page_size values: 00=4K, 01=2M, 10=1G.

mapcnt is a snapshot of the total number of active installations of this physical page across all processes (CPU, DMA, and guest mappings combined). It is refreshed on every operation against the handle; between operations, use the `sync` syscall to refresh without any other side effect. The snapshot carries no guarantee between operations — another process holding a copy of the handle can map or unmap the page_frame, changing the true count. Callers that need a stable value must construct that stability themselves (e.g. by not sharing the handle, or by sharing only with processes they trust not to interfere).

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | copy this handle to another process |
| 1 | move | move this handle to another process |
| 2 | read | can be mapped with read access |
| 3 | write | can be mapped with write access |
| 4 | execute | can be mapped with execute access |
| 5 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 6-15 | _reserved | |

[open] page_frame handle management at scale: a privileged memory manager may legitimately hold thousands of page_frames, but each handle consumes a slot in a 512-entry table. Larger page sizes (2 MiB, 1 GiB) alleviate this, but on systems with many small allocations or heterogeneous hardware constraints, the manager may hit handle-table pressure. Consider introducing split/merge primitives (split a large page_frame into smaller ones; merge N contiguous same-size frames into a larger one), a range-based multi-page handle, or an expanded handle table for privileged processes. Also: how does a manager "own all physical memory" at boot without running out of slots? Does it need a different handle type (e.g. "physical-memory region") that can be iteratively consumed to produce page_frames on demand?

### §[var] Virtual Address Range

An address space reservation is a contiguous range of the process's address space that permits installing mappings to physical memory or device regions.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63            48 47  45 44 42 41  39 38  36 35                              0
┌────────────────┬──────┬─────┬──────┬──────┬─────────────────────────────────┐
│   size (16)    │rsv(3)│cp(3)│rsv(3)│mtype │         base >> 12 (36)         │
└────────────────┴──────┴─────┴──────┴──────┴─────────────────────────────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15   14 13    12 11    10 9      8 7    6    5    4    3    2    1    0
┌──────┬────────┬─────────┬────────┬────┬────┬────┬────┬────┬────┬────┬────┐
│rsv(2)│rst_pol │page_sz  │cache_ty│mmio│mx  │mw  │mr  │writ│read│move│copy│
└──────┴────────┴─────────┴────────┴────┴────┴────┴────┴────┴────┴────┴────┘
```

mapping_type values:

| Value | Meaning |
|---|---|
| 0 | unmapped (just reserved) |
| 1 | page_frame |
| 2 | mmio |
| 3 | dma |
| 4 | guest |

`cp` (curperm, 3 bits: bit 42 = read, bit 43 = write, bit 44 = execute) is the VAR's currently active permission bits. The cap bits on word 0 (`map_read` / `map_write` / `map_execute`) are the ceiling; `cp` is the tunable layer adjusted by `remap`. All installed page_frames' effective mapping permissions are the intersection of `cp` and each page_frame's ceiling caps.

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | copy this handle to another process |
| 1 | move | move this handle to another process |
| 2 | read | read bytes from this VAR via the read syscall (no mapping required) |
| 3 | write | write bytes to this VAR via the write syscall (no mapping required) |
| 4 | map_read | install read mappings |
| 5 | map_write | install write mappings |
| 6 | map_execute | install execute mappings |
| 7 | mmio | dedicates VAR to MMIO mappings (mapping_type 0→2 only); required for `map` action=1. |
| 8-9 | cache_type | cache behavior (00=cached, 01=write-combining, 10=uncached, 11=write-through) |
| 10-11 | page_size | page size of this reservation (00=4K, 01=2M, 10=1G) |
| 12-13 | restart_policy | behavior on process restart (00=free, 01=decommit, 10=preserve, 11=snapshot) |
| 14-15 | _reserved | |

Installing any mapping requires at least map_read; the kernel will not install a mapping with no read permission. map_write and map_execute are additive — a mapping's effective permissions are the intersection of the VAR's map_* caps and the source's corresponding caps.

[open] cache-line operations (CLFLUSH / DC CIVAC and friends) are not exposed. Needed for non-coherent DMA scenarios and self-modifying code cache sync on some arches. Candidates: a new syscall on a VAR with an offset+len range, or an action on `map`/`remap`.

[open] intra-process memory protection domains (x86-64 MPK / aarch64 MTE): not exposed. Useful for defense-in-depth (e.g. isolating sensitive key material within a process). Would likely add a per-VAR domain/tag field and corresponding cap bits. Deferrable.

#### map

```
map(action: kind, [1] target, ...) -> variable
  syscall_num = [map]
  action = the kind of mapping to install (see table)
  [1] target is the handle being mapped into (VAR or VM, per action)
  Additional args are action-specific (see table below)
```

| Action | Kind | [1] target | [1] gating cap(s) | Input | Output |
|---|---|---|---|---|---|
| 0 | page_frame | VAR | map_read (+ map_write/map_execute for those perms) | [2+] (offset, page_frame) pairs | void |
| 1 | mmio | VAR | mmio + map_read (+ map_write for writable MMIO) | [2] device_region | void |
| 2 | dma | VAR | map_read (+ map_write for device-writable pages) | [2] device_region, [3+] (offset, page_frame) pairs | [1] IOVA |
| 3 | guest | VM | — (VMs non-transferable) | [2+] (guest_addr, page_frame) pairs | void |

[test] returns E_BADCAP if [1] is not a valid handle of the type required by the action.
[test] returns E_PERM if [1] lacks the gating cap(s) listed above.
[test] for actions 0 and 2 (page_frame, dma), returns E_PERM if the VAR has the mmio cap set (mmio-capped VARs accept only action=1 mappings).
[test] for actions 0-2, a successful map transitions [1]'s mapping_type to the corresponding value (1=page_frame, 2=mmio, 3=dma).

##### action=0 (page_frame)

[test] returns E_INVAL if no (offset, page_frame) pairs are provided, or if the pair count is not even.
[test] returns E_BADCAP if any page_frame argument is not a valid page_frame handle.
[test] returns E_INVAL if the VAR's mapping_type is not 0 or 1 (cannot mix mapping kinds).
[test] returns E_INVAL if any offset is not aligned to the VAR's page_size.
[test] returns E_INVAL if any page_frame's page_size is smaller than the VAR's page_size.
[test] returns E_INVAL if any pair's range [offset, offset + page_frame.size) exceeds the VAR's size.
[test] returns E_INVAL if any two pairs' ranges overlap each other.
[test] returns E_INVAL if any pair's range overlaps an existing mapping in the VAR.
[test] a read from a mapped page whose effective permissions (intersection of the VAR's map_read cap and the page_frame's read cap) do not include read delivers a memory fault to the faulting thread's registered memory_fault event_handler.
[test] a write to a mapped page whose effective permissions (intersection of the VAR's map_write cap and the page_frame's write cap) do not include write delivers a memory fault to the faulting thread's registered memory_fault event_handler.
[test] instruction fetch from a mapped page whose effective permissions (intersection of the VAR's map_execute cap and the page_frame's execute cap) do not include execute delivers a memory fault to the faulting thread's registered memory_fault event_handler.
[test] accesses that match the effective permissions succeed without faulting.
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.

##### action=1 (mmio)

[test] returns E_BADCAP if [2] is not a valid device_region handle.
[test] returns E_INVAL if the VAR's mapping_type is not 0 (mmio mappings are atomic; the VAR must be unmapped).
[test] returns E_INVAL if the device_region's size does not equal the VAR's size.
[test] a write to the mapped range when the VAR does not have the map_write cap delivers a memory fault to the faulting thread's registered memory_fault event_handler.
[test] reads and writes that match the VAR's map_read/map_write caps succeed without faulting.
The installed mapping's cache behavior is taken from the VAR's cache_type caps.

##### action=2 (dma)

[test] returns E_BADCAP if [2] is not a valid device_region handle.
[test] returns E_PERM if [2] does not have the dma cap.
[test] returns E_INVAL if the (offset, page_frame) vreg count after [2] is zero or not even.
[test] returns E_BADCAP if any page_frame argument is not a valid page_frame handle.
[test] returns E_INVAL if the VAR's mapping_type is not 0 (dma mappings are atomic; the VAR must be unmapped).
[test] returns E_INVAL if any offset is not aligned to the VAR's page_size.
[test] returns E_INVAL if any page_frame's page_size is smaller than the VAR's page_size.
[test] returns E_INVAL if any pair's range [offset, offset + page_frame.size) exceeds the VAR's size.
[test] returns E_INVAL if any two pairs' ranges overlap each other.
[test] on success, the assigned IOVA is returned in [1].
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.
The per-page permissions available to the device are the intersection of the VAR's map_read/map_write caps and each page_frame's read/write caps; the IOMMU rejects device accesses outside these permissions.

##### action=3 (guest)

[test] returns E_INVAL if the (guest_addr, page_frame) vreg count after [1] is zero or not even.
[test] returns E_BADCAP if any page_frame argument is not a valid page_frame handle.
[test] returns E_INVAL if any guest_addr is not aligned to its paired page_frame's page_size.
[test] returns E_INVAL if any two pairs' ranges overlap each other.
[test] returns E_INVAL if any pair's range overlaps an existing mapping in the VM's guest physical address space.
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.
The per-page read/write/execute permissions of each installed guest mapping come directly from the paired page_frame's read/write/execute caps (no VAR involvement). Guest accesses outside these permissions trigger a guest page fault, delivered as a VM exit through the vCPU thread's registered vm_exit event_handler.

#### unmap

```
unmap(action: kind, [1] target, ...) -> void
  syscall_num = [unmap]
  action = the kind of mapping to remove (see table)
```

| Action | Kind | [1] target | Input | Effect |
|---|---|---|---|---|
| 0 | page_frame | VAR | [2+] page_frame handles | Remove each page_frame's installation from the VAR |
| 1 | mmio | VAR | [2] device_region | Remove the MMIO mapping from the VAR |
| 2 | dma | VAR | [2+] page_frame handles | Remove each page_frame's IOMMU mapping |
| 3 | guest | VM | [2+] page_frame handles | Remove each page_frame's guest physical mapping |

[test] returns E_BADCAP if [1] is not a valid handle of the type required by the action.
[test] for actions 0-2, when the VAR has no remaining installations, its mapping_type returns to 0.

##### action=0 (page_frame)

[test] returns E_INVAL if no page_frame handles are provided.
[test] returns E_BADCAP if any [2+] argument is not a valid page_frame handle.
[test] returns E_INVAL if the VAR's mapping_type is not 1 (page_frame).
[test] returns E_INVAL if any provided page_frame was not previously installed in this VAR.
[test] on success, each provided page_frame's range within the VAR is unmapped; subsequent CPU accesses to that range fault.
[test] if all page_frames previously installed in the VAR are unmapped, the VAR's mapping_type returns to 0.
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.

##### action=1 (mmio)

[test] returns E_BADCAP if [2] is not a valid device_region handle.
[test] returns E_INVAL if the VAR's mapping_type is not 2 (mmio).
[test] returns E_INVAL if the provided device_region is not the one installed in this VAR.
[test] on success, the MMIO mapping is removed and the VAR's mapping_type returns to 0; subsequent CPU accesses to the range fault.

##### action=2 (dma)

[test] returns E_INVAL if no page_frame handles are provided.
[test] returns E_BADCAP if any [2+] argument is not a valid page_frame handle.
[test] returns E_INVAL if the VAR's mapping_type is not 3 (dma).
[test] returns E_INVAL if any provided page_frame was not previously installed in this VAR's DMA mapping.
[test] if all page_frames previously installed in the VAR are removed, the VAR's mapping_type returns to 0.
On success, each provided page_frame's IOMMU entry for this VAR is removed; subsequent device accesses to the corresponding IOVA range are rejected by the IOMMU.
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.

##### action=3 (guest)

[test] returns E_INVAL if no page_frame handles are provided.
[test] returns E_BADCAP if any [2+] argument is not a valid page_frame handle.
[test] returns E_INVAL if any provided page_frame was not previously installed in the VM's guest physical address space.
[test] on success, each provided page_frame's guest physical mapping is removed; subsequent guest accesses to that range trigger a guest page fault delivered as a VM exit through the vCPU thread's registered vm_exit event_handler.
[test] every invocation of this action refreshes each provided page_frame handle's mapcnt field to reflect the current total installation count across all processes.

#### remap

```
remap([1] var_handle, [2] new_caps) -> void
  syscall_num = [remap]
  Update the VAR's current permissions (curperm) to new_caps. All installed
  page_frames' mappings now take effective permissions = intersection of
  curperm and each page_frame's ceiling caps.
```

[test] returns E_BADCAP if [1] is not a valid VAR handle.
[test] returns E_PERM if new_caps r/w/x exceed the VAR's map_read/map_write/map_execute ceiling caps.
[test] on success, the VAR's curperm field is updated to new_caps; the VAR's ceiling caps are unchanged.
[test] on success, for each page_frame installed in the VAR, the live mapping's effective permissions become the intersection of new_caps and the page_frame's ceiling caps; accesses that no longer match fault via the registered memory_fault event_handler, matching accesses succeed.

#### read

```
read([1] var_handle, [2] offset, [3] len) -> [1+] data
  syscall_num = [read]
  Read bytes from the VAR's memory. Data returned in vregs starting at [1].
```

[test] returns E_BADCAP if [1] is not a valid VAR handle.
[test] returns E_PERM if the VAR does not have the read cap.
[test] returns E_INVAL if the VAR's mapping_type is not 1 (read is only valid for page_frame-backed VARs).
[test] returns E_INVAL if len is 0.
[test] returns E_INVAL if offset + len exceeds the VAR's size.
[test] returns E_INVAL if len exceeds the vreg payload capacity (len > 127 × 8 bytes).
[test] returns E_INVAL if any page in the range is not currently backed (sparse mapping hole).
[test] on success, len bytes starting at offset are packed into vregs [1..ceil(len/8)].

#### write

```
write([1] var_handle, [2] offset, [3] len, [4+] data) -> void
  syscall_num = [write]
  Write bytes to the VAR's memory. Data packed in vregs starting at [4].
```

[test] returns E_BADCAP if [1] is not a valid VAR handle.
[test] returns E_PERM if the VAR does not have the write cap.
[test] returns E_INVAL if the VAR's mapping_type is not 1 (write is only valid for page_frame-backed VARs).
[test] returns E_INVAL if len is 0.
[test] returns E_INVAL if offset + len exceeds the VAR's size.
[test] returns E_INVAL if len exceeds the vreg payload capacity (len > 124 × 8 bytes).
[test] returns E_INVAL if any page in the range is not currently backed (sparse mapping hole).
[test] on success, len bytes from vregs [4..ceil(len/8)+3] are written to the VAR starting at offset.

#### snapshot

```
snapshot([1] var_handle, [2] snapshot_var_handle) -> void
  syscall_num = [snapshot]
  Bind a snapshot source VAR to a target VAR. On process restart, the
  kernel copies the snapshot VAR's contents into the target VAR before
  the process resumes. Calling again replaces any prior binding.
  The source's page_frames may be populated freely before restart via
  any handles. At restart time, each backing page_frame must have
  mapcnt == 1 (the source VAR is its only active installation) AND
  the source mapping must be effectively read-only (write bit clear in
  the intersection of the VAR's map_write cap and the page_frame's
  write cap) for the restore to succeed.
```

[test] returns E_BADCAP if [1] is not a valid VAR handle.
[test] returns E_BADCAP if [2] is not a valid VAR handle.
[test] returns E_INVAL if [1]'s restart_policy is not 11 (snapshot).
[test] returns E_INVAL if [2]'s restart_policy is not 10 (preserve).
[test] returns E_INVAL if [1] and [2] have different sizes.
[test] calling snapshot a second time replaces the prior binding.
[test] if the source VAR [2] is deleted before restart, the snapshot binding is cleared; on restart with no binding, the process is terminated rather than restarted.
[test] if a VAR has restart_policy=snapshot but `snapshot` was never called to bind a source, the process is terminated on restart rather than restarted.
[test] on process restart, if every page_frame backing [2] has mapcnt == 1 AND the effective write permission of the source mapping (intersection of [2]'s map_write cap and each backing page_frame's write cap) is 0, [1]'s contents are replaced by a copy of [2]'s contents before the process resumes.
[test] on process restart, if any page_frame backing [2] has mapcnt > 1, or the effective write permission of the mapping is nonzero, the restore fails and the process is terminated rather than restarted.

## §[hardware] Hardware

### §[device_region] Device Region

A device region is an exclusive grant of access to MMIO for a given device, mappable into a VM reservation with suitable capabilities.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63  62                     36 35     28 27                          0
┌────┬─────────────────────────┬────────┬─────────────────────────────┐
│irqp│     _reserved (27)      │class(8)│         size (28)           │
└────┴─────────────────────────┴────────┴─────────────────────────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                      class-dependent (64)                          │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15                                        5 4    3    2    1    0
┌───────────────────────────────────────────┬────┬────┬────┬────┬────┐
│             _reserved (11)                │rstp│irq │dma │move│copy│
└───────────────────────────────────────────┴────┴────┴────┴────┴────┘
```

Size is in 4 KB pages (max 1 TB).

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | must be 0 (device handles are move-only) |
| 1 | move | move this handle to another process |
| 2 | dma | set up DMA mappings for this device |
| 3 | irq | acknowledge interrupts from this device |
| 4 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 5-15 | _reserved | |

#### ack

```
ack([1] device_handle) -> void
  syscall_num = [ack]
  Acknowledge an IRQ from this device region, clearing the irqp bit and
  unmasking the IRQ line at the interrupt controller.
```

[test] returns E_BADCAP if [1] is not a valid device_region handle.
[test] returns E_PERM if [1] does not have the irq cap.
[test] on success, the device_region's irqp bit is cleared to 0.

#### x86-64 Port I/O Virtualization

On x86-64, `in`/`out` instructions are privileged. Rather than use IOPL or the TSS I/O permission bitmap, Zag virtualizes port I/O as MMIO and intercepts access via intentional page faults.

A `device_region` with `device_type = port_io` (base_port: u16, port_count: u16) is mapped into a VAR with the mmio right. The kernel reserves the virtual range but deliberately leaves PTEs absent, so each userspace load/store into the range page-faults into the kernel.

The page-fault handler recognizes these "virtual BAR" ranges, decodes the faulting instruction (MOV variants; 1/2/4-byte operand widths), translates the virtual address to a port number as `base_port + (fault_vaddr - bar_start)`, executes the actual `in`/`out`, writes the result back to the destination register (on reads) or commits the written value (on writes), and advances RIP past the instruction.

An 8-port device_region at base_port 0xCF8 maps into a page-aligned virtual range: load from offset 0x00 reads port 0xCF8; store to offset 0x04 writes port 0xCFC. Access size follows the instruction's operand width. Accesses outside [0, port_count) deliver a memory_fault event.

The decoder supports MOV r/m ↔ reg and MOV r/m ← imm only. IN/OUT named mnemonics, INS/OUTS, and LOCK-prefixed variants are not decoded and deliver a thread_fault (protection_fault). `write_combining` is not permitted on port_io mappings; map returns E_INVAL.

### §[timer] Timer

A timer is a handle to a per-core hardware timer that can be armed to fire at a specified deadline.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                    8 7        0
┌───────────────────────────────────────────────────────┬──────────┐
│                   _reserved (56)                      │ core_id  │
└───────────────────────────────────────────────────────┴──────────┘

word 2 (field1):
 63                                                            1  0
┌────────────────────────────────────────────────────────────────┬──┐
│                     deadline_ns (63)                           │ar│
└────────────────────────────────────────────────────────────────┴──┘

cap (word 0, bits 48-63):
 15                                                4 3      2 1    0
┌───────────────────────────────────────────────────┬────────┬────┬────┐
│                _reserved (12)                     │rst_pol │move│copy│
└───────────────────────────────────────────────────┴────────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | must be 0 (timer handles are move-only) |
| 1 | move | move this handle to another process |
| 2-3 | restart_policy | behavior on process restart (00=drop, 01=disarm, 10=keep-armed, 11=_reserved) |
| 4-15 | _reserved | |

#### arm

```
arm([1] timer_handle, [2] thread_handle, [3] deadline_ns) -> void
  syscall_num = [arm]
```

[test] returns E_BADCAP if [1] is not a valid timer handle.
[test] returns E_BADCAP if [2] is not a valid thread handle.
[test] after arm, the timer handle's field1 bit 0 is 1 and bits 1-63 contain the deadline.
[test] when the deadline is reached and the currently running thread on the timer's core is [2], the timer disarms with no effect.
[test] when the deadline is reached and the currently running thread on the timer's core is not [2] and has a `preemption` event_handler registered, the current thread is preempted and a preemption event is delivered through that registration; [2] is then scheduled on the core.
[test] when the deadline is reached and the currently running thread on the timer's core is not [2] and has no `preemption` event_handler registered, the current thread is terminated per §[fault_handling]; [2] is then scheduled on the core.
[test] on fire, the timer handle's field1 is cleared to 0.
[test] every invocation of this syscall refreshes [2]'s prio field to reflect the target thread's current priority.

A thread placed on a core whose timer may fire is responsible for having a `preemption` event_handler registered. A scheduler owning a core typically registers preemption handlers for every thread it places there; an unregistered thread preempted by a timer fire is terminated, with no recovery.

#### cancel

```
cancel([1] timer_handle) -> void
  syscall_num = [cancel]
```

[test] returns E_BADCAP if [1] is not a valid timer handle.
[test] after cancel, the timer handle's field1 is 0.
[test] the hardware timer is stopped.

## §[events] Events

Events are signals delivered to a port for a consumer thread to handle. They originate either from IPC calls (via `call`) or from thread-attributable events — faults, breakpoints, suspensions, preemption, PMU overflows, and vCPU exits — routed through `event_handler` registrations. In both cases, `recv` delivers the event on its port and produces a `reply_cap` that the handler consumes via `reply`.

### §[event_type] Event Type

event_type is a 5-bit value carried in the `ev` field of reply_caps and used as the `event_type` argument to `create(event_handler)`. It identifies the origin of a reply cap and the kind of thread event a registration routes.

| Value | Name | Description | Registerable |
|---|---|---|---|
| 0 | call | IPC call delivered by `recv` on a port receiving `call` | no |
| 1 | memory_fault | invalid read/write/execute, unmapped access, protection violation | yes |
| 2 | thread_fault | arithmetic fault, illegal instruction, alignment check, stack overflow/underflow | yes |
| 3 | breakpoint | software or hardware breakpoint trap | yes |
| 4 | suspension | explicit suspension via the `suspend` syscall | yes |
| 5 | preemption | scheduler-driven preemption on the timer's core | yes |
| 6 | vm_exit | vCPU exited guest mode (nested exit reason in payload) | yes |
| 7 | pmu_overflow | configured performance counter overflowed | yes |
| 8-31 | _reserved | | |

[test] `create(event_handler)` returns E_INVAL if event_type is 0 (call) or in the reserved range (8-31).

Sub-codes within an event_type (read vs write vs execute within memory_fault; arithmetic vs illegal_instruction vs alignment vs stack_overflow within thread_fault; the exit reason within vm_exit) are carried in the event payload, not as separate event_type values.

### §[port] Port

A port is a rendezvous between a thread-suspending event and a consumer thread that handles it.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15                                6 5    4    3    2    1    0
┌───────────────────────────────────┬────┬────┬────┬────┬────┬────┐
│           _reserved (10)          │rstp│tev │recv│send│move│copy│
└───────────────────────────────────┴────┴────┴────┴────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | copy this handle to another process |
| 1 | move | move this handle to another process |
| 2 | send | deliver events into this port |
| 3 | recv | consume events from this port |
| 4 | thread_event | port can be registered as a thread's event_handler (see §[event_type] for the registerable event types) |
| 5 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 6-15 | _reserved | |

#### call

```
call(action: kind, [1] port_handle, [2+] payload, ...) -> [2+] reply payload
  syscall_num = [call]
  action = call mode (see table)
  Suspends the calling thread and queues the call on the port. The caller
  resumes when a handler replies via the reply cap. Layout on resume
  depends on the replier's `reply` action; see `reply` below.
```

| Action | Kind | Sysword extras | Vreg layout | Effect |
|---|---|---|---|---|
| 0 | default | — | [1] port_handle, [2+] payload | Send payload to the port. |
| 1 | transfer | pair_count = N | [1] port_handle, [2+] payload, [128-N..127] N packed pair vregs | Send N handles plus optional payload atomically. Each pair vreg: bit 63 = mode (0=copy, 1=move), low bits = handle reference. |

[test] returns E_BADCAP if [1] is not a valid port handle.
[test] returns E_PERM if [1] does not have the send cap.
[test] returns E_CLOSED if the port has no remaining recv-cap holders.
[test] if the reply cap is deleted without a reply, the suspended caller is resumed with E_REFUSED.
[test] if the port loses its last recv-cap holder while the caller is suspended, the caller is resumed with E_CLOSED.
[test] if the target process restarts with reply_policy=drop, the in-flight reply cap is deleted and the caller is resumed with E_REFUSED.
[test] if the target process restarts with reply_policy=keep, the caller remains suspended; the restarted handler can still recv the call and reply.

##### action=0 (default)

[test] on resume, the reply payload vregs are placed in the caller's [2..vreg_count] and the caller is resumed; [0] is the replier's reply sysword (action=0, pair_count=0), [1] is untouched.

##### action=1 (transfer)

[test] returns E_INVAL if pair_count (N) is 0.
[test] returns E_BADCAP if any of the packed pair vregs at [128-N..127] references a handle slot that is not valid in the caller's table.
[test] returns E_PERM if any pair has mode=copy and the referenced handle lacks the copy cap, or mode=move and the handle lacks the move cap.
[test] on recv delivery, N handles are transferred: copy-mode handles are placed in the receiver's table (the caller retains its copies); move-mode handles are moved from the caller's table to the receiver's table. The receiver sees pair_count=N and tstart=S (start slot) in its [0] sysword; handles occupy contiguous slots [S, S+N).
[test] if the call fails before recv delivery (E_CLOSED, E_REFUSED), no handle transfer occurs and the caller's table is unchanged.

#### recv

```
recv([1] port_handle) -> [0] event sysword, [1] reply_cap, [2+] event payload
  syscall_num = [recv]
  Suspends the calling thread until an event arrives on the port.
```

[test] returns E_BADCAP if [1] is not a valid port handle.
[test] returns E_PERM if [1] does not have the recv cap.
[test] returns E_CLOSED if the port has no send-cap holders, no active event_handler registrations targeting it, and no pending events.
[test] when multiple threads are suspended in `recv` on the same port, events are delivered to the thread with the highest prio value first; ties break in FIFO order of suspension.
[test] on wake, [0] is the sysword from the event's source (action and pair_count reflect the source); [1] is a reply_cap handle reference; [2+] is the event payload.
[test] if the event is a call whose sender used action=0, [0].pair_count = 0 and [2+] contains the call payload.
[test] if the event is a call whose sender used action=1 (transfer) with N pairs, [0].pair_count = N and [0].tstart = S; N handles are inserted into contiguous slots [S, S+N) in the recv'er's handle table atomically before recv returns, and [2+] contains the call payload.
[test] if the event is a thread event (memory_fault, thread_fault, breakpoint, suspension, preemption, vm_exit, pmu_overflow), [0].pair_count = 0, [1] is a reply_cap, and [2+] contains register state / event-specific payload.

#### reply

```
reply(action: kind, [1] reply_cap, ...) -> void
  syscall_num = [reply]
  action = reply mode (see table)
  Resume the suspended thread. Consumes the reply cap.
```

| Action | Kind | Sysword extras | Vreg layout | Effect |
|---|---|---|---|---|
| 0 | default | — | [1] reply_cap, [2+] vregs | Resume on original core. For call events, [2+] is reply payload; for thread events, [2+] is register state. |
| 1 | place | — | [1] reply_cap, [2] timer_handle, [3+] vregs | Resume on the core identified by timer_handle, optionally with [3+] as new register state. Valid only for thread-event reply_caps. |
| 2 | transfer | pair_count = N | [1] reply_cap, [2+] payload, [128-N..127] N packed pair vregs | Resume the caller with N handles plus optional payload. Each pair vreg: bit 63 = mode (0=copy, 1=move), low bits = handle reference. Valid only for call-event reply_caps. |

[test] returns E_BADCAP if [1] is not a valid reply_cap handle.
[test] on success, the reply_cap handle is consumed (removed from the caller's handle table).

##### action=0 (default)

[test] if the event is a call, [2+] vregs are delivered to the caller as the reply payload and the caller is resumed on its original core.
[test] if the event is a thread event (memory_fault, thread_fault, breakpoint, suspension, preemption, vm_exit, pmu_overflow), [2+] vregs are written as the suspended thread's register state (subject to the originating registration's state_write cap) and the thread is resumed on its original core.

##### action=1 (place)

[test] returns E_INVAL if [1]'s event_type is `call` (place is for thread events only).
[test] returns E_BADCAP if [2] is not a valid timer_handle.
[test] on success, the suspended thread is resumed on the core identified by [2]; if [3+] vregs are provided and the originating registration has the state_write cap, they are applied as the thread's register state.

##### action=2 (transfer)

[test] returns E_INVAL if [1]'s event_type is not `call` (transfer is for call-event reply_caps only).
[test] returns E_INVAL if pair_count (N) is 0.
[test] returns E_BADCAP if any of the packed pair vregs at [128-N..127] references a handle slot that is not valid in the replier's table.
[test] returns E_PERM if any pair has mode=copy and the referenced handle lacks the copy cap, or mode=move and the handle lacks the move cap.
[test] on caller wake, N handles are transferred: copy-mode handles are placed in the caller's table (the replier retains its copies); move-mode handles are moved from the replier's table to the caller's table. The caller sees pair_count=N and tstart=S in its [0] sysword; handles occupy contiguous slots [S, S+N), and [2+] contains the reply payload.
[test] if the caller was terminated before the reply could deliver, reply returns E_TERM and no handle transfer occurs.

### §[event_handler] Event Handler

An event_handler is a handle to a kernel-side binding that routes a thread's events of a specific type to a port. Single-owner and non-transferable; created via `create`. The registration lives as long as the handle, the target thread, and the target port's recv side all exist.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                            4    0
┌──────────────────────────────────────────────────────────────┬─────┐
│                      _reserved (59)                          │ev(5)│
└──────────────────────────────────────────────────────────────┴─────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15                                5 4    3    2    1    0
┌───────────────────────────────────┬────┬────┬────┬────┬────┐
│           _reserved (11)          │rstp│swrt│sred│move│copy│
└───────────────────────────────────┴────┴────┴────┴────┴────┘
```

ev (field0 bits 0-4): the event_type the registration routes (see §[event_type]).

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | must be 0 (event_handler handles are not copyable) |
| 1 | move | must be 0 (event_handler handles are not moveable) |
| 2 | state_read | events delivered via this registration carry the thread's register state |
| 3 | state_write | reply caps derived from this registration may write the thread's register state on reply |
| 4 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 5-15 | _reserved | |

### §[reply_cap] Reply Cap

A reply cap is a one-shot handle to a suspended thread, created by recv and consumed by reply.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                            4    0
┌──────────────────────────────────────────────────────────────┬─────┐
│                      _reserved (59)                          │ev(5)│
└──────────────────────────────────────────────────────────────┴─────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15                                                          1    0
┌────────────────────────────────────────────────────────────┬────┬────┐
│                       _reserved (14)                       │move│copy│
└────────────────────────────────────────────────────────────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | must be 0 (reply caps are not copyable) |
| 1 | move | move this reply cap to another process |

field0 bits 0-4 (ev): event_type identifying the origin of this reply cap (see §[event_type]).

### §[fault_handling] Fault Handling

When an event fires on a thread and no `event_handler` registration exists for that (thread, event_type) — either because one was never created, or because the registration was torn down (port lost recv, handle deleted, thread of the registration's subject terminated, etc.) — the kernel resolves the event based on its event_type:

| event_type | Resolution |
|---|---|
| memory_fault | terminate process |
| thread_fault | terminate thread |
| breakpoint | terminate thread |
| suspension | terminate thread (no handler to resume it) |
| preemption | terminate thread (see §[timer] `arm`) |
| vm_exit | destroy VM, terminate all associated vCPU threads |
| pmu_overflow | overflow event is dropped; thread continues running |

[open] sub-codes within each event_type are not yet specified: read/write/execute within memory_fault; arithmetic/illegal_instruction/alignment/stack_overflow within thread_fault; the architecture-specific exit reason within vm_exit; ESR/vector data on aarch64 vs error codes on x86-64. The event payload needs a portable field for these plus room for arch-specific detail.

[open] the ABI for event delivery is not yet specified — when an event is delivered to a port via `recv`, what register state is placed in `[2+]` vregs? General-purpose registers are presumably arch-specific (x86-64 GPRs packed, aarch64 Xn packed). How is SIMD / FPU state handled? Options: (a) the event payload also carries a page_frame reference where SIMD state is dumped, (b) the handler registers a page_frame with the event_handler at registration time for the kernel to dump into, (c) pass via separate syscall after recv. Also: if the kernel does lazy FPU save and didn't dump SIMD for this event, how is that signaled to the handler?

[open] the ABI for `reply` action=0 mirroring the delivery ABI is not yet specified — the handler writes register state in vregs and the kernel loads it back into the thread. Must define packing symmetric with delivery, and how partial reply (e.g. only update some regs) is handled if at all.

[open] machine check exceptions (#MC on x86-64, async SError on aarch64) are not specified. The CPU raises these for hardware errors (ECC, bus/cache parity, uncorrectable DRAM). Options: add a new `machine_check` event_type routed via event_handler for the running thread, route through a system-wide error port held by a privileged supervisor process, or kernel-terminate-with-log. The "attach to the running thread" option is imperfect because machine checks may not be attributable to any specific thread (e.g. error detected during idle) and because recoverability differs from normal faults.

## §[virtualization] Virtualization

### §[vm] Virtual Machine

A virtual machine is a hardware-virtualized guest execution environment whose exits are delivered to userspace for handling.

Handle ABI:

```
word 0:
 63            48 47                    24 23   17 16     9 8       0
┌────────────────┬────────────────────────┬───────┬────────┬─────────┐
│   cap (16)     │    _reserved (24)      │type(7)│_rsvd(8)│  id (9) │
└────────────────┴────────────────────────┴───────┴────────┴─────────┘

word 1 (field0):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                 0
┌────────────────────────────────────────────────────────────────────┐
│                           _reserved (64)                           │
└────────────────────────────────────────────────────────────────────┘

cap (word 0, bits 48-63):
 15                                                3 2    1    0
┌───────────────────────────────────────────────────┬────┬────┬────┐
│                  _reserved (13)                   │rstp│move│copy│
└───────────────────────────────────────────────────┴────┴────┴────┘
```

Handle capabilities:

| Bits | Name | Grants |
|---|---|---|
| 0 | copy | must be 0 (VM handles are not copyable) |
| 1 | move | must be 0 (VM handles are not moveable) |
| 2 | restart_policy | behavior on process restart (0=drop, 1=keep) |
| 3-15 | _reserved | |

[open] the ABI for VM exits delivered through a vCPU thread's registered `vm_exit` event_handler is not yet specified — what's packed into the event payload (exit reason, guest register state, exit-specific fields like guest_linear_addr for EPT violations, port I/O ports and values)? How does the handler's reply modify guest state before resumption (GPRs, some control regs, skip instruction, inject exception)? Presumably mostly per-arch (VMX/SVM on x86-64, stage-2 / SMC / HVC on aarch64) with a portable reason code and a per-arch payload tail.

[open] SIMD / FPU state for vCPUs — same question as the event delivery ABI open in §[fault_handling]: how is guest SIMD state delivered on exits that need it, and how is lazy save handled for exits that don't?

[open] PCI/device passthrough into a VM is not specified. Three pieces are missing: (1) mapping a `device_region`'s MMIO range into the VM's guest physical address space (currently `map` action=3 (guest) only takes page_frames, so a guest can't see device registers directly); (2) DMA from the device targeting guest physical addresses via IOMMU stage-2 / nested translation (`map` action=2 (dma) sets up IOMMU for host-side VARs, not guest-side); (3) a bridging mechanism from a real device IRQ to a virtual IRQ delivered into the guest (`virt` action=1 (irq) injects virtual IRQs but the wiring from an actual device IRQ to that injection is userspace's job and isn't described). Likely wants at least one new `map` action (e.g. action=4 for guest_mmio) plus an explicit passthrough DMA variant.

#### virt

```
virt(action: kind, [1] vm_handle, ...) -> void
  syscall_num = [virt]
  action = virtualization operation (see table)
```

| Action | Kind | Input | Effect |
|---|---|---|---|
| 0 | passthrough | [2] sysreg_id, [3] flags (bit 0=read, bit 1=write) | Configure MSR/sysreg bypass so the guest can access the given sysreg without trapping. |
| 1 | irq | [2] irq_num, [3] assert (1=assert, 0=deassert) | Manipulate the virtual interrupt controller for the VM. |

[test] returns E_BADCAP if [1] is not a valid VM handle.

##### action=0 (passthrough)

[test] returns E_INVAL if sysreg_id does not identify a passthrough-eligible sysreg on the host.
[test] on success, guest reads of the sysreg succeed without a VM exit if flags bit 0 is set.
[test] on success, guest writes to the sysreg succeed without a VM exit if flags bit 1 is set.
[test] guest accesses not enabled by flags trigger a VM exit delivered on the vCPU thread's registered vm_exit event_handler.
[open] what's the sysreg_id enum ABI? Presumably per-arch (MSR numbers on x86-64, SYSREG encodings on aarch64) — how do we namespace it in a portable spec?

##### action=1 (irq)

[test] returns E_INVAL if irq_num exceeds the maximum IRQ line supported by the VM's virtual interrupt controller.
[test] returns E_INVAL if assert is neither 0 nor 1.
[test] on success with assert=1, the specified IRQ line is asserted on the VM's virtual interrupt controller; if a vCPU is unmasked for the line, it exits with an interrupt event.
[test] on success with assert=0, the specified IRQ line is deasserted.

## §[system_services] System Services

### §[time] Time

#### time

```
time(action: kind, ...) -> variable
  syscall_num = [time]
  action = time query or set (see table)
```

| Action | Kind | Input | Output |
|---|---|---|---|
| 0 | monotonic | — | [1] monotonic time in nanoseconds |
| 1 | getwall | — | [1] wall clock time |
| 2 | setwall | [1] wall_time | void |

##### action=0 (monotonic)

[test] on success, [1] contains the monotonic nanoseconds since boot as a u64.
[test] consecutive invocations never return a decreasing value.

##### action=1 (getwall)

[test] on success, [1] contains the current wall clock time (nanoseconds since UNIX epoch, UTC) as a u64.

##### action=2 (setwall)

[test] returns E_PERM if the calling process's self-handle does not have the set_time cap.
[test] on success, the wall clock is set to [1] nanoseconds since UNIX epoch (UTC).
[test] after a successful setwall, getwall returns a value at least as large as the set value (plus elapsed monotonic time since the set).

### §[rng] RNG

#### random

```
random([1] len) -> [1+] random bytes in vregs
  syscall_num = [random]
  Returns len bytes of cryptographically secure random data in vregs starting at [1].
```

[test] returns E_INVAL if len is 0.
[test] returns E_INVAL if len exceeds 127 × 8 bytes (the max vreg output capacity).
[test] on success, [1..ceil(len/8)] contain len random bytes sourced from a cryptographically secure RNG.
[test] successive invocations produce different byte sequences (statistical property).

### §[system_info] System Info

#### info

```
info(action: kind, ...) -> [1+] data
  syscall_num = [info]
  action = info query kind (see table)
```

| Action | Kind | Input | Output |
|---|---|---|---|
| 0 | system | — | [1] core_count, [2] mem_total |
| 1 | cores | — | [1+] per-core data |

##### action=0 (system)

[test] on success, [1] contains the total number of CPU cores.
[test] on success, [2] contains the total physical memory in bytes.

##### action=1 (cores)

[test] on success, per-core data for each core 0..core_count is returned in vregs.
[open] exact packing — 3 vregs per core (freq_hz, temp_mc, c_state)? Or packed?

[open] CPU feature detection: a portable way to query CPU feature flags (SSE/AVX variants on x86-64, SVE/SME presence on aarch64, pointer auth, etc.) is missing. Userspace can execute CPUID directly on x86-64 (readable from CPL3), but a spec-level query would be nicer for portability. Consider adding an `info` action that returns an arch-specific feature bitmap or a handful of well-known feature bits.

[open] CPU topology (NUMA nodes, SMT sibling groups, cache hierarchy) is not exposed. `info` returns `core_count` and aggregate `mem_total` plus per-core dynamic data, but nothing about which cores share an LLC, which are SMT siblings, or which NUMA node each core and each memory region belongs to. Sources exist (CPUID leaves 4/1F on x86-64, ACPI PPTT and cache ID regs on aarch64). Needed by memory managers doing affinity-aware allocation and schedulers doing SMT- or LLC-aware placement. Candidates: additional `info` actions (`numa`, `cache`, `smt`) each returning packed per-entity data, or a single `topology` action returning a nested description.

### §[power] Power Management

#### power

```
power(action: kind, ...) -> void
  syscall_num = [power]
  action = power management operation (see table)
```

| Action | Kind | Input | Effect |
|---|---|---|---|
| 0 | shutdown | — | Shut down the system |
| 1 | reboot | — | Reboot the system |
| 2 | sleep | — | Enter low-power sleep |
| 3 | screen_off | — | Turn off the display |
| 4 | set_freq | [1] cpu_id, [2] freq | Set CPU frequency |
| 5 | set_idle | [1] cpu_id, [2] idle_state | Set CPU idle state |

[test] returns E_PERM if the calling process's self-handle does not have the power cap.

##### action=0 (shutdown)
On success, the system shuts down; no further syscalls execute.

##### action=1 (reboot)
On success, the system reboots; no further syscalls execute.

##### action=2 (sleep)
On success, the system enters a low-power sleep state and resumes on a wake event.

##### action=3 (screen_off)
On success, the display is turned off.

##### action=4 (set_freq)
[test] returns E_INVAL if cpu_id exceeds core_count.
[test] returns E_INVAL if freq is not a supported frequency on the target CPU.
On success, the target CPU operates at freq Hz.

##### action=5 (set_idle)
[test] returns E_INVAL if cpu_id exceeds core_count.
[test] returns E_INVAL if idle_state is not a valid state for the target CPU.
On success, the target CPU uses idle_state when idling.
