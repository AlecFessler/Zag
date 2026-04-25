# Zag Microkernel Specification v3.0

## §[scope] Scope

## §[syscall_abi] Syscall ABI

Syscalls transfer payload via 128 **virtual registers** (vregs). The low-numbered vregs are backed by architecture GPRs; the rest spill to the user stack.

### vreg mapping (x86-64)

| vreg | location |
|---|---|
| 0 | `[rsp + 0]` — syscall word |
| 1 | rax |
| 2 | rbx |
| 3 | rdx |
| 4 | rbp |
| 5 | rsi |
| 6 | rdi |
| 7 | r8 |
| 8 | r9 |
| 9 | r10 |
| 10 | r12 |
| 11 | r13 |
| 12 | r14 |
| 13 | r15 |
| 14..127 | `[rsp + (N - 13) * 8]` — stack |

rsp, rcx, and r11 are not GPR-backed: rsp is the stack pointer anchor, and rcx/r11 are clobbered by `sysret` for return address and RFLAGS.

### vreg mapping (aarch64)

| vreg | location |
|---|---|
| 0 | `[sp + 0]` — syscall word |
| 1..31 | x0..x30 |
| 32..127 | `[sp + (N - 31) * 8]` — stack |

## §[capabilities] Capabilities

An unforgeable reference to a kernel object, paired with bits that gate operations on that object.

Capability layout:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     type-dependent metadata                         │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     type-dependent metadata                         │
└─────────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Purpose |
|---|---|---|
| id | 12 | handle id (table index, 0..4095) |
| type | 4 | kernel object type tag |
| _reserved | 32 | reserved |
| capabilities | 16 | type-dependent capabilities bitfield |
| field0 | 64 | type-dependent metadata |
| field1 | 64 | type-dependent metadata |

Syscall arguments that take a handle carry only the 12-bit handle id — the caller's handle-table index. Such arguments may be named `handle` directly or after the role they play (e.g. `target`, `exit_port`). The kernel resolves the id against the caller's table and reads the full capability for cap checks and dispatch.

Handle types a capability domain can hold:

| Type | How obtained |
|---|---|
| capability_domain_self | inherent (slot 0 at capability domain creation) |
| capability_domain (IDC handle) | `create_capability_domain`; received via call/reply transfer |
| execution_context | `create_execution_context`; received via call/reply transfer |
| page_frame | `create_page_frame`; received via call/reply transfer |
| virtual_address_range | `create_var`; received via call/reply transfer |
| device_region | kernel-issued at boot to root service; received via call/reply transfer |
| port | `create_port`; received via call/reply transfer |
| reply | created by recv |
| virtual_machine | `create_virtual_machine` |

### Lifetimes

Kernel objects are grouped by the **ceiling** of their lifetime — the longest they could possibly persist. An object may die sooner (via delete, revoke, kill, etc.) but cannot outlive its ceiling.

- **System lifetime** — Device Region, Capability Domain. Could persist as long as the kernel runs.
- **Refcount lifetime** — Port, Page Frame. Bounded by the distributed set of handles referencing them.
- **Capability domain lifetime** — Execution Context, Virtual Address Range, Virtual Machine. Cannot outlive the capability domain they are bound to.
- **Execution context lifetime** — Event Route, Reply. Event routes are kernel-held bindings (not handles) that are swept when the execution context they route from is destroyed. Replies cannot outlive the execution context they are bound to.

### restrict

Reduces the caps on a handle in place. The new caps must be a subset of the current caps. No self-handle cap is required — reducing authority never requires authority.

```
restrict([1] handle, [2] caps) -> void
  syscall_num = [restrict]

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
  [2] caps: u64 packed as
    bits  0-15: new caps
    bits 16-63: _reserved
```

[test] returns E_BADCAP if [1] is not a valid handle.
[test] returns E_PERM if [2].caps is not a subset of the handle's current caps.
[test] returns E_INVAL if any reserved bits are set in [1] or [2].
[test] on success, the handle's caps field equals [2].caps.
[test] on success, syscalls gated by caps cleared by restrict return E_PERM when invoked via this handle.

### delete

Releases a handle from the calling domain's handle table. Type-specific side effects apply.

```
delete([1] handle) -> void
  syscall_num = [delete]

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
```

No self-handle cap required.

| Handle type | Observable delete behavior |
|---|---|
| `capability_domain_self` | The calling domain is cleaned up; each handle in its table is released with its type-specific delete behavior applied |
| `capability_domain` (IDC) | Release handle. Domain has system lifetime; it does not terminate when IDC handles drop |
| `execution_context` | Release handle. ECs have capability-domain lifetime; they are not destroyed by handle drops |
| `page_frame` | Release handle. When the last handle to a page frame is released, the physical memory returns to the free pool |
| `virtual_address_range` | Non-transferable; exactly one handle exists. Delete unmaps everything installed, frees the address range, releases the handle |
| `device_region` | Release handle. When the last handle to a device region is released, the region returns to the root service |
| `port` | Decrement the send refcount if this handle has `xfer` or `call`; decrement the recv refcount if this handle has `recv`. When the recv refcount hits zero, callers suspended on the port resume with `E_CLOSED`. When the send refcount hits zero and no event routes target the port, receivers suspended on the port resume with `E_CLOSED`. Release handle |
| `reply` | If the suspended sender is still waiting, resume them with `E_ABANDONED`. Release handle |
| `virtual_machine` | Non-transferable; exactly one handle exists. Destroy the VM: all vCPU ECs terminate, guest memory is freed, kernel-emulated LAPIC/IOAPIC/timer state is torn down. Release handle |

[test] returns E_BADCAP if [1] is not a valid handle.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, the handle is released and subsequent operations on it return E_BADCAP.

### revoke

Releases every handle transitively derived from the target via `copy`, across all capability domains. The target handle itself is not released — use `delete` for that.

```
revoke([1] handle) -> void
  syscall_num = [revoke]

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
```

No self-handle cap required.

A handle that was copied from the target and then subsequently moved is still a derivation of the target — moving a handle keeps it on the copy ancestry chain rather than orphaning it. A domain that has moved a handle elsewhere no longer holds it and cannot revoke it; whoever holds the copy ancestor still can, and the revoke will reach the moved descendant through the preserved chain.

Each released descendant is processed with the type-specific behavior defined for `delete`.

[test] returns E_BADCAP if [1] is not a valid handle.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, every handle transitively derived via copy from [1] is released from its holder with the type-specific delete behavior applied.
[test] a handle that was copied from [1] and then subsequently moved is released by revoke([1]).
[test] revoke([1]) does not release [1] itself.
[test] revoke([1]) does not release any handle on the copy ancestor side of [1].

## §[capability_domain] Capability Domain

A capability domain is a set of capabilities usable by execution contexts bound to the domain.

### Self handle

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63      56 55    48 47     40 39     32 31     24 23         16 15           0
┌─────────┬────────┬─────────┬─────────┬─────────┬────────────┬──────────────┐
│port_clg │  vm_   │   pf_   │ idc_rx  │cridc_clg│var_ceiling │ ec_ceiling   │
│  (8)    │ceiling │ ceiling │   (8)   │   (8)   │    (8)     │    (16)      │
│         │  (8)   │   (8)   │         │         │            │              │
└─────────┴────────┴─────────┴─────────┴─────────┴────────────┴──────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15    13 12                        6   5    4    3     2      1      0
┌────────┬───────────────────────────┬──────┬──────┬──────┬──────┬──────┬────┐
│ pri(3) │       _reserved (7)       │ crpt │ crvm │ crpf │ crvr │ crec │crcd│
└────────┴───────────────────────────┴──────┴──────┴──────┴──────┴──────┴────┘
```

| Bit(s) | Name | Gates |
|---|---|---|
| 0 | `crcd` — create capability domain | `create_capability_domain` syscall |
| 1 | `crec` — create execution context | `create_execution_context` syscall (target = self) |
| 2 | `crvr` — create virtual address range | `create_var` syscall |
| 3 | `crpf` — create page frame | `create_page_frame` syscall |
| 4 | `crvm` — create virtual machine | `create_virtual_machine` syscall |
| 5 | `crpt` — create port | `create_port` syscall |
| 13-15 | `pri` — priority ceiling (0-7) | max priority any EC in this domain may be created with or raised to |

field0:

| field | bits | meaning |
|---|---|---|
| ec_ceiling | 0-15 | max caps any EC handle referencing an EC in this domain may hold |
| var_ceiling | 16-23 | max caps any VAR handle referencing a VAR in this domain may hold |
| cridc_ceiling | 24-31 | see §[cridc_ceiling] |
| idc_rx | 32-39 | mask intersected with sent caps when this domain receives an IDC handle |
| pf_ceiling | 40-47 | max caps `create_page_frame` may mint when called from this domain (`max_rwx` bits 40-42, `max_sz` bits 43-44) |
| vm_ceiling | 48-55 | max caps `create_virtual_machine` may mint when called from this domain (`policy` bit 48) |
| port_ceiling | 56-63 | max caps `create_port` may mint when called from this domain (`xfer` bit 58, `call` bit 59, `recv` bit 60, `bind` bit 61) |

#### §[cridc_ceiling] cridc_ceiling

At `create_capability_domain`:

- The IDC handle the caller receives to the new domain has caps = the caller's `cridc_ceiling`.
- The IDC handle placed in the new domain's slot 2 has caps = the `cridc_ceiling` passed in the ceilings word.

All subsequent IDC handles to the new domain derive from these two originals by copy or move, subject to cap-subset rules.

#### §[idc_rx] idc_rx

When a domain receives an IDC handle over IDC:

- The installed handle has caps = the intersection of the caps attempted to be granted and the receiving domain's `idc_rx`.

[test] when a domain receives an IDC handle over IDC, the installed handle's caps = intersection of the granted caps and the receiver's `idc_rx`.

### IDC handle

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                          3   2    1    0
┌─────────────────────────────────────────────┬──────┬────┬────┐
│              _reserved (13)                 │ crec │copy│move│
└─────────────────────────────────────────────┴──────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `crec` — create execution context in referenced domain | `create_execution_context` with this handle as `target` |

### create_capability_domain

Creates a new capability domain from an ELF image carried in a page frame. The caller receives back an IDC handle to the new domain.

```
create_capability_domain([1] caps, [2] ceilings, [3] elf_page_frame, [4+] passed_handles)
  -> [1] idc_handle
  syscall_num = [create_capability_domain]

  [1] caps: u64 packed as
    bits  0-15: self_caps          — caps on the new domain's slot-0 self-handle
    bits 16-23: idc_rx             — new domain's idc_rx (see §[capability_domain] Self handle)
    bits 24-63: _reserved

  [2] ceilings: u64 packed as
    bits  0-15: ec_ceiling         — max caps any EC handle in the new domain may hold
    bits 16-23: var_ceiling:
                   bit 16:     mmio_allowed
                   bits 17-18: max_sz (enum)
                   bits 19-21: max_rwx (r/w/x)
                   bits 22-23: _reserved
    bits 24-31: cridc_ceiling      — new domain's cridc_ceiling (see §[capability_domain] Self handle)
    bits 32-39: pf_ceiling:
                   bits 32-34: max_rwx (r/w/x)
                   bits 35-36: max_sz (enum)
                   bits 37-39: _reserved
    bits 40-47: vm_ceiling:
                   bit 40:     policy
                   bits 41-47: _reserved
    bits 48-55: port_ceiling:
                   bit 50:     xfer
                   bit 51:     call
                   bit 52:     recv
                   bit 53:     bind
                   bits 48-49, 54-55: _reserved
    bits 56-63: _reserved

  [3] elf_page_frame: page frame handle containing the ELF image from offset 0

  [4+] passed_handles: each entry is a u64 packed as
    bits  0-11: handle id (12-bit handle in the caller's table)
    bits 12-15: _reserved
    bits 16-31: caps to install on the handle inserted into the new domain
    bit     32: move (1 = remove from caller; 0 = copy, both retain)
    bits 33-63: _reserved
```

Self-handle cap required: `crcd`.

The ELF image is read from `elf_page_frame` starting at byte 0. The pointer to the new domain's read-only view of its capability table is passed as the first argument to the initial EC's entry point.

The caller receives an IDC handle to the new domain with caps = the caller's own `cridc_ceiling`. The new domain's slot-2 self-IDC handle is minted with caps = the `cridc_ceiling` passed in [2].

Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the caller's handle table has no free slot for the returned IDC handle.

[test] returns E_PERM if the caller's self-handle lacks `crcd`.
[test] returns E_PERM if `self_caps` is not a subset of the caller's self-handle caps.
[test] returns E_PERM if `ec_ceiling` is not a subset of the caller's `ec_ceiling`.
[test] returns E_PERM if `var_ceiling` is not a subset of the caller's `var_ceiling`.
[test] returns E_PERM if `cridc_ceiling` is not a subset of the caller's `cridc_ceiling`.
[test] returns E_PERM if `pf_ceiling` is not a subset of the caller's `pf_ceiling`.
[test] returns E_PERM if `vm_ceiling` is not a subset of the caller's `vm_ceiling`.
[test] returns E_PERM if `port_ceiling` is not a subset of the caller's `port_ceiling`.
[test] returns E_BADCAP if `elf_page_frame` is not a valid page frame handle.
[test] returns E_BADCAP if any passed handle id is not a valid handle in the caller's table.
[test] returns E_INVAL if the ELF header is malformed.
[test] returns E_INVAL if `elf_page_frame` is smaller than the declared ELF image size.
[test] returns E_INVAL if any reserved bits are set in [1], [2], or a passed handle entry.
[test] on success, the caller receives an IDC handle to the new domain with caps = the caller's `cridc_ceiling`.
[test] on success, the new domain's handle table contains the self-handle at slot 0 with caps = `self_caps`.
[test] on success, the new domain's handle table contains the initial EC at slot 1.
[test] on success, the new domain's handle table contains an IDC handle to itself at slot 2 with caps = the passed `cridc_ceiling`.
[test] on success, passed handles occupy slots 3+ of the new domain's handle table in the order supplied, each with the caps specified in its entry.
[test] a passed handle entry with `move = 1` is removed from the caller's handle table after the call.
[test] a passed handle entry with `move = 0` remains in the caller's handle table after the call.
[test] on success, the new domain's `ec_ceiling`, `var_ceiling`, `cridc_ceiling`, `pf_ceiling`, `vm_ceiling`, and `port_ceiling` in field0 are set to the values supplied in [2].
[test] on success, the new domain's `idc_rx` in field0 is set to the value supplied in [1].
[test] the initial EC begins executing at the entry point declared in the ELF header.

## §[execution_context] Execution Context

An execution context is a schedulable unit of executable state bound to a capability domain.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                    4    3    2    1    0
┌───────────────────────────────────────┬──────┬──────┬────┬────┐
│           _reserved (12)              │ spri │ saff │copy│move│
└───────────────────────────────────────┴──────┴──────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `saff` — set affinity | future `set_affinity` syscall on this EC |
| 3 | `spri` — set priority | future `set_priority` syscall on this EC |

### create_execution_context

Creates a new execution context either in the caller's own domain or in a target domain referenced by an IDC handle.

```
create_execution_context([1] caps, [2] entry, [3] stack_pages, [4] target, [5] vm_handle, [6] affinity)
  -> [1] handle
  syscall_num = [create_execution_context]

  [1] caps: u64 packed as
    bits  0-15: caps          — caps on the EC handle returned to the caller
    bits 16-31: target_caps   — caps on the EC handle inserted into target's table
                                (ignored when target = self)
    bits 32-34: priority      — scheduling priority, 0-7, bounded by caller's priority ceiling
    bits 35-63: _reserved

  [2] entry:        instruction pointer where the EC begins execution
  [3] stack_pages:  number of stack pages the kernel allocates in the target's address space;
                    kernel installs unmapped guard pages above and below the stack
  [4] target:       0 = self, else IDC handle with crec cap to the target domain
  [5] affinity:     64-bit core mask; bit N = 1 allows the EC to run on core N.
                    0 = any core (kernel chooses)
```

Caps required:
- Caller's self-handle must always have `crec`.
- If `[4] != 0`: the IDC handle in `[4]` must additionally have `crec`.

The kernel allocates `[3]` pages of stack in the target's address space with unmapped guard pages above and below to catch overflow and underflow. The EC begins executing at `[2] entry` with the stack pointer set to the top of the allocated stack.

Returns E_NOMEM if insufficient kernel memory; returns E_NOSPC if the target's address space has insufficient contiguous space for the stack; returns E_FULL if the caller's handle table has no free slot, or if `[4]` is nonzero and the target domain's handle table is full.

[test] returns E_PERM if the caller's self-handle lacks `crec`.
[test] returns E_PERM if [4] is nonzero and [4] lacks `crec`.
[test] returns E_PERM if caps is not a subset of the target domain's `ec_ceiling`.
[test] returns E_PERM if target_caps is not a subset of the target domain's `ec_ceiling`.
[test] returns E_PERM if priority exceeds the caller's priority ceiling.
[test] returns E_BADCAP if [4] is nonzero and not a valid IDC handle.
[test] returns E_INVAL if [3] stack_pages is 0.
[test] returns E_INVAL if [5] affinity has bits set outside the system's core count.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, the caller receives an EC handle with caps = `[1].caps`.
[test] on success, when [4] is nonzero, the target domain also receives a handle with caps = `[1].target_caps`.
[test] on success, the EC's priority is set to `[1].priority`.
[test] on success, the EC's affinity is set to `[5]`.

## §[var] Virtual Address Range

A virtual address range is a contiguous span of the virtual address space bound to a capability domain. It is available for demand-paged memory, or for installing page frames or device regions.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     base virtual address (64)                       │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                         39 38    36 35 34 33 32 31             0
┌─────────────────────────────┬────────┬─────┬──────┬────────────────┐
│     _reserved (25)          │cur_rwx │ cch │  sz  │ page_count (32)│
└─────────────────────────────┴────────┴─────┴──────┴────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| base vaddr | field0 bits 0-63 | base virtual address of the VAR |
| page_count | field1 bits 0-31 | number of pages (in `sz` units) |
| sz | field1 bits 32-33 | page size (immutable): 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| cch | field1 bits 34-35 | cache type (immutable): 0=wb, 1=uc, 2=wc, 3=wt |
| cur_rwx | field1 bits 36-38 | current mapping permissions (bit 36=r, 37=w, 38=x) |

cap (word 0, bits 48-63):

```
 15            6 5    4 3      2   1   0
┌───────────────┬──────┬──────┬───┬───┬───┐
│ _reserved(10) │max_sz│ mmio │ x │ w │ r │
└───────────────┴──────┴──────┴───┴───┴───┘
```

| Bit(s) | Name | Meaning |
|---|---|---|
| 0 | `r` | max read |
| 1 | `w` | max write |
| 2 | `x` | max execute |
| 3 | `mmio` | mmio mode |
| 4-5 | `max_sz` | max page size: 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| 6-15 | `_reserved` | |

`r`/`w`/`x` and `max_sz` are ceiling-checked against the domain's `var_ceiling`. `mmio` and `max_sz` describe the VAR object and are immutable after creation. `sz`, `cch`, and `cur_rwx` in field1 are observable state on the VAR.

### create_var

Reserves a range of virtual address space bound to the caller's domain.

```
create_var([1] caps, [2] props, [3] pages, [4] preferred_base) -> [1] handle
  syscall_num = [create_var]

  [1] caps: u64 packed as
    bits  0-15: caps        — caps on the VAR handle returned to the caller
    bits 16-63: _reserved

  [2] props: u64 packed as
    bits 0-2: cur_rwx       — initial current rwx
    bits 3-4: sz            — page size (immutable; must be 0 when caps.mmio = 1)
    bits 5-6: cch           — cache type (immutable)
    bits 7-63: _reserved

  [3] pages:          number of `sz` pages to reserve
  [4] preferred_base: 0 = kernel chooses
```

Self-handle cap required: `crvr`.

Returns E_NOMEM if insufficient kernel memory; returns E_NOSPC if the address space has no room for the requested range; returns E_FULL if the caller's handle table has no free slot.

[test] returns E_PERM if the caller's self-handle lacks `crvr`.
[test] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `var_ceiling.max_rwx`.
[test] returns E_PERM if caps.max_sz exceeds the caller's `var_ceiling.max_sz`.
[test] returns E_PERM if caps.mmio = 1 and the caller's `var_ceiling` does not permit mmio.
[test] returns E_INVAL if [3] pages is 0.
[test] returns E_INVAL if [4] preferred_base is nonzero and not aligned to the page size encoded in props.sz.
[test] returns E_INVAL if caps.max_sz is 3 (reserved).
[test] returns E_INVAL if caps.mmio = 1 and props.sz != 0.
[test] returns E_INVAL if props.sz is 3 (reserved).
[test] returns E_INVAL if props.sz exceeds caps.max_sz.
[test] returns E_INVAL if caps.mmio = 1 and caps.x is set.
[test] returns E_INVAL if props.cur_rwx is not a subset of caps.r/w/x.
[test] returns E_INVAL if any reserved bits are set in [1] or [2].
[test] on success, the caller receives a VAR handle with caps = `[1].caps`.
[test] on success, field0 contains the assigned base address.
[test] on success, field1 contains `[2].props` together with `[3]` pages.
[test] on success, when [4] preferred_base is nonzero and the range is available, the assigned base address equals `[4]`.

## §[page_frame] Page Frame

A page frame is a reference to physical memory. Installing it into virtual address ranges bound to multiple capability domains creates shared memory.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                         34 33 32 31                            0
┌─────────────────────────────┬──────┬────────────────────────────────┐
│        _reserved (30)       │  sz  │        page_count (32)         │
└─────────────────────────────┴──────┴────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| page_count | field0 bits 0-31 | number of pages (in `sz` units) |
| sz | field0 bits 32-33 | page size (immutable): 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |

cap (word 0, bits 48-63):

```
 15             7 6   5  4   3   2    1    0
┌────────────────┬──────┬───┬───┬───┬────┬────┐
│ _reserved (9)  │max_sz│ x │ w │ r │copy│move│
└────────────────┴──────┴───┴───┴───┴────┴────┘
```

| Bit(s) | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `r` | read; applied only if the installing VAR's `cur_rwx.r` is set |
| 3 | `w` | write; applied only if the installing VAR's `cur_rwx.w` is set |
| 4 | `x` | execute; applied only if the installing VAR's `cur_rwx.x` is set |
| 5-6 | `max_sz` | max page size: 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| 7-15 | `_reserved` | |

### create_page_frame

Allocates physical memory and returns a page frame handle.

```
create_page_frame([1] caps, [2] props, [3] pages) -> [1] handle
  syscall_num = [create_page_frame]

  [1] caps: u64 packed as
    bits  0-15: caps        — caps on the page frame handle returned to the caller
    bits 16-63: _reserved

  [2] props: u64 packed as
    bits  0-1: sz           — page size (immutable)
    bits  2-63: _reserved

  [3] pages: number of `sz` pages to allocate
```

Self-handle cap required: `crpf`.

Returns E_NOMEM if insufficient physical memory; returns E_FULL if the caller's handle table has no free slot.

[test] returns E_PERM if the caller's self-handle lacks `crpf`.
[test] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `pf_ceiling.max_rwx`.
[test] returns E_PERM if caps.max_sz exceeds the caller's `pf_ceiling.max_sz`.
[test] returns E_INVAL if [3] pages is 0.
[test] returns E_INVAL if caps.max_sz is 3 (reserved).
[test] returns E_INVAL if props.sz is 3 (reserved).
[test] returns E_INVAL if props.sz exceeds caps.max_sz.
[test] returns E_INVAL if any reserved bits are set in [1] or [2].
[test] on success, the caller receives a page frame handle with caps = `[1].caps`.
[test] on success, field0 contains `[3]` pages and `[2].props.sz`.

## §[device_region] Device Region

A device region is a reference to a physical device's MMIO region. Installing it into a virtual address range makes the device directly accessible to execution contexts in that capability domain.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                                  2  1    0
┌────────────────────────────────────────────────────┬────┬────┐
│                 _reserved (14)                     │copy│move│
└────────────────────────────────────────────────────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |

## §[virtual_machine] Virtual Machine

A virtual machine is a guest execution environment with its own guest physical address space. Execution contexts enter guest mode within a VM to run.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                                       1    0
┌──────────────────────────────────────────────────────────┬──────┐
│                   _reserved (15)                         │policy│
└──────────────────────────────────────────────────────────┴──────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `policy` | mutating this VM's policy tables (§[vm_policy]) via runtime syscalls |

### create_virtual_machine

Allocates a VM with its own guest physical address space and initializes kernel-emulated LAPIC/IOAPIC state. vCPUs are created separately via `create_vcpu`.

```
create_virtual_machine([1] caps, [2] policy_page_frame) -> [1] handle
  syscall_num = [create_virtual_machine]

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the VM handle returned to the caller
    bits 16-63: _reserved

  [2] policy_page_frame: page frame handle containing a VmPolicy struct at
                         offset 0 (static CPUID responses and CR access
                         policies applied to all vCPUs on exits; layout in
                         §[vm_policy])
```

Self-handle cap required: `crvm`.

The kernel retains a reference on `policy_page_frame` for the lifetime of the VM.

Returns E_NOMEM if insufficient kernel memory; returns E_NODEV if the platform does not support hardware virtualization; returns E_FULL if the caller's handle table has no free slot.

[test] returns E_PERM if the caller's self-handle lacks `crvm`.
[test] returns E_PERM if caps is not a subset of the caller's `vm_ceiling`.
[test] returns E_NODEV if the platform does not support hardware virtualization.
[test] returns E_BADCAP if [2] is not a valid page frame handle.
[test] returns E_INVAL if `policy_page_frame` is smaller than `sizeof(VmPolicy)`.
[test] returns E_INVAL if `VmPolicy.num_cpuid_responses` exceeds `MAX_CPUID_POLICIES`.
[test] returns E_INVAL if `VmPolicy.num_cr_policies` exceeds `MAX_CR_POLICIES`.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, the caller receives a VM handle with caps = `[1].caps`.

### §[vm_policy] VM Policy

`VmPolicy` is a per-arch struct carrying fixed-size tables consulted by the kernel on guest exits to handle selected operations inline. Each table has an entry array and a count; only the first `num_*` entries are consulted. Tables seed with `create_virtual_machine` and are mutable at runtime by VMs holding the `policy` cap (runtime mutation syscall spec TBD).

**x86-64**

```
VmPolicy {
  cpuid_responses: CpuidPolicy[MAX_CPUID_POLICIES],
  num_cpuid_responses: u32,
  _pad0: u32,
  cr_policies: CrPolicy[MAX_CR_POLICIES],
  num_cr_policies: u32,
  _pad1: u32,
}

CpuidPolicy {
  leaf: u32,
  subleaf: u32,
  eax: u32,
  ebx: u32,
  ecx: u32,
  edx: u32,
}

CrPolicy {
  cr_num: u8,
  _pad: u8[7],
  read_value: u64,
  write_mask: u64,
}

MAX_CPUID_POLICIES = 32
MAX_CR_POLICIES = 8
```

Semantics:
- A guest `CPUID` matching `(leaf, subleaf)` in `cpuid_responses` resumes with `(eax, ebx, ecx, edx)` from the entry. Non-matching CPUIDs deliver a `vm_exit` event.
- A guest CR read matching `cr_num` in `cr_policies` resumes with `read_value`; a guest CR write matching `cr_num` is applied masked by `write_mask` (bits not set in `write_mask` are ignored). Non-matching CR accesses deliver a `vm_exit` event.
- MSR accesses are not covered by `VmPolicy` today; they always deliver a `vm_exit` event unless explicitly configured via a separate passthrough mechanism.

**aarch64**

```
VmPolicy {
  id_reg_responses: IdRegResponse[MAX_ID_REG_RESPONSES],
  num_id_reg_responses: u32,
  _pad0: u32,
  sysreg_policies: SysregPolicy[MAX_SYSREG_POLICIES],
  num_sysreg_policies: u32,
  _pad1: u32,
}

IdRegResponse {
  op0: u8,
  op1: u8,
  crn: u8,
  crm: u8,
  op2: u8,
  _pad: u8[3],
  value: u64,
}

SysregPolicy {
  op0: u8,
  op1: u8,
  crn: u8,
  crm: u8,
  op2: u8,
  _pad: u8[3],
  read_value: u64,
  write_mask: u64,
}

MAX_ID_REG_RESPONSES = 64
MAX_SYSREG_POLICIES = 32
```

Sysreg identifiers `(op0, op1, crn, crm, op2)` follow Arm ARM C5.3.

Semantics:
- A guest read of an `ID_AA64*` register matching the `(op0, op1, crn, crm, op2)` tuple in `id_reg_responses` resumes with `value`. Writes to ID registers are silently ignored.
- A guest sysreg read matching the tuple in `sysreg_policies` resumes with `read_value`; a guest sysreg write matching the tuple is applied masked by `write_mask` (bits not set in `write_mask` are ignored). Non-matching sysreg accesses deliver a `vm_exit` event.

### create_vcpu

Creates a vCPU execution context bound to a VM. The vCPU is created suspended on its exit port with zeroed guest state; the creator installs initial guest state through the same mechanism used to handle vm exits — recv on the exit port, modify the vregs, reply with a resume action.

```
create_vcpu([1] caps, [2] vm_handle, [3] affinity, [4] exit_port) -> [1] handle
  syscall_num = [create_vcpu]

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the EC handle returned to the caller
    bits 32-34: priority   — scheduling priority, 0-7, bounded by caller's priority ceiling
    bits 35-63: _reserved

  [2] vm_handle:  VM handle the vCPU binds to
  [3] affinity:   64-bit core mask; bit N = 1 allows the vCPU to run on core N.
                  0 = any core (kernel chooses)
  [4] exit_port:  port handle where vm_exit events for this vCPU are delivered
```

Caps required: caller's self-handle must have `crec`. Holding the VM handle implies the authority to spawn vCPUs in it.

The vCPU EC is bound to the capability domain that holds the VM handle. `create_vcpu` binds `exit_port` as the destination for its vm_exit events. Immediately upon creation, the kernel enqueues a vm_exit-style delivery on `exit_port` representing the initial "not yet started" condition: the reply cap is valid, all guest-state vregs are zero, and the exit sub-code is the initial-state sub-code. The creator recvs this event, writes the real initial guest state into the vregs, and replies with a resume action to enter guest mode. All subsequent guest exits flow through the same port and the same reply-cap lifecycle.

Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the caller's handle table has no free slot.

[test] returns E_PERM if the caller's self-handle lacks `crec`.
[test] returns E_PERM if caps is not a subset of the VM's owning domain's `ec_ceiling`.
[test] returns E_PERM if priority exceeds the caller's priority ceiling.
[test] returns E_BADCAP if [2] is not a valid VM handle.
[test] returns E_BADCAP if [4] is not a valid port handle.
[test] returns E_INVAL if [3] affinity has bits set outside the system's core count.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, the caller receives an EC handle with caps = `[1].caps`.
[test] on success, the EC is a vCPU bound to VM [2] with exit delivery on [4].
[test] on success, the EC's priority is set to `[1].priority`.
[test] on success, the EC's affinity is set to `[3]`.
[test] immediately after creation, an initial vm_exit event is delivered on `[4] exit_port` with zeroed guest state in the vregs and the initial-state sub-code.

## §[port] Port

A port is a rendezvous point between a calling execution context and a receiving execution context, used for IDC, transfer of capabilities, and execution context event delivery.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                  6     5    4    3    2    1  0
┌────────────────────┬────┬────┬────┬────┬────┬────┐
│   _reserved (10)   │bind│recv│call│xfer│copy│move│
└────────────────────┴────┴────┴────┴────┴────┴────┘
```

| Bit | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `xfer` | transferring capabilities on this port, either as part of a call or as part of a reply |
| 3 | `call` | suspending on this port and passing register state |
| 4 | `recv` | reading events off this port and receiving the associated reply capability |
| 5 | `bind` | binding this port as an event delivery target (e.g., vCPU exit port, event route destination) |

### create_port

Allocates a port and returns a handle to it.

```
create_port([1] caps) -> [1] handle
  syscall_num = [create_port]

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the port handle returned to the caller
    bits 16-63: _reserved
```

Self-handle cap required: `crpt`.

Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the caller's handle table has no free slot.

[test] returns E_PERM if the caller's self-handle lacks `crpt`.
[test] returns E_PERM if caps is not a subset of the caller's `port_ceiling`.
[test] returns E_INVAL if any reserved bits are set in [1].
[test] on success, the caller receives a port handle with caps = `[1].caps`.

### §[event_type] Event Type

Event type identifies the kind of event an event route binds or that a reply originated from.

| Value | Name | Description |
|---|---|---|
| 0 | call | IDC call delivered via recv on a port |
| 1 | memory_fault | invalid read/write/execute, unmapped access, protection violation |
| 2 | thread_fault | arithmetic fault, illegal instruction, alignment check, stack overflow |
| 3 | breakpoint | software or hardware breakpoint trap |
| 4 | suspension | explicit suspension |
| 5 | vm_exit | vCPU exited guest mode |
| 6 | pmu_overflow | performance counter overflowed |
| 7..31 | _reserved | |

Sub-codes within an event type (e.g., read vs write vs execute within memory_fault; arithmetic vs illegal_instruction vs alignment vs stack_overflow within thread_fault; the architecture-specific exit reason within vm_exit) are carried in the event payload rather than as separate event type values.

### §[event_state] Event State

For suspended events other than IDC, when the event handler holds a capability with read and/or write access to the suspended execution context's state, the kernel exposes that state through the vreg layout at recv time and consumes modifications on reply. GPRs are 1:1 with hardware registers during handler execution — the handler reads or modifies EC state by directly reading or writing the hardware register. Non-GPR state lives on the stack at fixed offsets. VM exit events expose additional state — see §[vm_exit_state].

**x86-64**

| vreg | location | content |
|---|---|---|
| 1..13 | GPRs | EC's rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15 |
| 14 | `[rsp + 8]` | RIP |
| 15 | `[rsp + 16]` | RFLAGS |
| 16 | `[rsp + 24]` | RSP |
| 17 | `[rsp + 32]` | FS.base |
| 18 | `[rsp + 40]` | GS.base |
| 19..126 | `[rsp + ...]` | event-specific payload |
| 127 | `[rsp + 912]` | reply capability |

**aarch64**

| vreg | location | content |
|---|---|---|
| 1..31 | x0..x30 | EC's x0..x30 |
| 32 | `[sp + 8]` | PC |
| 33 | `[sp + 16]` | PSTATE |
| 34 | `[sp + 24]` | SP_EL0 |
| 35 | `[sp + 32]` | TPIDR_EL0 |
| 36..126 | `[sp + ...]` | event-specific payload |
| 127 | `[sp + 768]` | reply capability |

FPU, SIMD, and other extended state (XSAVE area on x86-64, SVE/NEON state on aarch64) is not exposed through vregs and is accessed through a separate mechanism. When copied to a buffer, the state is laid out per-architecture:

- **x86-64**: XSAVE(C) format, as defined in Intel® 64 and IA-32 Architectures Software Developer's Manual Vol. 1, Chapter 13 ("Managing State Using the XSAVE Feature Set"). Layout and offsets of individual state components are enumerated at runtime via `CPUID.0xD`.
- **aarch64**: V0..V31 packed from offset 0 (16 bytes each, 512 bytes total), FPSR at offset 512, FPCR at offset 516. If SVE is enabled, SVE state (Z0..Z31, P0..P15, FFR) follows in the architecturally canonical layout as defined in Arm Architecture Reference Manual (DDI0487), §B1.

### §[vm_exit_state] VM Exit State

VM exit events (`event_type` = `vm_exit`) extend §[event_state] to expose the full architectural guest state the handler needs to emulate trapped instructions and resume the vCPU. The exit sub-code identifies what caused the exit; the exit payload carries sub-code-specific data (faulting address, port number, MSR index, etc.).

**x86-64**

Exit sub-codes:

| Value | Name | Description |
|---|---|---|
| 0 | cpuid | guest executed CPUID |
| 1 | io | guest executed IN/OUT to a trapped port |
| 2 | mmio | guest memory access to a trapped MMIO region |
| 3 | cr | guest accessed a trapped control register |
| 4 | msr_r | guest executed RDMSR |
| 5 | msr_w | guest executed WRMSR |
| 6 | ept | EPT violation (unmapped guest physical access) |
| 7 | except | guest took an exception delivered to the host |
| 8 | intwin | interrupt window opened |
| 9 | hlt | guest executed HLT |
| 10 | shutdown | guest triggered shutdown |
| 11 | triple | guest triple-faulted |
| 12 | unknown | unknown or unhandled exit reason |

vreg layout:

| vreg | location | content |
|---|---|---|
| 1..13 | GPRs | guest rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15 |
| 14 | `[rsp + 8]` | guest RIP |
| 15 | `[rsp + 16]` | guest RFLAGS |
| 16 | `[rsp + 24]` | guest RSP |
| 17 | `[rsp + 32]` | guest RCX |
| 18 | `[rsp + 40]` | guest R11 |
| 19 | `[rsp + 48]` | CR0 |
| 20 | `[rsp + 56]` | CR2 |
| 21 | `[rsp + 64]` | CR3 |
| 22 | `[rsp + 72]` | CR4 |
| 23 | `[rsp + 80]` | CR8 |
| 24 | `[rsp + 88]` | EFER |
| 25 | `[rsp + 96]` | APIC_BASE |
| 26..41 | `[rsp + 104..231]` | segment registers (cs, ds, es, fs, gs, ss, tr, ldtr); each occupies 2 vregs: base u64, then `{limit u32, selector u16, access_rights u16}` packed |
| 42..43 | `[rsp + 232..247]` | GDTR base, GDTR limit (u32) |
| 44..45 | `[rsp + 248..263]` | IDTR base, IDTR limit (u32) |
| 46..55 | `[rsp + 264..343]` | STAR, LSTAR, CSTAR, SFMASK, KERNEL_GS_BASE, SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP, PAT, TSC_AUX |
| 56..61 | `[rsp + 344..391]` | DR0, DR1, DR2, DR3, DR6, DR7 |
| 62..65 | `[rsp + 392..423]` | vcpu_events: exception state packed, exception payload, interrupt/nmi packed, sipi/smi/triple_fault packed |
| 66..69 | `[rsp + 424..455]` | interrupt_bitmap (256 bits = 4 u64s) |
| 70 | `[rsp + 456]` | exit sub-code |
| 71..73 | `[rsp + 464..487]` | exit payload (per sub-code below) |
| 74..126 | `[rsp + 488..911]` | _reserved |
| 127 | `[rsp + 912]` | reply capability |

Exit payload per sub-code (up to 3 vregs = 24 bytes; unused vregs in the payload band are `_reserved` for that sub-code):

| Sub-code | vreg[71] | vreg[72] | vreg[73] |
|---|---|---|---|
| cpuid | `{leaf u32, subleaf u32}` | _reserved | _reserved |
| io | next_rip | `{value u32, port u16, size u8, is_write u8}` | _reserved |
| mmio | guest_phys | value | `{size u8, is_write u8}` |
| cr | value | `{cr_num u4, is_write u1, gpr u4}` packed | _reserved |
| msr_r, msr_w | value | msr index (u32) | _reserved |
| ept | guest_phys | `{is_read u1, is_write u1, is_exec u1}` packed | _reserved |
| except | `{vector u8}` | error_code | _reserved |
| intwin, hlt, shutdown, triple | _reserved | _reserved | _reserved |
| unknown | raw exit reason | _reserved | _reserved |

**aarch64**

Exit sub-codes:

| Value | Name | Description |
|---|---|---|
| 0 | stage2_fault | stage-2 translation fault (unmapped guest physical access) |
| 1 | hvc | hypervisor call |
| 2 | smc | secure monitor call |
| 3 | sysreg | trapped system register access |
| 4 | wfi_wfe | guest executed WFI or WFE |
| 5 | unknown_ec | unrecognized exception class |
| 6 | sync_el1 | synchronous EL1 exception |
| 7 | halt | guest requested halt |
| 8 | shutdown | guest triggered shutdown |
| 9 | unknown | other unhandled exit |

vreg layout:

| vreg | location | content |
|---|---|---|
| 1..31 | x0..x30 | guest x0..x30 |
| 32 | `[sp + 8]` | guest PC |
| 33 | `[sp + 16]` | PSTATE |
| 34 | `[sp + 24]` | SP_EL0 |
| 35 | `[sp + 32]` | SP_EL1 |
| 36..54 | `[sp + 40..183]` | SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, MAIR_EL1, AMAIR_EL1, CPACR_EL1, CONTEXTIDR_EL1, TPIDR_EL0, TPIDR_EL1, TPIDRRO_EL0, VBAR_EL1, ELR_EL1, SPSR_EL1, ESR_EL1, FAR_EL1, AFSR0_EL1, AFSR1_EL1, MDSCR_EL1 |
| 55..57 | `[sp + 192..207]` | MIDR_EL1, MPIDR_EL1, REVIDR_EL1 |
| 58..73 | `[sp + 216..335]` | ID_AA64PFR0_EL1, ID_AA64PFR1_EL1, ID_AA64ZFR0_EL1, ID_AA64SMFR0_EL1, ID_AA64DFR0_EL1, ID_AA64DFR1_EL1, ID_AA64AFR0_EL1, ID_AA64AFR1_EL1, ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64ISAR2_EL1, ID_AA64MMFR0_EL1, ID_AA64MMFR1_EL1, ID_AA64MMFR2_EL1, ID_AA64MMFR3_EL1, ID_AA64MMFR4_EL1 |
| 74..81 | `[sp + 344..399]` | CNTV_CVAL_EL0, CNTV_CTL_EL0, CNTV_TVAL_EL0, CNTP_CVAL_EL0, CNTP_CTL_EL0, CNTP_TVAL_EL0, CNTKCTL_EL1, CNTVOFF_EL2 |
| 82..101 | `[sp + 408..559]` | debug regs: DBGBVR0..5_EL1, DBGBCR0..5_EL1, DBGWVR0..3_EL1, DBGWCR0..3_EL1 |
| 102..115 | `[sp + 568..671]` | PMU regs: PMCR_EL0, PMCNTENSET_EL0, PMCNTENCLR_EL0, PMOVSR_EL0, PMOVSSET_EL0, PMSELR_EL0, PMCCNTR_EL0, PMXEVTYPER_EL0, PMXEVCNTR_EL0, PMCCFILTR_EL0, PMINTENSET_EL1, PMINTENCLR_EL1, PMUSERENR_EL0, PMEVCNTR (aggregate) |
| 116 | `[sp + 680]` | packed pending state `{virq u8, vfiq u8, vserror u8}` |
| 117 | `[sp + 688]` | exit sub-code |
| 118..120 | `[sp + 696..719]` | exit payload (per sub-code below) |
| 121..126 | `[sp + 720..767]` | _reserved |
| 127 | `[sp + 768]` | reply capability |

Exit payload per sub-code (up to 3 vregs = 24 bytes; unused vregs in the payload band are `_reserved` for that sub-code):

| Sub-code | vreg[118] | vreg[119] | vreg[120] |
|---|---|---|---|
| stage2_fault | guest_phys | guest_virt | `{access_size u8, srt u8, fsc u8, flags u8}` (flags: instr, write, iss_valid, sign_extend, reg64, acqrel) |
| hvc | `{imm u16}` | _reserved | _reserved |
| smc | `{imm u16}` | _reserved | _reserved |
| sysreg | `{iss u32, op0 u2, op1 u3, crn u4, crm u4, op2 u3, rt u5, is_read u1}` packed | _reserved | _reserved |
| wfi_wfe | `{is_wfe u1}` | _reserved | _reserved |
| unknown_ec | raw EC value | _reserved | _reserved |
| sync_el1 | ESR_EL2 | _reserved | _reserved |
| halt, shutdown | _reserved | _reserved | _reserved |
| unknown | raw ESR_EL2 | _reserved | _reserved |

## §[event_route] Event Route

An event route is a kernel-held binding of events generated by an execution context to a given port, such that the execution context is suspended on the port when the event occurs. Event routes are not handles — they are identified by the `(execution_context, event_type)` tuple and cleared either by explicit syscall or by destruction of the execution context they are bound to.

## §[reply] Reply

A reply is a one-shot capability referencing a suspended execution context that has been dequeued from a port by a receive but has not yet been resumed.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                                              0
┌─────────────────────────────────────────────────────────────────┐
│                        _reserved (16)                           │
└─────────────────────────────────────────────────────────────────┘
```

## §[system_services] System Services

### §[time] Time

### §[rng] RNG

### §[system_info] System Info

### §[power] Power Management
