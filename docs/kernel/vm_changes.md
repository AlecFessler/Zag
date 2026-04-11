# Zag Microkernel — VM Support Design

This document describes the virtual machine support being added to Zag. It is almost entirely new additions — existing kernel primitives are largely unchanged. The agents updating the spec and systems docs should use this as the source of truth.

---

## Overview

Zag supports hosting virtual machines via a set of new kernel primitives. A userspace VM manager process creates and manages VMs, handles VM exits that require policy decisions or device emulation, and communicates with other Zag services for device I/O. The kernel handles low-level VM mechanics — setting up hardware virtualization structures, managing guest memory, dispatching exits — but policy lives in userspace.

The design is intentionally generic. All architecture-specific VM concepts (VMCS, EPT, VMXON on x64; equivalent structures on other architectures) are hidden behind the arch dispatch layer. The kernel proper never references x64-specific types or concepts.

---

## Architecture Layering

The arch dispatch layer for VM support follows the same pattern as the rest of the kernel:

```
arch/dispatch.zig       — generic VM interface, comptime dispatch on arch
arch/x64/vm.zig         — x64 VM interface, runtime dispatch on CPU vendor (Intel vs AMD)
arch/x64/intel/vmx.zig  — Intel VT-x implementation
arch/x64/amd/svm.zig    — AMD-V/SVM implementation
```

The runtime vs comptime distinction matters: Intel vs AMD is a runtime check (CPUID vendor detection at boot) because the same kernel binary runs on both. x64 vs other architectures is comptime because you cross-compile for a target.

The generic types exposed by `arch/dispatch.zig` for VM support:

- `arch.GuestState` — full guest register state snapshot, arch-specific layout
- `arch.VmExitInfo` — exit reason and qualification data, arch-specific tagged union
- `arch.GuestInterrupt` — interrupt to inject into a guest, arch-specific
- `arch.GuestException` — exception to inject into a guest, arch-specific  
- `arch.VmPolicy` — static policy table for inline exit handling, arch-specific

All of these are opaque to the generic kernel layer. The arch layer is responsible for their layout, serialization, and interpretation. aarch64 stubs exist as empty structs so the kernel compiles — implementation comes later.

---

## New Kernel Objects

### Vm

A Vm represents a virtual machine. It is owned by a process — specifically the VM manager process. A process can own at most one Vm. The Vm is stored as an optional field on Process:

```
Process {
    // ... existing fields ...
    vm: ?*Vm
}
```

The Vm struct:

```
Vm {
    vcpus:      [MAX_VCPUS]*VCpu
    num_vcpus:  u32
    owner:      *Process
    exit_box:   VmExitBox
    policy:     arch.VmPolicy       // static, set at creation, never changes
    lock:       SpinLock
    vm_id:      u64                 // monotonic ID
}
```

`MAX_VCPUS` = 64, matching `MAX_THREADS`.

The Vm is not a perm table entry type — ownership is implicit via `proc.vm`. A process interacts with its VM via VM syscalls which check `proc.vm != null`. No capability transfer of VM objects is supported.

When the VM manager process dies, the kernel destroys its Vm as part of process cleanup, same as address space teardown.

### VCpu

A vCPU represents a virtual CPU. It owns a Zag thread (which the scheduler treats like any other thread) and arch-specific hardware virtualization state. vCPU threads are not created via `thread_create` — they are created internally by the kernel when `vm_create` is called.

```
VCpu {
    thread:      *Thread
    vm:          *Vm
    guest_state: arch.GuestState    // current guest register snapshot
    state:       VCpuState          // { idle, running, exited, waiting_reply }
}
```

`VCpuState.idle` — created but not yet started via `vm_vcpu_run`.
`VCpuState.running` — actively executing guest code or scheduled to do so.
`VCpuState.exited` — hit a VM exit, waiting for `vm_reply`.
`VCpuState.waiting_reply` — exit message delivered, pending reply.

vCPU threads have a fixed kernel-managed entry point. When scheduled, they execute the arch equivalent of VMRESUME. When a VM exit fires, the hardware returns to host mode on that thread's kernel stack and the arch VM exit handler runs.

vCPU threads appear in the VM manager process's permissions table as normal thread handles with full `ThreadHandleRights`. This means a debugger attaching to the VM manager process gets thread handles for vCPU threads and can suspend/inspect them like any thread.

---

## VmExitBox

The VmExitBox is a message box on the Vm struct, separate from the VM manager process's fault box and IPC message box. This separation is critical — a debugger attaching to the VM manager process acquires the fault box but has no access to the VmExitBox.

```
VmExitBox {
    state:    VmExitBoxState    // { idle, receiving, pending_replies }
    queue:    PriorityQueue     // queued exited vCPUs waiting to be recv'd
    receiver: ?*Thread          // thread blocked on vm_recv
    pending:  [MAX_VCPUS]bool   // which vCPUs have unresolved exits
    lock:     SpinLock
}
```

Unlike FaultBox which has a single `pending_reply` constraint, VmExitBox tracks one pending exit per vCPU independently. Multiple vCPUs can exit simultaneously — each enqueues on the box. The VM manager dequeues and replies to each via the exit token (which is the vCPU's thread handle ID). The box moves to `idle` only when all pending exits are resolved.

State transitions:
- `idle` → `receiving`: VM manager calls blocking `vm_recv` with empty queue
- `idle` → `pending_replies`: first vCPU exit arrives, VM manager calls `vm_recv` and dequeues it
- `receiving` → `pending_replies`: vCPU exit delivered directly to blocked receiver
- `pending_replies` → `idle`: last pending exit resolved via `vm_reply`
- `pending_replies` → `pending_replies`: additional vCPU exits arrive or are resolved while others remain pending

---

## VmExitMessage

The struct written to the userspace buffer on `vm_recv`:

```
VmExitMessage {
    thread_handle: u64              // vCPU thread handle ID in caller's perm table
    exit_info:     arch.VmExitInfo  // arch-specific exit reason and qualification
    guest_state:   arch.GuestState  // full guest register snapshot at time of exit
}
```

The exit token returned by `vm_recv` is equal to `thread_handle`. The VM manager uses it to identify which vCPU to reply to.

---

## Kernel-Handled vs VMM-Handled Exits

The kernel classifies VM exits into two categories at the arch dispatch layer:

**Kernel-handled inline** — exits that can be resolved without VMM involvement:
- Guest memory access on an already-mapped demand-paged region — kernel maps the page and resumes, same as host demand paging
- Guest CPU feature queries where the queried feature is in `vm.policy` — kernel returns the pre-configured response
- Guest privileged register accesses where the register is in `vm.policy` — kernel returns or accepts the pre-configured value

**VMM-handled** — exits delivered to the VmExitBox:
- Guest device I/O (port I/O, MMIO on unmapped regions)
- Guest memory access on unmapped regions not covered by demand paging
- Guest CPU feature queries not in `vm.policy`
- Guest privileged register accesses not in `vm.policy`
- Guest halt
- Guest shutdown or unrecoverable fault

The policy table (`arch.VmPolicy`) is set at `vm_create` time and never changes. It is entirely arch-specific in content — the generic kernel just stores it on the Vm struct and passes it to the arch layer on every exit.

---

## Guest Memory

Guest physical address space is managed separately from host virtual address space. The VM has its own arch-specific guest physical memory structures (EPT on x64, Stage-2 page tables on ARM).

`vm_guest_map(addr, size, rights)` maps a range of guest physical address space backed by private demand-paged memory. The kernel allocates physical pages on access, same as host demand paging. `rights` controls guest access permissions (read, write, execute) in the guest physical memory structures. This is how the VMM establishes guest RAM before booting.

EPT violations (or equivalent) on demand-paged regions are handled inline by the kernel — no exit delivered to the VMM. EPT violations on unmapped regions are delivered to the VMM as exits, allowing the VMM to either call `vm_guest_map` to back the region or inject a fault into the guest.

---

## Interrupt Injection

The VMM can inject interrupts into a vCPU at any time via `vm_vcpu_interrupt`. If the vCPU thread is currently running on a core, the kernel sends an IPI to that core, suspends the vCPU thread, injects the interrupt into the arch-specific interrupt injection mechanism, and immediately resumes the vCPU. From the guest's perspective the interrupt simply arrives. No VM exit is delivered to the VMM.

If the vCPU is not currently running (suspended or waiting for a vm_reply), the kernel writes the pending interrupt directly into the vCPU's arch state and it fires on next resume.

---

## vm_reply Actions

The action passed to `vm_reply` is a tagged union:

```
VmReplyAction = union(enum) {
    resume:           arch.GuestState       // resume with possibly modified guest state
    inject_interrupt: arch.GuestInterrupt   // resume with virtual interrupt pending
    inject_exception: arch.GuestException   // resume with exception pending
    map_memory: struct {
        addr:       u64    // guest physical address
        size:       u64
        rights:     u8     // read, write, execute bits
    }                      // map demand-paged memory at guest physical addr, then resume
    kill:             void // terminate the vCPU
}
```

`map_memory` is a convenience reply action that combines `vm_guest_map` + resume in one round trip, for handling EPT violations on unmapped regions without a separate syscall.

`arch.GuestException` is arch-specific and opaque to the generic kernel layer. It carries whatever the arch layer needs to inject an exception into the guest — vector, error code, fault address etc. The arch layer knows what to do with it.

---

## Syscall Surface

All VM syscalls check that the calling process has a VM (`proc.vm != null`) unless otherwise noted. All return `E_INVAL` if the calling process has no VM where applicable.

**`vm_create(vcpu_count, policy_ptr) → result`**
Creates a Vm, initializes arch-specific hardware virtualization structures, creates `vcpu_count` vCPU threads with fixed kernel-managed entry points, inserts thread handles for all vCPUs into the calling process's permissions table with full `ThreadHandleRights`, sets `proc.vm`. `policy_ptr` points to an `arch.VmPolicy` struct that is stored on the Vm and never changes. Returns `E_INVAL` if `vcpu_count` is 0 or exceeds `MAX_VCPUS`. Returns `E_INVAL` if the calling process already has a VM. Returns `E_NOMEM` on allocation failure. Returns `E_NODEV` if the hardware does not support virtualization. Returns `E_MAXCAP` if the permissions table cannot fit all vCPU thread handles.

**`vm_destroy() → result`**
Kills all vCPU threads, tears down guest memory mappings, frees arch-specific virtualization structures, frees the Vm struct, clears `proc.vm`. Returns `E_OK` on success.

**`vm_guest_map(addr, size, rights) → result`**
Maps a range of guest physical address space at `addr` with `size` bytes, backed by private demand-paged memory. `rights` is a bitmask of guest access permissions. Returns `E_INVAL` for zero size, non-page-aligned addr or size, or invalid rights bits. Returns `E_NOMEM` on allocation failure.

**`vm_recv(buf_ptr, blocking) → exit_token`**
Reads from the VM's exit box. Writes a `VmExitMessage` to `buf_ptr`. Returns the exit token (vCPU thread handle ID) on success. With blocking flag set, blocks when no exits are pending. With blocking flag clear, returns `E_AGAIN` when no exits are pending. Returns `E_BADADDR` if `buf_ptr` is not a writable region of `sizeof(VmExitMessage)` bytes.

**`vm_reply(exit_token, action_ptr) → result`**
Resolves a pending VM exit identified by `exit_token`. `action_ptr` points to a `VmReplyAction`. Returns `E_NOENT` if `exit_token` does not match any pending exit. Returns `E_BADADDR` if `action_ptr` is not readable. Returns `E_INVAL` for invalid action type.

**`vm_vcpu_set_state(thread_handle, guest_state_ptr) → result`**
Sets the full guest register state for a vCPU. Only valid when the vCPU is in `idle` state (before `vm_vcpu_run`). Returns `E_BADHANDLE` if `thread_handle` does not refer to a vCPU thread. Returns `E_BUSY` if the vCPU is not in `idle` state. Returns `E_BADADDR` if `guest_state_ptr` is not a readable region of `sizeof(arch.GuestState)` bytes.

**`vm_vcpu_get_state(thread_handle, guest_state_ptr) → result`**
Reads the full guest register state for a vCPU. If the vCPU is currently running, the kernel IPIs its core, suspends it, snapshots the state, writes to `guest_state_ptr`, and immediately resumes. If the vCPU is already suspended, reads state directly. Returns `E_BADHANDLE` if `thread_handle` does not refer to a vCPU thread. Returns `E_BADADDR` if `guest_state_ptr` is not a writable region of `sizeof(arch.GuestState)` bytes.

**`vm_vcpu_run(thread_handle) → result`**
Transitions a vCPU from `idle` to `running` state, making its thread eligible for scheduling. Returns `E_BADHANDLE` if `thread_handle` does not refer to a vCPU thread. Returns `E_BUSY` if the vCPU is not in `idle` state.

**`vm_vcpu_interrupt(thread_handle, interrupt_ptr) → result`**
Injects a virtual interrupt into a vCPU. `interrupt_ptr` points to an `arch.GuestInterrupt`. If the vCPU is running, IPIs its core, injects the interrupt, resumes immediately. If the vCPU is suspended or waiting for a reply, writes the pending interrupt into its arch state for delivery on next resume. Returns `E_BADHANDLE` if `thread_handle` does not refer to a vCPU thread. Returns `E_BADADDR` if `interrupt_ptr` is not readable.

---

## Process Cleanup

When the VM manager process exits or is killed, the kernel calls the equivalent of `vm_destroy` as part of process cleanup — all vCPU threads are killed, guest memory is freed, arch-specific structures are torn down, and `proc.vm` is cleared. This happens before the process's own address space is freed.

---

## New Files — Create These

Every file listed here must be created as a new file. Do not add this code to existing files. Agents tend to shove new code into existing files — do not do that here.

### `kernel/kvm/` — new directory

This is the primary new directory. All VM and vCPU kernel logic lives here.

**`kernel/kvm/vm.zig`** — `Vm` struct definition, `vm_create`, `vm_destroy`, `vm_guest_map` implementations. Owns the Vm slab allocator. Handles process cleanup path (called from process exit to destroy the VM).

**`kernel/kvm/vcpu.zig`** — `VCpu` struct definition, `vm_vcpu_run`, `vm_vcpu_set_state`, `vm_vcpu_get_state`, `vm_vcpu_interrupt` implementations. Owns the VCpu slab allocator. Contains the fixed kernel-managed vCPU thread entry point that executes the arch resume instruction.

**`kernel/kvm/exit_box.zig`** — `VmExitBox` and `VmExitMessage` struct definitions. The exit box state machine (idle, receiving, pending_replies). `vm_recv` and `vm_reply` implementations. `VmReplyAction` tagged union definition.

**`kernel/kvm/exit_handler.zig`** — the VM exit dispatch path. Called by the arch layer when a VM exit fires. Classifies exits as kernel-handled or VMM-handled. For kernel-handled exits, resolves inline and resumes. For VMM-handled exits, snapshots guest state, enqueues on the exit box, transitions vCPU to `exited` state.

**`kernel/kvm/guest_memory.zig`** — guest physical address space management. Tracks guest physical memory mappings per Vm. Handles demand paging for `vm_guest_map` regions — allocates physical pages on guest memory access fault, maps into arch-specific guest memory translation structures. Guest-physical analog of `kernel/memory/vmm.zig`.

**`kernel/kvm/kvm.zig`** — module root, re-exports all kvm types. Referenced by `kernel/zag.zig`.

### `kernel/arch/x64/intel/vmx.zig` — new file in existing directory

Intel VT-x implementation. VMXON/VMXOFF, VMCS allocation and initialization, VMCS field read/write, VM entry/exit, EPT setup and management, posted interrupt support. Implements the interface defined in `kernel/arch/x64/vm.zig`. Contains all Intel-specific constants, VMCS field encodings, and exit reason codes.

### `kernel/arch/x64/amd/svm.zig` — new file in existing directory

AMD-V/SVM stub. Empty implementations of the interface defined in `kernel/arch/x64/vm.zig`. Returns `E_NODEV` for all calls. To be implemented later.

### `kernel/arch/x64/vm.zig` — new file

x64-level VM interface. Detects Intel vs AMD at runtime via CPUID vendor check at boot. Dispatches all VM operations to either `vmx.zig` or `svm.zig`. Defines the x64-specific concrete types that implement the arch-generic interfaces:

- `GuestState` — all x64 guest registers (GP regs, RIP, RSP, RFLAGS, CR0/2/3/4, segment registers, MSRs that need saving)
- `VmExitInfo` — tagged union of all x64 exit reasons with their qualification data
- `GuestInterrupt` — x64 interrupt injection fields (vector, type, error code valid flag)
- `GuestException` — x64 exception injection fields (vector, error code, fault address)
- `VmPolicy` — x64 policy table (CPU feature query responses, privileged register policy)

Also handles per-core VMX/SVM initialization called from `sched.perCoreInit()`. Detects hardware virtualization support and sets a global flag checked by `vm_create`.

### Additions to `kernel/arch/dispatch.zig` — existing file, add new section

Add a VM dispatch section to the existing dispatch file. Do not reorganize existing content. The new section adds:

- `pub const GuestState = switch (builtin.cpu.arch) { .x86_64 => x64.GuestState, .aarch64 => aarch64.GuestState, else => @compileError(...) }`
- Same pattern for `VmExitInfo`, `GuestInterrupt`, `GuestException`, `VmPolicy`
- `pub fn vmInit() void` — dispatches to arch VM initialization
- `pub fn vmPerCoreInit() void` — dispatches to per-core arch VM setup
- `pub fn vmSupported() bool` — returns whether hardware virtualization is available

The aarch64 variants are empty struct stubs that compile but have no implementation.

### Additions to `kernel/arch/syscall.zig` — existing file, add new cases

Add dispatch cases for the new VM syscalls: `vm_create`, `vm_destroy`, `vm_guest_map`, `vm_recv`, `vm_reply`, `vm_vcpu_set_state`, `vm_vcpu_get_state`, `vm_vcpu_run`, `vm_vcpu_interrupt`. These dispatch to the implementations in `kernel/kvm/`.

### Additions to `kernel/main.zig` — existing file, add init calls

Add `arch.vmInit()` to the boot sequence after `arch.parseFirmwareTables` and before `sched.globalInit()`. Add `arch.vmPerCoreInit()` to the per-core init sequence in `sched.perCoreInit()`.

### Additions to `kernel/zag.zig` — existing file, add re-export

Add `pub const kvm = @import("kvm/kvm.zig")` alongside the existing module re-exports.

### Additions to `kernel/sched/process.zig` — existing file, add vm field

Add `vm: ?*kvm.Vm = null` to the Process struct. Add call to `kvm.vm.destroy()` in the process cleanup path if `proc.vm != null`, before address space teardown.

### Slab Allocators — add to `kernel/memory/init.zig`

Two new slabs with dedicated bump allocator backing regions:
- `VmAllocator = SlabAllocator(kvm.Vm, false, 0, 64)` — 16 MiB bump region
- `VCpuAllocator = SlabAllocator(kvm.VCpu, false, 0, 64)` — 16 MiB bump region

Initialize these in `memory.init()` alongside the existing slabs.

---

## Systems Notes

VmExitBox lock ordering: acquire `exit_box.lock` before `fault_box.lock` if both are ever needed simultaneously. In practice they should never be needed at the same time.

vCPU threads are allocated from the existing `ThreadAllocator` slab. The vCPU thread entry point in `kernel/kvm/vcpu.zig` calls into the arch layer to execute the hardware resume instruction. When a VM exit fires, the arch layer calls `kernel/kvm/exit_handler.zig` to dispatch the exit.

Hardware virtualization availability is detected once at boot in `arch.vmInit()` and cached. `vm_create` checks this cached flag and returns `E_NODEV` if virtualization is unavailable rather than attempting to use the hardware.

---

## Systems Notes

VmExitBox lock ordering: acquire `exit_box.lock` before `fault_box.lock` if both are ever needed simultaneously. In practice they should never be needed at the same time.

vCPU threads are allocated from the existing `ThreadAllocator` slab. The vCPU thread entry point in `kernel/kvm/vcpu.zig` calls into the arch layer to execute the hardware resume instruction. When a VM exit fires, the arch layer calls `kernel/kvm/exit_handler.zig` to dispatch the exit.

Hardware virtualization availability is detected once at boot in `arch.vmInit()` and cached. `vm_create` checks this cached flag and returns `E_NODEV` if virtualization is unavailable rather than attempting to use the hardware.
