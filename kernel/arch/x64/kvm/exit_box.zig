const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const interrupts = zag.arch.x64.interrupts;
const kvm = zag.arch.x64.kvm;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.x64.vm;
const vm_mod = kvm.vm;

const ArchCpuContext = zag.arch.x64.interrupts.ArchCpuContext;
const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const EcQueue = zag.sched.scheduler.EcQueue;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;
const Vm = vm_mod.Vm;

const MAX_VCPUS = vm_mod.MAX_VCPUS;

pub const VmExitBoxState = enum {
    idle,
    receiving,
    pending_replies,
};

pub const VmExitBox = struct {
    state: VmExitBoxState = .idle,
    queue: EcQueue = .{},
    receiver: ?SlabRef(ExecutionContext) = null,
    pending: [MAX_VCPUS]bool = .{false} ** MAX_VCPUS,
    lock: SpinLock = .{ .class = "VmExitBox.lock" },

    /// Check if any exits are pending resolution.
    pub fn hasPendingExits(self: *VmExitBox) bool {
        for (self.pending) |p| {
            if (p) return true;
        }
        return false;
    }

    /// Check if a receiver EC is blocked waiting.
    pub fn isReceiving(self: *VmExitBox) bool {
        return self.state == .receiving;
    }

    /// Enqueue an exited vCPU EC for delivery. Caller must hold lock.
    /// Internal helper of queueOrDeliver — not for use across modules.
    fn enqueueLocked(self: *VmExitBox, ec: *ExecutionContext) void {
        self.queue.enqueue(ec);
        if (self.state == .idle) {
            self.state = .pending_replies;
        }
    }

    /// Take the blocked receiver EC. Caller must hold lock.
    /// Transitions from receiving to pending_replies. Returns a
    /// `SlabRef(ExecutionContext)` — the consumer must `lock()` before
    /// using the EC pointer.
    /// Internal helper of queueOrDeliver — not for use across modules.
    fn takeReceiverLocked(self: *VmExitBox) SlabRef(ExecutionContext) {
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .pending_replies;
        return r;
    }

    /// Mark a vCPU slot as having a pending exit. Caller must hold lock.
    /// Internal helper — not for use across modules.
    fn markPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = true;
    }

    /// Clear a pending exit for a vCPU slot. Caller must hold lock.
    /// If no more pending exits remain and the queue is empty, transitions to idle.
    fn clearPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = false;
        if (!self.hasPendingExits() and self.queue.isEmpty()) {
            self.state = .idle;
        }
    }
};

/// Message written to userspace buffer on vm_recv.
pub const VmExitMessage = struct {
    exit_handle: u64,
    exit_info: vm_hw.VmExitInfo,
    guest_state: vm_hw.GuestState,
};

/// Action to take when replying to a VM exit.
pub const VmReplyAction = union(enum) {
    resume_guest: vm_hw.GuestState,
    inject_interrupt: vm_hw.GuestInterrupt,
    inject_exception: vm_hw.GuestException,
    map_memory: struct {
        host_vaddr: u64,
        guest_addr: u64,
        size: u64,
        rights: u8,
    },
    kill: void,
};

/// Single home for "an exit happened, push it to userspace". Called by
/// `exit_handler.handleExit` for every VMM-bound exit. Owns the lock,
/// the queue/receiver bookkeeping, and (when a receiver is already
/// blocked) the deliverExit handoff.
pub fn queueOrDeliver(box: *VmExitBox, vm_obj: *Vm, vcpu_obj: *VCpu) void {
    // TODO step 6: rewrite for spec-v3. vm_exit delivery flows through
    // the recv/reply lifecycle on the vCPU EC's exit_port (see
    // `kernel/sched/port.zig` fireVmExit and `kernel/capdom/virtual_machine.zig`
    // handleGuestExit).
    _ = box;
    _ = vm_obj;
    _ = vcpu_obj;
    @panic("step 6: rewrite for spec-v3");
}

/// Deliver an exit to an EC that is already blocked in `vm_recv`.
/// Marks the vCPU pending, transitions it to .waiting_reply, writes the
/// exit message to the receiver's saved buffer, and wakes the receiver.
fn deliverExit(vm_obj: *Vm, vcpu_obj: *VCpu, receiver: *ExecutionContext) void {
    // TODO step 6: rewrite for spec-v3. Receiver wake-up and exit
    // payload write use the spec-v3 port recv path and the per-EC
    // exit_port write-cap snapshot.
    _ = vm_obj;
    _ = vcpu_obj;
    _ = receiver;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall implementation: dequeue from exit box, write VmExitMessage
/// to userspace buffer, return exit token (= vCPU EC handle).
pub fn vmRecv(domain: *CapabilityDomain, vcpu_ec: *ExecutionContext, ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: bool) i64 {
    // TODO step 6: rewrite for spec-v3. vm_exit delivery folds into
    // recv on the vCPU's `exit_port`, which returns the reply handle
    // and writes guest state to the receiver's vregs. See spec
    // §[vm_exit_state] / §[port].recv.
    _ = domain;
    _ = vcpu_ec;
    _ = ctx;
    _ = vm_handle;
    _ = buf_ptr;
    _ = blocking;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall implementation: resolve a pending exit by token.
pub fn vmReply(domain: *CapabilityDomain, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. Replies consume a reply handle
    // minted by recv on the vCPU's exit_port. Action decoding lives on
    // the generic-side reply path (spec §[reply] / §[vm_exit_state]);
    // per-arch resume sequencing flows through
    // dispatch.vm.{loadGuestState,enterGuest}.
    _ = domain;
    _ = vm_handle;
    _ = exit_token;
    _ = action_ptr;
    @panic("step 6: rewrite for spec-v3");
}

fn deliverExitMessage(domain: *CapabilityDomain, vm_obj: *Vm, ec: *ExecutionContext, buf_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. Message layout follows the
    // spec-v3 vm_exit vreg encoding (spec §[vm_exit_state]).
    _ = domain;
    _ = vm_obj;
    _ = ec;
    _ = buf_ptr;
    @panic("step 6: rewrite for spec-v3");
}

fn writeExitMessageToUser(domain: *CapabilityDomain, buf_ptr: u64, handle_id: u64, vcpu_obj: *VCpu) void {
    // TODO step 6: rewrite for spec-v3. Guest state is delivered via
    // the receiver's vregs at recv time.
    _ = domain;
    _ = buf_ptr;
    _ = handle_id;
    _ = vcpu_obj;
    @panic("step 6: rewrite for spec-v3");
}

/// Read bytes from userspace into a kernel buffer, handling cross-page boundaries.
fn readUserBytes(domain: *CapabilityDomain, user_va: u64, buf: []u8) bool {
    // TODO step 6: rewrite for spec-v3. Capability-domain user-memory
    // accessors live behind a different API.
    _ = domain;
    _ = user_va;
    _ = buf;
    @panic("step 6: rewrite for spec-v3");
}

fn vcpuIndex(vm_obj: *Vm, vcpu_obj: *VCpu) ?u32 {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v.ptr == vcpu_obj) return @intCast(i);
    }
    return null;
}

fn resumeVcpuEc(ec: *ExecutionContext) void {
    while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    ec.state = .ready;
    const target_core = if (ec.affinity != 0) @as(u64, @ctz(ec.affinity)) else apic.coreID();
    sched.enqueueOnCore(@intCast(target_core), ec);
}

/// Resolve a VM handle from the caller's capability domain table.
fn resolveVmHandle(domain: *CapabilityDomain, vm_handle: u64) ?*Vm {
    // TODO step 6: rewrite for spec-v3. Handle resolution goes through
    // the CapabilityDomain user/kernel handle tables and returns
    // `VirtualMachine` from `kernel/capdom/virtual_machine.zig`.
    _ = domain;
    _ = vm_handle;
    @panic("step 6: rewrite for spec-v3");
}
