//! Aarch64 VmExitBox.
//!
//! Mirrors `kernel/arch/x64/kvm/exit_box.zig`. The exit-box bridges the
//! per-vCPU exit stream into the spec-v3 port/reply event machinery:
//! it holds pending exits per-vCPU and dispatches deliveries on the
//! vCPU EC's bound `exit_port` per spec §[virtual_machine].create_vcpu.
//!
//! Almost everything here is architecture-neutral. The only arch-specific
//! parts are the `vm_hw.GuestState` / `VmExitInfo` / `GuestInterrupt` /
//! `GuestException` types, which differ between x86 and ARM. There is no
//! ARM equivalent of the x86 "reject vector < 32" check in
//! `inject_interrupt` — see the GICv3 §2.2.1 INTID range comment.

const std = @import("std");
const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.aarch64.vm;
const vm_mod = kvm.vm;

const EcQueue = zag.sched.execution_context.EcQueue;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
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

    pub fn hasPendingExits(self: *VmExitBox) bool {
        for (self.pending) |p| {
            if (p) return true;
        }
        return false;
    }

    pub fn isReceiving(self: *VmExitBox) bool {
        return self.state == .receiving;
    }

    fn enqueueLocked(self: *VmExitBox, ec: *ExecutionContext) void {
        self.queue.enqueue(ec);
        if (self.state == .idle) {
            self.state = .pending_replies;
        }
    }

    fn takeReceiverLocked(self: *VmExitBox) SlabRef(ExecutionContext) {
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .pending_replies;
        return r;
    }

    fn markPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = true;
    }

    fn clearPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = false;
        if (!self.hasPendingExits() and self.queue.isEmpty()) {
            self.state = .idle;
        }
    }
};

/// Spec §[virtual_machine] vm_exit payload header. Matches the layout
/// emitted by the recv path on a vm_exit event.
pub const VmExitMessage = struct {
    ec_handle: u64,
    exit_info: vm_hw.VmExitInfo,
    guest_state: vm_hw.GuestState,
};

/// Spec §[virtual_machine] reply payload tag.
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

// TODO(step 6): wire the queue/deliver path to fire vm_exit events on
// the vCPU EC's bound `exit_port` (spec §[virtual_machine].create_vcpu
// test 12) and to consume replies through the standard reply-handle
// lifecycle.

/// Single home for "an exit happened, push it to userspace". Called by
/// `exit_handler.handleExit` for every VMM-bound exit.
pub fn queueOrDeliver(box: *VmExitBox, vm_obj: *Vm, vcpu_obj: *VCpu) void {
    _ = box;
    _ = vm_obj;
    _ = vcpu_obj;
    @panic("step 6: rewrite for spec-v3");
}

