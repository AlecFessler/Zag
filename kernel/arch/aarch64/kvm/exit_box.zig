//! Aarch64 VmExitBox.
//!
//! Mirrors `kernel/arch/x64/kvm/exit_box.zig`. The exit-box bridges the
//! per-vCPU exit stream into the spec-v3 port/reply event machinery:
//! it holds pending exits per-vCPU and dispatches deliveries on the
//! vCPU EC's bound `exit_port` per spec §[virtual_machine].create_vcpu.

const zag = @import("zag");

const EcQueue = zag.sched.scheduler.EcQueue;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const vm_mod = zag.arch.aarch64.kvm.vm;

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
};
