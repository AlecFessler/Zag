const zag = @import("zag");

const EcQueue = zag.sched.scheduler.EcQueue;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const vm_mod = zag.arch.x64.kvm.vm;

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
};
