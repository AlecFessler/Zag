const lib = @import("lib");

const perms = lib.perms;
const perm_view = lib.perm_view;
const syscall = lib.syscall;

/// Shared state mapped into both root service and waiter via shm.
/// Must match the layout in perf_futex.zig.
const Shared = extern struct {
    futex_val: u64,
    wake_timestamp: u64,
    measured_delta: u64,
    waiter_ready: u64,
    waiter_done: u64,
    exit: u64,
    affinity: u64,
};

/// Futex benchmark waiter. Receives shm via cap transfer, maps it,
/// reads affinity from the shared struct, and enters the futex_wait loop.
/// Each wake records TSC delta in the shm for the parent to read.
pub fn main(pv: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = view[i].handle;
            shm_size = view[i].field0;
            break;
        }
    }
    if (shm_handle == 0) syscall.thread_exit();

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) syscall.thread_exit();
    if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) syscall.thread_exit();

    const shared: *Shared = @ptrFromInt(vm.val2);

    _ = syscall.set_affinity(@atomicLoad(u64, &shared.affinity, .acquire));
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    while (@atomicLoad(u64, &shared.exit, .acquire) == 0) {
        @atomicStore(u64, &shared.waiter_ready, 1, .release);
        _ = syscall.futex_wait(@ptrCast(&shared.futex_val), 0, ~@as(u64, 0));

        if (@atomicLoad(u64, &shared.exit, .acquire) != 0) break;

        const woke_at = rdtscp();
        const wake_ts = @atomicLoad(u64, &shared.wake_timestamp, .acquire);
        @atomicStore(u64, &shared.measured_delta, woke_at -% wake_ts, .release);
        @atomicStore(u64, &shared.waiter_done, 1, .release);
    }

    syscall.thread_exit();
}

inline fn rdtscp() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtscp"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        :
        : .{ .rcx = true, .memory = true }
    );
    return (@as(u64, hi) << 32) | lo;
}
