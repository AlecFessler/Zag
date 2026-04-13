const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

const ITERATIONS: u32 = 1000;

/// Shared struct mapped into both root service and waiter child via shm.
/// Must match the layout in child_perf_futex_waiter.zig.
const Shared = extern struct {
    futex_val: u64,
    wake_timestamp: u64,
    measured_delta: u64,
    waiter_ready: u64,
    waiter_done: u64,
    exit: u64,
    affinity: u64,
};

/// Futex benchmarks covering the distinct kernel paths:
/// - uncontended_wait: value mismatch, futex_wait returns immediately
/// - wake_no_waiters: futex_wake with nobody sleeping
/// - wake_one_cross_core: cross-process wake (shm), waiter on different core
/// - wake_one_same_core: cross-process wake (shm), waiter on same core
pub fn main(_: u64) void {
    // Drop root's default .pinned priority before set_affinity; see
    // kernel/syscall/thread.zig:98 (set_affinity is E_BUSY while pinned).
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);

    benchUncontendedWait();
    benchWakeNoWaiters();

    // Reset priority so the child can be scheduled (runBench set REALTIME)
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);

    benchCrossProcessWake("futex_wake_one_cross_core", 2);
    benchCrossProcessWake("futex_wake_one_same_core", 1);

    syscall.shutdown();
}

// --- Fast-path variants (single process, no cross-address-space needed) ---

var local_futex: u64 = 0;

fn uncontendedWaitBody() void {
    // expected=1, actual=0 → fast-path return
    _ = syscall.futex_wait(@ptrCast(&local_futex), 1, 0);
}

fn benchUncontendedWait() void {
    @atomicStore(u64, &local_futex, 0, .release);
    _ = bench.runBench(.{
        .name = "futex_uncontended_wait",
        .warmup = 1000,
        .iterations = 10000,
    }, uncontendedWaitBody);
}

fn wakeNoWaitersBody() void {
    _ = syscall.futex_wake(@ptrCast(&local_futex), 1);
}

fn benchWakeNoWaiters() void {
    _ = bench.runBench(.{
        .name = "futex_wake_no_waiters",
        .warmup = 1000,
        .iterations = 10000,
    }, wakeNoWaitersBody);
}

// --- Cross-process wake via shm ---

fn benchCrossProcessWake(name: []const u8, waiter_affinity: u64) void {
    const shm_size: u64 = 4096;
    const shm_rights = perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    };
    const shm_rc = syscall.shm_create_with_rights(shm_size, shm_rights.bits());
    if (shm_rc < 0) {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP shm_create failed\n");
        return;
    }
    const shm_handle: u64 = @bitCast(shm_rc);

    // Map shm in root service
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) {
        _ = syscall.revoke_perm(shm_handle);
        return;
    }
    if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) {
        _ = syscall.revoke_perm(shm_handle);
        return;
    }

    const shared: *Shared = @ptrFromInt(vm.val2);
    shared.* = .{
        .futex_val = 0,
        .wake_timestamp = 0,
        .measured_delta = 0,
        .waiter_ready = 0,
        .waiter_done = 0,
        .exit = 0,
        .affinity = waiter_affinity,
    };

    // Spawn waiter child
    const child_rights = (perms.ProcessRights{
        .mem_reserve = true,
        .mem_shm_create = true,
        .set_affinity = true,
    }).bits();
    const waiter_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_futex_waiter.ptr),
        children.child_perf_futex_waiter.len,
        child_rights,
    );
    if (waiter_rc < 0) {
        _ = syscall.revoke_perm(shm_handle);
        return;
    }
    const waiter_handle: u64 = @bitCast(waiter_rc);

    // Single cap-transfer IPC: child receives shm handle, reads affinity from shm
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(waiter_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Run measurement loop
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        @atomicStore(u64, &shared.exit, 1, .release);
        _ = syscall.revoke_perm(waiter_handle);
        _ = syscall.revoke_perm(shm_handle);
        return;
    };
    const buf = buf_ptr[0..ITERATIONS];

    // Warmup
    var w: u32 = 0;
    while (w < 100) {
        wakeOnce(shared);
        w += 1;
    }

    // Measurement
    var i: u32 = 0;
    while (i < ITERATIONS) {
        wakeOnce(shared);
        buf[i] = @atomicLoad(u64, &shared.measured_delta, .acquire);
        i += 1;
    }

    // Tell waiter to exit
    @atomicStore(u64, &shared.exit, 1, .release);
    @atomicStore(u64, &shared.futex_val, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&shared.futex_val), 1);

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report(name, result);

    _ = syscall.revoke_perm(waiter_handle);
    _ = syscall.revoke_perm(shm_handle);
}

fn wakeOnce(shared: *Shared) void {
    // Wait for waiter to announce it is armed in futex_wait.
    while (@atomicLoad(u64, &shared.waiter_ready, .acquire) == 0) {
        syscall.thread_yield();
    }
    @atomicStore(u64, &shared.waiter_ready, 0, .release);

    @atomicStore(u64, &shared.wake_timestamp, bench.rdtscp(), .release);
    @atomicStore(u64, &shared.futex_val, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&shared.futex_val), 1);

    // Wait for the waiter to record its delta for this round.
    while (@atomicLoad(u64, &shared.waiter_done, .acquire) == 0) {
        syscall.thread_yield();
    }
    // Re-arm for the next round BEFORE clearing waiter_done. Clearing
    // waiter_done is what the waiter polls on after its rearm handshake,
    // so futex_val must already be back to 0 when the waiter observes
    // waiter_done==0; otherwise the waiter's next futex_wait fast-fails
    // with E_AGAIN and we never block on the real wake path.
    @atomicStore(u64, &shared.futex_val, 0, .release);
    @atomicStore(u64, &shared.waiter_done, 0, .release);
}
