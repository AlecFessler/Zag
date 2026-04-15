//! Composed kprof workload: debugger scenario + SHM-cycle driver in one
//! root_service process. Intended for CI perf runs so a single trace
//! dump captures both workloads' syscall paths (fault delivery / IPC
//! handoff from the debugger path, mem_reserve / mem_shm_map /
//! mem_unmap / revoke_perm from the SHM-cycle path) in a single "OS"
//! boot. See tests/prof/src/{debugger,shm_cycle}.zig for the individual
//! workloads.
//!
//! Flow:
//!   1. Spawn child_debugger and child_debuggee, then ipc_call_cap the
//!      debugger handle into the debuggee's perm table. After this the
//!      debuggee enters its bp_stop loop and the debugger runs forever
//!      until the OS shuts down.
//!   2. Spawn child_shm_cycle and run 50 iterations of SHM create/map/
//!      touch/unmap/revoke against it.
//!   3. syscall.shutdown() — kills the debugger/debuggee processes
//!      alongside root so QEMU exits cleanly and the trace dump is
//!      flushed.

const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

const PAGE_SIZE: u64 = 4096;
const SHM_PAGES: u64 = 16;
const SHM_SIZE: u64 = SHM_PAGES * PAGE_SIZE;
const SHM_ITERATIONS: u64 = 50;

pub fn main(_: u64) void {
    runDebuggerHandoff();
    runShmCycle();
    syscall.shutdown();
}

/// Mirror of tests/prof/src/debugger.zig main, minus the self-suspend
/// at the end so the composed workload can continue into the SHM cycle.
fn runDebuggerHandoff() void {
    const debugger_rights = (perms.ProcessRights{}).bits();
    const dbg_rc = syscall.proc_create(
        @intFromPtr(children.child_debugger.ptr),
        children.child_debugger.len,
        debugger_rights,
    );
    if (dbg_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const debugger_h: u64 = @bitCast(dbg_rc);

    const debuggee_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const dee_rc = syscall.proc_create(
        @intFromPtr(children.child_debuggee.ptr),
        children.child_debuggee.len,
        debuggee_rights,
    );
    if (dee_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const debuggee_h: u64 = @bitCast(dee_rc);

    const xfer_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(
        debuggee_h,
        &.{ debugger_h, xfer_rights },
        &reply,
    );
}

/// Mirror of tests/prof/src/shm_cycle.zig main, minus the final
/// syscall.shutdown() so the composed workload can own termination.
fn runShmCycle() void {
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
    }).bits();
    const ch_rc: i64 = syscall.proc_create(
        @intFromPtr(children.child_shm_cycle.ptr),
        children.child_shm_cycle.len,
        child_rights,
    );
    if (ch_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const child_handle: u64 = @bitCast(ch_rc);

    const shm_rights = perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    var iter: u64 = 0;
    while (iter < SHM_ITERATIONS) : (iter += 1) {
        const shm_rc = syscall.shm_create_with_rights(SHM_SIZE, shm_rights.bits());
        if (shm_rc < 0) {
            syscall.thread_yield();
            continue;
        }
        const shm_handle: u64 = @bitCast(shm_rc);

        var reply: syscall.IpcMessage = .{};
        if (syscall.ipc_call_cap(
            child_handle,
            &.{ shm_handle, shm_rights.bits() },
            &reply,
        ) != 0) {
            _ = syscall.revoke_perm(shm_handle);
            syscall.thread_yield();
            continue;
        }

        const vm = syscall.mem_reserve(0, SHM_SIZE, vm_rights);
        if (vm.val < 0) {
            _ = syscall.revoke_perm(shm_handle);
            continue;
        }
        const vm_handle: u64 = @bitCast(vm.val);

        if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) {
            _ = syscall.revoke_perm(vm_handle);
            _ = syscall.revoke_perm(shm_handle);
            continue;
        }

        const base: [*]volatile u8 = @ptrFromInt(vm.val2);
        var off: u64 = 0;
        while (off < SHM_SIZE) {
            base[off] = 1;
            off += PAGE_SIZE;
        }

        _ = syscall.mem_unmap(vm_handle, 0, SHM_SIZE);
        _ = syscall.revoke_perm(vm_handle);
        _ = syscall.revoke_perm(shm_handle);
    }
}
