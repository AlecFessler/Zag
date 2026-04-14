const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.10 — When a thread faults and an external process holds `fault_handler` for it, the faulting thread enters `.faulted` state; all other threads in the process that are `.running` or `.ready` enter `.suspended` state (stop-all); a fault message is enqueued in the handler's fault box.
pub fn main(pv: u64) void {
    _ = pv;

    // Allocate a one-page SHM region the child can also map. The child's
    // worker thread will increment a counter here; after the fault, stop-all
    // should freeze it.
    const shm_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(0x1000, shm_rights)));

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, 0x1000, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§4.1.10 mem_reserve");
        syscall.shutdown();
    }
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) {
        t.fail("§4.1.10 mem_shm_map");
        syscall.shutdown();
    }
    const counter_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    counter_ptr.* = 0;

    // Spawn the child and cap-transfer the SHM handle via ipc_call. The
    // child maps it, spawns a worker writing to it, and replies with
    // HANDLE_SELF+fault_handler so we become its external fault handler.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_shm_counter_then_fault.ptr),
        children.child_shm_counter_then_fault.len,
        child_rights,
    )));

    const shm_cap_rights: u64 = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_cap_rights }, &reply);

    // Block until the fault arrives.
    var fault_buf: [syscall.fault_msg_size]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§4.1.10 fault_recv", 0, token);
        syscall.shutdown();
    }

    // At this point the worker should be suspended by stop-all. The
    // suspend IPI is dispatched asynchronously and has a short window
    // before it actually deschedules the worker on its remote core
    // (notably on aarch64 KVM), so yield enough for the IPI to land
    // before snapshotting, then verify the counter is frozen across a
    // second yield window.
    for (0..500) |_| syscall.thread_yield();
    const snap1 = counter_ptr.*;
    for (0..500) |_| syscall.thread_yield();
    const snap2 = counter_ptr.*;

    if (snap1 != snap2) {
        t.fail("§4.1.10 worker counter still advancing after stop-all");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Also verify the fault message fields look sane.
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    if (fm.thread_handle == @as(u64, @bitCast(token))) {
        t.pass("§4.1.10");
    } else {
        t.fail("§4.1.10 fault_msg thread_handle mismatch");
    }

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
