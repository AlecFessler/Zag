const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.23 — On any `fault_reply`, all threads in the target process that are in `.suspended` state are moved to `.ready` and re-enqueued before the action on the faulting thread is applied.
pub fn main(_: u64) void {
    // SHM page for the worker counter.
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
    const vm_result = syscall.vm_reserve(0, 0x1000, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§2.12.23 vm_reserve");
        syscall.shutdown();
    }
    if (syscall.shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) {
        t.fail("§2.12.23 shm_map");
        syscall.shutdown();
    }
    const counter_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    counter_ptr.* = 0;

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

    // Block until the fault arrives. At this point the worker is suspended
    // by stop-all.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.12.23 fault_recv", 0, token);
        syscall.shutdown();
    }

    // Confirm the worker is currently frozen (counter not advancing).
    const before = counter_ptr.*;
    for (0..30) |_| syscall.thread_yield();
    const still = counter_ptr.*;
    if (still != before) {
        t.fail("§2.12.23 worker not suspended pre-reply");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Reply with FAULT_RESUME — per §2.12.23, suspended threads must be
    // moved to .ready BEFORE the resume action is applied. The worker
    // should start running again.
    const rc = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_RESUME);
    if (rc != 0) {
        t.failWithVal("§2.12.23 fault_reply", 0, rc);
        syscall.shutdown();
    }

    // The main thread will re-fault (same null deref) — drain that next.
    // The worker should meanwhile be advancing the counter.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§2.12.23 fault_recv 2", 0, token2);
        syscall.shutdown();
    }

    const after = counter_ptr.*;
    if (after > still) {
        t.pass("§2.12.23");
    } else {
        t.fail("§2.12.23 worker did not resume");
    }
    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}
