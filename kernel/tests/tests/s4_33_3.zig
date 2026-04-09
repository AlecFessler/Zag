const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.33.3 — `fault_recv` with blocking flag set blocks when the fault box is empty.
///
/// Strategy: a sibling thread spawns a child that transfers fault_handler to us
/// and then faults. The main thread, before any of that happens, calls
/// `fault_recv(blocking=1)`. If `fault_recv` had returned immediately the box
/// would be empty (E_AGAIN) — getting a valid token means the call actually
/// blocked until the fault arrived.
var sibling_done: u64 = 0;

fn siblingTrigger() void {
    // Yield a few times so the main thread reaches fault_recv first.
    for (0..20) |_| syscall.thread_yield();

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    @atomicStore(u64, &sibling_done, 1, .release);
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    const sib_rc = syscall.thread_create(siblingTrigger, 0, 4);
    if (sib_rc < 0) {
        t.failWithVal("§4.33.3 thread_create", 0, sib_rc);
        syscall.shutdown();
    }

    // Block in fault_recv. Box must be empty at this point — sibling is yielding.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§4.33.3 fault_recv", 0, token);
        syscall.shutdown();
    }

    t.pass("§4.33.3");
    syscall.shutdown();
}
