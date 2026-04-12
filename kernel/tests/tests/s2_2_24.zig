const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.2.24 — `thread_kill` on a `.faulted` thread returns `E_BUSY`; the fault must be resolved via `fault_reply` with `FAULT_KILL` before the thread can be killed.
pub fn main(_: u64) void {
    // Spawn a child that transfers fault_handler to us then null-derefs.
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

    // Block until the fault arrives. The token is the faulting thread's
    // handle in our perm table (§2.12.14, §2.12.19).
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.2.24 fault_recv", 0, token);
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // Attempt to kill the faulted thread — must return E_BUSY.
    const kill_rc = syscall.thread_kill(token_u);
    if (kill_rc == E_BUSY) {
        t.pass("§2.2.24");
    } else {
        t.failWithVal("§2.2.24 thread_kill on faulted", E_BUSY, kill_rc);
    }

    // Clean up the fault pending state so the test exits cleanly.
    _ = syscall.fault_reply_simple(token_u, syscall.FAULT_KILL);
    syscall.shutdown();
}
