const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §2.11.22 — `send` never queues — it returns `E_AGAIN` if no receiver is waiting.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_sleep.ptr), children.child_sleep.len, child_rights.bits())));
    syscall.thread_yield();
    // child_sleep never calls recv — send should not queue, returns E_AGAIN
    const rc = syscall.ipc_send(ch, &.{0x42});
    t.expectEqual("§2.11.22", E_AGAIN, rc);
    syscall.shutdown();
}
