const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.5 — `call` blocks the caller until the receiver calls `reply`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    // call blocks until child replies — if we get a reply, it blocked and unblocked correctly.
    // child_ipc_server adds 1 to first word: 0x42 -> 0x43. Verifying the reply payload
    // proves we actually waited for and received the reply, not just that rc==0.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{0x42}, &reply);
    if (rc != 0) {
        t.fail("§2.11.5");
        syscall.shutdown();
    }
    if (reply.words[0] != 0x43) {
        t.fail("§2.11.5");
        syscall.shutdown();
    }
    t.pass("§2.11.5");
    syscall.shutdown();
}
