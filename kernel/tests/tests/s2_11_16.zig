const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.16 — `reply` to a `call` copies reply payload to the caller's registers and unblocks the caller.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{0x42}, &reply);
    // Reply unblocked us and payload is in reply registers
    if (rc == 0 and reply.words[0] == 0x43) {
        t.pass("§2.11.16");
    } else {
        t.fail("§2.11.16");
    }
    syscall.shutdown();
}
