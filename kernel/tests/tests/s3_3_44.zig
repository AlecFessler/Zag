const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §3.3.44 — `call` cap transfer invalid payload returns `E_INVAL`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    // Cap transfer with fewer than 2 words — should return E_INVAL
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call_cap(child_handle, &.{0x42}, &reply);
    t.expectEqual("§3.3.44", E_INVAL, rc);
    syscall.shutdown();
}
