const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.8 — `call` returns with reply payload in the payload registers.
///
/// Verify all 5 payload words round-trip by calling a child that replies
/// with w[i] = msg.words[i] + (i + 1) for i = 0..4.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_five_word_echo.ptr),
        children.child_ipc_five_word_echo.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{ 0x100, 0x200, 0x300, 0x400, 0x500 }, &reply);
    if (rc != 0) {
        t.failWithVal("§2.11.8 call", 0, rc);
        syscall.shutdown();
    }

    const ok = reply.word_count == 5 and
        reply.words[0] == 0x101 and
        reply.words[1] == 0x202 and
        reply.words[2] == 0x303 and
        reply.words[3] == 0x404 and
        reply.words[4] == 0x505;
    if (ok) {
        t.pass("§2.11.8");
    } else {
        t.fail("§2.11.8");
    }
    syscall.shutdown();
}
