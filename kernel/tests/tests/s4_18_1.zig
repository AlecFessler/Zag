const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.18.1 — `recv` returns `E_OK` with payload and r14 sender metadata on success.
pub fn main(_: u64) void {
    // child_ipc_metadata_echo receives a message, then replies with:
    //   word[0] = word_count from r14, word[1] = from_call (1 or 0) from r14.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_metadata_echo.ptr),
        children.child_ipc_metadata_echo.len,
        child_rights.bits(),
    )));
    // Send 3 words via call (from_call should be 1).
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{ 0xA, 0xB, 0xC }, &reply);
    if (rc != 0) {
        t.failWithVal("§4.18.1", 0, rc);
        syscall.shutdown();
    }
    // Verify child saw correct r14 metadata.
    const word_count = reply.words[0];
    const from_call = reply.words[1];
    if (word_count == 3 and from_call == 1) {
        t.pass("§4.18.1");
    } else {
        t.fail("§4.18.1");
    }
    syscall.shutdown();
}
