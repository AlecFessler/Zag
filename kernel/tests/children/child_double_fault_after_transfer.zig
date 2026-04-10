const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC, replies with HANDLE_SELF via cap transfer with fault_handler
/// bit set, then executes two consecutive null-deref instructions at distinct
/// target addresses. Used by §2.12.26 to verify FAULT_RESUME_MODIFIED: after
/// the parent receives the first fault (at address 0), it advances RIP by 2
/// to skip the first instruction; the second instruction then faults at
/// address 0xCAFE0000, which the parent observes as a distinct fault.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Two consecutive 2-byte null-deref instructions at distinct addresses.
    // `movb (%rax), %al` — encodes as 0x8a 0x00 (2 bytes). The parent will
    // skip past the first by advancing RIP by 2.
    asm volatile (
        \\movb (%%rax), %%al
        \\movb (%%rbx), %%al
        :
        : [a] "{rax}" (@as(u64, 0)),
          [b] "{rbx}" (@as(u64, 0xCAFE0000)),
        : .{ .memory = true });
}
