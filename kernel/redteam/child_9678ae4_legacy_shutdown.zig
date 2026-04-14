// Child for 9678ae4 PoC. Spawned with empty ProcessRights (no power bit).
// Calls the legacy shutdown syscall directly:
//
//   Pre-patch: the syscall dispatches to sysShutdown() → arch.shutdown(),
//   the entire machine halts, and this thread never executes another
//   instruction. The parent never receives anything and the optimistic
//   "VULNERABLE" line stays as the last serial output.
//
//   Post-patch: the syscall dispatches to sysSysPower(0), which checks
//   the slot-0 ProcessRights.power bit, finds it missing, and returns
//   E_PERM. The shutdown wrapper in libz declares the syscall noreturn,
//   so we can't use it as-is — we issue the raw syscall ourselves so we
//   can observe the return value, then ipc_send the rc back to the
//   parent so it can print PATCHED.

const builtin = @import("builtin");
const lib = @import("lib");
const syscall = lib.syscall;

const SHUTDOWN_NUM: u64 = @intFromEnum(syscall.SyscallNum.shutdown);

fn rawShutdown() i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (SHUTDOWN_NUM),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (SHUTDOWN_NUM),
            : .{ .memory = true }),
        else => unreachable,
    };
}

pub fn main(_: u64) void {
    // Park ourselves in ipc_recv until the parent ipc_call's us. This
    // both establishes a reply channel back to the parent and gives the
    // parent a chance to print its optimistic VULNERABLE marker before
    // we attempt to halt the world.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != syscall.E_OK) {
        syscall.thread_exit();
    }

    // Attempt the legacy shutdown. Pre-patch this never returns (whole
    // system halts). Post-patch we get E_PERM back as a normal i64.
    const rc = rawShutdown();

    // We're still alive — reply to the parent's pending call with the
    // rc so it can declare the patch effective.
    const rc_word: u64 = @bitCast(rc);
    _ = syscall.ipc_reply(&.{rc_word});

    syscall.thread_exit();
}
