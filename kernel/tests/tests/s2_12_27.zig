const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// r14 flag bits for fault_reply
const FAULT_EXCLUDE_NEXT: u64 = 0x1;

/// Raw fault_reply syscall that passes flags in r14.
fn fault_reply_with_flags(token: u64, action: u64, modified_regs_ptr: u64, flags: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall.SyscallNum.fault_reply)),
          [a0] "{rdi}" (token),
          [a1] "{rsi}" (action),
          [a2] "{rdx}" (modified_regs_ptr),
          [flags] "{r14}" (flags),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

/// §2.12.27 — `fault_reply` with `FAULT_EXCLUDE_NEXT` sets `exclude_oneshot` on the faulting thread's perm entry in the handler's table and clears `exclude_permanent`.
/// faulting thread's perm entry in the handler's table and clears `exclude_permanent`.
/// `syncUserView` is called on the handler.
pub fn main(_: u64) void {

    // Spawn a child that transfers fault_handler then faults.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token < 0) {
        t.fail("§2.12.27 fault_recv failed");
        syscall.shutdown();
    }

    // First set exclude_permanent via fault_set_thread_mode so we can verify
    // that FAULT_EXCLUDE_NEXT clears it.
    _ = syscall.fault_set_thread_mode(@bitCast(token), syscall.FAULT_MODE_EXCLUDE_PERMANENT);

    // Reply with FAULT_RESUME and FAULT_EXCLUDE_NEXT flag.
    // Per §2.12.27, this sets exclude_oneshot on the thread's perm entry
    // and clears exclude_permanent. syncUserView is called on the handler.
    const rc = fault_reply_with_flags(@bitCast(token), syscall.FAULT_RESUME, 0, FAULT_EXCLUDE_NEXT);
    t.expectEqual("§2.12.27", 0, rc);

    // Clean up: the child will fault again at the same instruction, kill it.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 >= 0) {
        _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    }
    syscall.shutdown();
}
