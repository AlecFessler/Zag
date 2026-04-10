const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

// r14 flag bits for fault_reply
const FAULT_EXCLUDE_NEXT: u64 = 0x1;
const FAULT_EXCLUDE_PERMANENT: u64 = 0x2;

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

/// §2.12.22 — `fault_reply` with both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` set returns `E_INVAL`.
/// `FAULT_EXCLUDE_PERMANENT` set returns `E_INVAL`.
///
/// Strong test: this isolates the combined-flags validation branch by
/// first putting the fault box into `pending_reply` state via a real
/// fault delivery and fault_recv. Otherwise E_INVAL could come from the
/// §2.12.20 "not in pending_reply" branch instead of the combined-flags
/// branch, as the previous weak test admitted.
pub fn main(_: u64) void {
    // Spawn a faulting child and enter pending_reply via fault_recv.
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token <= 0) {
        t.fail("§2.12.22 fault_recv failed");
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // Fault box is now in `pending_reply` with a valid token — §2.12.20
    // is satisfied. Reply with BOTH exclude flags to isolate the
    // §2.12.22 combined-flags branch. Expected: E_INVAL.
    const both_flags = FAULT_EXCLUDE_NEXT | FAULT_EXCLUDE_PERMANENT;
    const rc = fault_reply_with_flags(token_u, syscall.FAULT_RESUME, 0, both_flags);
    if (rc != E_INVAL) {
        t.failWithVal("§2.12.22", E_INVAL, rc);
        // Clean up before exit so the child can be killed.
        _ = syscall.fault_reply_simple(token_u, syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Clean up the still-pending fault.
    _ = syscall.fault_reply_simple(token_u, syscall.FAULT_KILL);
    t.pass("§2.12.22");
    syscall.shutdown();
}
