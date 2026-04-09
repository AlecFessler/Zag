const lib = @import("lib");

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

/// §2.12.22 — `fault_reply` with both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` set returns `E_INVAL`
/// set returns `E_INVAL`
pub fn main(_: u64) void {
    // Call fault_reply with both exclude flags set. Even though the fault box
    // is not in pending_reply state, the combined-flags validation may fire
    // first or E_INVAL is returned either way. Both conditions yield E_INVAL.
    const both_flags = FAULT_EXCLUDE_NEXT | FAULT_EXCLUDE_PERMANENT;
    const rc = fault_reply_with_flags(0, syscall.FAULT_RESUME, 0, both_flags);
    t.expectEqual("§2.12.22", E_INVAL, rc);
    syscall.shutdown();
}
