const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.23.3 — `futex_wake` with non-8-byte-aligned addr returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const misaligned_addr = result.val2 + 1;
    const ret = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall.SyscallNum.futex_wake)),
          [a0] "{rdi}" (misaligned_addr),
          [a1] "{rsi}" (@as(u64, 1)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
    t.expectEqual("§4.23.3", E_INVAL, ret);
    syscall.shutdown();
}
