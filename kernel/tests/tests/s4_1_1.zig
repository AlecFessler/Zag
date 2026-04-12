const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.1.1 — Unknown syscall number returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // No wrapper exists for an invalid syscall number, so raw asm is needed.
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@as(u64, 9999)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
    t.expectEqual("§4.1.1", E_INVAL, ret);
    syscall.shutdown();
}
