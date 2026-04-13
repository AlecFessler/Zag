const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §8.1 — Unknown syscall number returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // No wrapper exists for an invalid syscall number, so raw asm is needed.
    const ret = switch (@import("builtin").cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@as(u64, 9999)),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@as(u64, 9999)),
            : .{ .memory = true }),
        else => unreachable,
    };
    t.expectEqual("§8.1", E_INVAL, ret);
    syscall.shutdown();
}
