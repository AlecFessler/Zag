const builtin = @import("builtin");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Arch-specific `ret` encoding. x86: `0xC3` (1 byte near RET).
/// aarch64: `0xD65F03C0` (4 bytes, little-endian) — `ret` to x30.
const RET_BYTES: []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => &[_]u8{0xC3},
    .aarch64 => &[_]u8{ 0xC0, 0x03, 0x5F, 0xD6 },
    else => @compileError("unsupported arch"),
};

/// Reserves a read+write (no execute) region, writes a `ret` instruction
/// (arch-appropriate encoding), then jumps to it.
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.mem_reserve(0, 4096, rights);
    if (result.val < 0) return;
    const dest: [*]volatile u8 = @ptrFromInt(result.val2);
    for (RET_BYTES, 0..) |byte, i| dest[i] = byte;
    const func: *const fn () void = @ptrFromInt(result.val2);
    func();
}
