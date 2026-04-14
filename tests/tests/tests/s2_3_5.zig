const builtin = @import("builtin");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// Arch-specific `ret` encoding. The test writes this byte pattern into a
/// demand-paged private page and invokes it via a function pointer to
/// confirm execute rights reverted post-unmap. On x86 `0xC3` is a 1-byte
/// near RET that pops RIP from the stack. On aarch64 `0xD65F03C0` is a
/// 4-byte `ret` instruction that branches to x30 (LR).
const RET_BYTES: []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => &[_]u8{0xC3},
    .aarch64 => &[_]u8{ 0xC0, 0x03, 0x5F, 0xD6 }, // little-endian 0xD65F03C0
    else => @compileError("unsupported arch"),
};

/// §2.3.5 — After `mem_unmap`, unmapped private nodes revert to demand-paged state with max RWX rights.
///
/// We reserve the range with read+write+execute so that "max RWX" means all
/// three bits are observable post-unmap. After unmapping, we verify:
///   - Read: fresh demand-paged page reads as zero (not the old SHM value).
///   - Write: a new value written sticks.
///   - Execute: we write a single `ret` (0xC3) into the page and invoke it
///     via a function pointer. If execute rights did not revert with the
///     page, this would take a #PF(xd) and crash the test.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rwx = perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rwx.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    // Write a known pattern to SHM.
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xDEAD_BEEF_CAFE_BABE;
    // Unmap SHM.
    _ = syscall.mem_unmap(vm_handle, 0, 4096);
    // After unmap, range reverts to private demand-paged. Reading should yield zero
    // (fresh demand-paged page), NOT the old SHM data.
    const read_val = ptr.*;
    if (read_val != 0) {
        t.failWithVal("§2.3.5", 0, @bitCast(read_val));
        syscall.shutdown();
    }
    // Write a fresh value and verify it sticks (write right present).
    ptr.* = 0x1234_5678_9ABC_DEF0;
    if (ptr.* != 0x1234_5678_9ABC_DEF0) {
        t.fail("§2.3.5");
        syscall.shutdown();
    }
    // Execute right: write an arch-appropriate `ret` encoding and invoke
    // via fn pointer. If execute rights failed to revert, this faults with
    // invalid_execute. Page start is 4K-aligned, so the aarch64 4-byte
    // instruction is also 4-byte aligned as aarch64 requires.
    const dest: [*]volatile u8 = @ptrFromInt(vm.val2);
    for (RET_BYTES, 0..) |byte, i| dest[i] = byte;
    const func: *const fn () void = @ptrFromInt(vm.val2);
    func();
    t.pass("§2.3.5");
    syscall.shutdown();
}
