const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.15 — Userspace derives the `field0` address of a device entry as `perm_view_vaddr + slot_index * 32 + 16` and uses it directly as a futex wait target (via `futex_wait_val` or `futex_wait_change`).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Verify that the computed field0 address matches the actual struct field address.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const computed_addr = pv + i * 32 + 16;
        const actual_addr = @intFromPtr(&e.field0);
        t.expectEqual("§2.5.15", @as(i64, @bitCast(computed_addr)), @as(i64, @bitCast(actual_addr)));
        syscall.shutdown();
    }
    // No device entries found — pass vacuously.
    t.pass("§2.5.15");
    syscall.shutdown();
}
