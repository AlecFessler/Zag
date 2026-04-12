const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_MAXCAP: i64 = -5;

/// §2.2.74 — `set_priority(.pinned)` returns `E_MAXCAP` if the permissions table is full.
pub fn main(perm_view: u64) void {
    _ = perm_view;

    // Fill the perm table by creating SHM handles. The table has 128 slots;
    // some are already occupied (slot 0 = process, slot 1 = main thread, etc.).
    // Create enough to fill it.
    var created: u64 = 0;
    for (0..128) |_| {
        const ret = syscall.shm_create_with_rights(syscall.PAGE4K, 0x3);
        if (ret < 0) break;
        created += 1;
    }

    // Table should now be full. Try to pin → E_MAXCAP (needs a new slot for core_pin).
    _ = syscall.set_affinity(0b1);
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    t.expectEqual("§2.2.74", E_MAXCAP, ret);

    // Verify we actually filled the table (sanity check).
    if (created == 0) {
        t.fail("§2.2.74 sanity: no SHM handles created");
    }

    syscall.shutdown();
}
