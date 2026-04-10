const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const U64_MAX: u64 = 0xFFFFFFFFFFFFFFFF;

/// §2.1.18 — Each entry's handle field is a monotonic u64 ID; empty slots have handle = `U64_MAX`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Empty-slot invariant: every ENTRY_TYPE_EMPTY slot must carry U64_MAX.
    var empty_checked: u32 = 0;
    var empties_ok = true;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_EMPTY) {
            empty_checked += 1;
            if (view[i].handle != U64_MAX) {
                empties_ok = false;
                break;
            }
        }
    }

    // Monotonic allocation: allocate several handles in sequence and verify
    // each newly-minted ID is strictly greater than the previous one.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    var prev: u64 = 0;
    var monotonic_ok = true;
    var allocated: [5]u64 = undefined;
    for (0..5) |i| {
        const r = syscall.vm_reserve(0, 4096, rw.bits());
        if (r.val <= 0) {
            monotonic_ok = false;
            break;
        }
        const h: u64 = @bitCast(r.val);
        if (h <= prev) {
            monotonic_ok = false;
            break;
        }
        allocated[i] = h;
        prev = h;
    }
    for (allocated) |h| {
        _ = syscall.revoke_perm(h);
    }

    if (empties_ok and empty_checked > 0 and monotonic_ok) {
        t.pass("§2.1.18");
    } else {
        t.fail("§2.1.18");
    }
    syscall.shutdown();
}
