const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.1.3 — Revoking SHM unmaps it from all reservations, reverts to private, and clears the slot.
///
/// To give teeth to the "all reservations" plural, we map the same SHM into
/// TWO distinct vm_reservations, write a magic value via one view (observable
/// in the other via the backing SHM), revoke the SHM, then verify:
///   1. the SHM slot is cleared,
///   2. both vm_reservations still exist,
///   3. BOTH vaddrs no longer expose the SHM contents (reading the magic
///      would prove the old mapping survived somewhere — and writes to each
///      view must revert to private demand-paged pages that are decoupled).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create two distinct VM reservations, both shareable + RW.
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm_a = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_a_handle: u64 = @bitCast(vm_a.val);
    const vm_b = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_b_handle: u64 = @bitCast(vm_b.val);

    // Sanity: distinct reservations should have distinct base vaddrs.
    if (vm_a.val2 == vm_b.val2) {
        t.fail("§3.1.3");
        syscall.shutdown();
    }

    // Create one SHM and map it into BOTH reservations.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    if (syscall.mem_shm_map(shm_handle, vm_a_handle, 0) != 0) {
        t.fail("§3.1.3");
        syscall.shutdown();
    }
    if (syscall.mem_shm_map(shm_handle, vm_b_handle, 0) != 0) {
        t.fail("§3.1.3");
        syscall.shutdown();
    }

    // Write a magic value through A and verify B observes it through the
    // shared backing store (confirms both mappings really reference the SHM
    // before revocation).
    const ptr_a: *volatile u64 = @ptrFromInt(vm_a.val2);
    const ptr_b: *volatile u64 = @ptrFromInt(vm_b.val2);
    const magic: u64 = 0xCAFE_BABE_D00D_F00D;
    ptr_a.* = magic;
    if (ptr_b.* != magic) {
        t.fail("§3.1.3");
        syscall.shutdown();
    }

    // Revoke the SHM handle.
    const revoke_ret = syscall.revoke_perm(shm_handle);

    // Verify the SHM slot is cleared.
    var shm_found = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            shm_found = true;
            break;
        }
    }

    // Both VM reservations must still exist (only SHM was revoked).
    var vm_a_found = false;
    var vm_b_found = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            if (view[i].handle == vm_a_handle) vm_a_found = true;
            if (view[i].handle == vm_b_handle) vm_b_found = true;
        }
    }

    // Both vaddrs must no longer expose the SHM contents. After revoke each
    // range reverts to private demand-paged memory: the magic value must be
    // gone from both views, and a write through A must NOT appear in B
    // (they are now independent private pages).
    const readback_a = ptr_a.*;
    const readback_b = ptr_b.*;
    ptr_a.* = 0xDEAD_BEEF_0000_0001;
    ptr_b.* = 0xDEAD_BEEF_0000_0002;
    const post_a = ptr_a.*;
    const post_b = ptr_b.*;

    if (revoke_ret == 0 and
        !shm_found and
        vm_a_found and vm_b_found and
        readback_a != magic and readback_b != magic and
        post_a == 0xDEAD_BEEF_0000_0001 and
        post_b == 0xDEAD_BEEF_0000_0002)
    {
        t.pass("§3.1.3");
    } else {
        t.fail("§3.1.3");
    }
    syscall.shutdown();
}
