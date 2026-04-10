const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.3.13 — Revoking a device handle unmaps MMIO, returns handle up the process tree (§2.1), and clears the slot.
/// process tree, and clears the slot.
///
/// Part A: we hold a device and map it into a reservation. After revoke we
///   verify (1) the device slot is gone from our perm view, and (2) the VA
///   no longer points at MMIO — the range reverts to private (§2.2.10
///   mirror) so a plain write/read succeeds as private memory, which would
///   be impossible if MMIO were still mapped to a read-only register range.
/// Part B: we exercise the tree-walk return. We spawn a child, exclusively
///   transfer a different device handle to the child via cap transfer, then
///   the child exits. The device should return up the tree to us (its
///   nearest alive ancestor).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Part A uses AHCI MMIO (stable QEMU q35 MMIO device).
    // Part B uses the Bochs display MMIO BAR (second stable MMIO device).
    const ahci_ent = t.requireDevice(view, "§2.3.13", t.AHCI_VENDOR, t.AHCI_DEVICE, 0);
    const bochs_ent = t.requireDevice(view, "§2.3.13", t.BOCHS_VENDOR, t.BOCHS_DEVICE, 0);
    // Total count of device-region entries at start, used as baseline for the
    // tree-walk return check at the end of Part B.
    var devs_at_start: usize = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) devs_at_start += 1;
    }
    const n_devs: usize = devs_at_start;

    // --- Part A: device A mapped, then revoked; verify slot gone + MMIO gone ---
    const dev_a = ahci_ent.handle;
    const vm_rights = perms.VmReservationRights{
        .read = true,
        .write = true,
        .mmio = true,
    };
    const vm = syscall.vm_reserve(0, PAGE, vm_rights.bits());
    const vm_h: u64 = @bitCast(vm.val);
    if (syscall.mmio_map(dev_a, vm_h, 0) != 0) {
        t.fail("§2.3.13");
        syscall.shutdown();
    }

    if (syscall.revoke_perm(dev_a) != 0) {
        t.fail("§2.3.13");
        syscall.shutdown();
    }

    // Slot cleared.
    var dev_a_found = false;
    for (0..128) |i| {
        if (view[i].handle == dev_a and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_a_found = true;
            break;
        }
    }

    // MMIO no longer mapped — the range must revert to private and accept a
    // normal read/write round-trip. (If the mapping were still MMIO, the
    // device backing would either fault the test or return real register
    // values that do not match our written magic.)
    const mmio_ptr: *volatile u64 = @ptrFromInt(vm.val2);
    mmio_ptr.* = 0xD15EA5E5_1234BEEF;
    const mmio_readback = mmio_ptr.*;
    const mmio_gone = mmio_readback == 0xD15EA5E5_1234BEEF;

    // --- Part B: transfer dev_b to child, child exits; dev_b returns to us ---
    const dev_b = bochs_ent.handle;
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_recv_device_wait.ptr),
        children.child_recv_device_wait.len,
        child_rights.bits(),
    )));

    const dev_transfer_rights: u64 = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ dev_b, dev_transfer_rights }, &reply);

    // After transfer (child now blocked on its second recv, still holding
    // dev_b), verify dev_b is gone from the parent — the exclusive transfer
    // must have removed it from our table.
    var dev_b_present_after_xfer = false;
    for (0..128) |i| {
        if (view[i].handle == dev_b and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_b_present_after_xfer = true;
            break;
        }
    }

    // Signal child to exit so the device walks back up the tree to us.
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Wait for child to exit — its device should walk back up to us.
    var attempts: u32 = 0;
    var dev_b_returned = false;
    while (attempts < 500000) : (attempts += 1) {
        var found = false;
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].handle == dev_b) {
                found = true;
                break;
            }
            // A fresh device handle (different id, same device payload) would
            // also indicate return-up — but since our device entry tracks by
            // id, walk finds the existing slot cleared and re-inserts. In
            // either case the device region count after child exit must be
            // >= the count before transfer minus zero (i.e., it came back).
        }
        if (found) {
            dev_b_returned = true;
            break;
        }
        syscall.thread_yield();
    }

    // Count DEVICE_REGION entries as a fallback: we started with n_devs, gave
    // one (dev_a) away to revoke, and transferred one (dev_b) to the child
    // who exited. We should now have (n_devs - 1) devices back — dev_a stays
    // revoked, but dev_b came back (possibly with a new id on re-insert).
    var count_after: usize = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) count_after += 1;
    }
    const expected_count = n_devs - 1;
    const tree_walk_ok = dev_b_returned or count_after >= expected_count;

    if (!dev_a_found and mmio_gone and !dev_b_present_after_xfer and tree_walk_ok) {
        t.pass("§2.3.13");
    } else {
        t.fail("§2.3.13");
    }
    syscall.shutdown();
}
