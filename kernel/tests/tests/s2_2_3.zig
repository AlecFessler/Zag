const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.3 — `vm_perms` with non-zero RWX takes effect: accessing the range respects the new permissions (e.g., writing to a read-only range faults).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Reserve a RW region, write to it, then change to read-only, verify read still works.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ptr: *volatile u64 = @ptrFromInt(result.val2);
    // Write while RW.
    ptr.* = 0xCAFEBABE;
    // Change to read-only.
    const ro = perms.VmReservationRights{ .read = true };
    const ret = syscall.vm_perms(handle, 0, 4096, ro.bits());
    // Read should still work after changing to read-only.
    if (ret != 0 or ptr.* != 0xCAFEBABE) {
        t.fail("§2.2.3");
        syscall.shutdown();
    }
    // Write fault: spawn child_invalid_write which reserves RO and writes — should fault.
    const child_rights = perms.ProcessRights{ .mem_reserve = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_invalid_write.ptr), children.child_invalid_write.len, child_rights.bits())));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    if (view[slot].processCrashReason() == .invalid_write) {
        t.pass("§2.2.3");
    } else {
        t.fail("§2.2.3");
    }
    syscall.shutdown();
}
