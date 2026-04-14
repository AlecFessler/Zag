// TODO aarch64: NOOUT on Pi 5 KVM. Child `child_invalid_write` takes a write
// fault on an RO-reverted page but is never reaped — kernel loops emitting
// "K: PAGEFAULT pid=2 addr=0xf80 w=false x=false" (from the is_kernel_privilege
// && is_user_va branch of handlePageFault). Root cause likely sits in the
// aarch64 data_abort_same_el path: either the exception is being taken at
// the wrong vector (same-EL vs lower-EL) or proc.kill isn't actually
// stopping the faulting thread from being rescheduled on SMP, so we re-take
// the same fault on every core. Need to audit handleSyncCurrentEl vs
// handleSyncLowerEl dispatch and the SMP kill path.
const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.3 — `mem_perms` with non-zero RWX takes effect: accessing the range respects the new permissions (e.g., writing to a read-only range faults).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Reserve a RW region, write to it, then change to read-only, verify read still works.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ptr: *volatile u64 = @ptrFromInt(result.val2);
    // Write while RW.
    ptr.* = 0xCAFEBABE;
    // Change to read-only.
    const ro = perms.VmReservationRights{ .read = true };
    const ret = syscall.mem_perms(handle, 0, 4096, ro.bits());
    // Read should still work after changing to read-only.
    if (ret != 0 or ptr.* != 0xCAFEBABE) {
        t.fail("§2.3.3");
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
        t.pass("§2.3.3");
    } else {
        t.fail("§2.3.3");
    }
    syscall.shutdown();
}
