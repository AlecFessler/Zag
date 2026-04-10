const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.10.6 — Core pin user view `field1` = `thread_tid`.
///
/// Looks up the calling thread's tid via the thread entry for `thread_self`,
/// compares it to the core pin entry's `field1`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_ret = syscall.thread_self();
    if (self_ret < 0) {
        t.fail("§2.10.6 thread_self failed");
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(self_ret);

    // Find our tid by looking up the thread entry.
    var self_tid: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    for (0..128) |i| {
        if (view[i].handle == self_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            self_tid = view[i].threadTid();
            break;
        }
    }
    if (self_tid == 0xFFFF_FFFF_FFFF_FFFF) {
        t.fail("§2.10.6 self thread entry not found");
        syscall.shutdown();
    }

    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.pin_exclusive();
    if (ret < 0) {
        t.fail("§2.10.6 pin_exclusive failed");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    var field1: u64 = 0xDEADBEEF;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == perm_view.ENTRY_TYPE_CORE_PIN) {
            field1 = view[i].field1;
            break;
        }
    }

    _ = syscall.revoke_perm(pin_handle);

    if (field1 == self_tid) {
        t.pass("§2.10.6");
    } else {
        t.failWithVal("§2.10.6", @bitCast(self_tid), @bitCast(field1));
    }
    syscall.shutdown();
}
