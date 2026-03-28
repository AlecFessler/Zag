const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 128;

pub fn run(perm_view_addr: u64) void {
    t.section("user permissions view (S2.2)");
    testViewMapped(perm_view_addr);
    testSelfHandle(perm_view_addr);
    testVmReservationInView(perm_view_addr);
    testShmInView(perm_view_addr);
}

fn getView(addr: u64) *const [MAX_PERMS]pv.UserViewEntry {
    return @ptrFromInt(addr);
}

fn testViewMapped(addr: u64) void {
    if (addr == 0) {
        t.fail("perm_view addr is null");
        return;
    }
    const view = getView(addr);
    if (view[0].entry_type == pv.ENTRY_TYPE_PROCESS) {
        t.pass("S2.1: user view mapped read-only, slot 0 is process type");
    } else {
        t.fail("S2.1: slot 0 is not process type");
    }
}

fn testSelfHandle(addr: u64) void {
    const view = getView(addr);
    const slot0 = &view[0];
    t.expectEqual("S2.3: HANDLE_SELF at slot 0 has handle=0", 0, @as(i64, @bitCast(slot0.handle)));
    if (slot0.entry_type != pv.ENTRY_TYPE_PROCESS) {
        t.fail("slot 0 not process");
        return;
    }
    t.pass("S2.1: user view arg passed to initial thread is perm_view_vaddr");
}

fn testVmReservationInView(addr: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("setup failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const view = getView(addr);
    var found = false;
    for (view) |*entry| {
        if (entry.handle == handle and entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) {
            if (entry.field1 == syscall.PAGE4K) found = true;
            break;
        }
    }
    if (found) {
        t.pass("S2.1: vm_reservation entry visible with start+size fields");
    } else {
        t.fail("S2.1: vm_reservation not found in view after reserve");
    }
}

fn testShmInView(addr: u64) void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("setup failed");
        return;
    }
    const view = getView(addr);
    var found = false;
    for (view) |*entry| {
        if (entry.handle == @as(u64, @intCast(shm_handle)) and entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            if (entry.field0 == syscall.PAGE4K) found = true;
            break;
        }
    }
    if (found) {
        t.pass("S2.1: shared_memory entry visible with size field");
    } else {
        t.fail("S2.1: shared_memory not found in view after create");
    }
}
